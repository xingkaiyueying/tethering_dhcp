/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vector>
#include "dhcp_s_server.h"
#include "dhcp_nearlink_scope.h"
#include <new>
#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <securec.h>
#include <stdint.h>
#include <cstdio>
#include <cstdlib>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <mutex>
#include <pthread.h>
#include <atomic>
#include "address_utils.h"
#include "common_util.h"
#include "dhcp_address_pool.h"
#include "dhcp_binding.h"
#include "dhcp_config.h"
#include "dhcp_define.h"
#include "dhcp_logger.h"
#include "dhcp_option.h"
#include "dhcp_common_utils.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpServer");

constexpr int REPLY_PACKET_MAX_LEN = 1500;
 
#ifndef DHCP_SEL_WAIT_TIMEOUTS
#define DHCP_SEL_WAIT_TIMEOUTS 1000
#endif
#define OPT_MESSAGE_TYPE_LEGTH 1
#define OPT_HEADER_LENGTH 2
#define OPT_TIME_LENGTH 4
#define OPT_TYPE_FIELD_LENGTH 1
#define OPT_MAC_ADDR_LENGTH 6
#define MAGIC_COOKIE_LENGTH 4
#define OPT_BROADCAST_FLAG_ENABLE 0
#define OFFER_MIN_INTERVAL_TIME 5

#define PENDING_DEFAULT_TIMEOUT 1200
#define PENDING_DEFAULT_INTERVAL 1
#define PENDING_INTERVAL_CHECKING_ENABLE 1
#define DHCP_MAGIC_COOKIE 0x63825363
#define RECV_BUFFER_SIZE 2048
#define ALLOW_NOBINDING_REQUEST 1
#define REUSE_ADDRESS_ENABLE 1
#define WAIT_STOPED_TIME 5
#define DHCP_SERVER_SLEEP_TIMEOUTS 600000  // 600ms

#define VNEDOR_OPEN_HARMONY "OPEN_HARMONY"

const uint8_t MAGIC_COOKIE_DATA[MAGIC_COOKIE_LENGTH] = {0x63, 0x82, 0x53, 0x63};  // Vendor Information "Magic Cookie"

enum AssignedNumbers {
    ETHERNET = 1,               // Ethernet (10Mb)
    EXPERIMENTAL_ETHERNET,      // Experimental Ethernet (3Mb)
    AMATEUR_RADIO_AX_25,        // Amateur Radio AX.25
    PROTEON_PRONET_TOKEN_RING,  // Proteon ProNET Token Ring
    CHAOS,
    IEEE802_NETWORKS,
    ARCNET,
    HYPERCHANNEL,
    LANSTAR
};

struct ServerContext {
    int broadCastFlagEnable;
    DhcpAddressPool addressPool;
    DhcpServerCallback callback;
    DeviceConnectFun deviceConnectFun;
    DhcpConfig config;
    std::atomic<int> serverFd;
    std::atomic<int> looperState;
    int initialized;
    std::mutex fdMutex;
};

enum LooperState {
    LS_IDLE = 0,
    LS_STARING,
    LS_RUNNING,
    LS_RELOADNG,
    LS_STOPING,
    LS_STOPED
};
typedef struct sockaddr_in sockaddr_in;
int FillReply(PDhcpServerContext ctx, PDhcpMsgInfo received, PDhcpMsgInfo reply);
static int OnReceivedDiscover(PDhcpServerContext ctx, PDhcpMsgInfo received, PDhcpMsgInfo reply);
static int OnReceivedRequest(PDhcpServerContext ctx, PDhcpMsgInfo received, PDhcpMsgInfo reply);
static int OnReceivedDecline(PDhcpServerContext ctx, PDhcpMsgInfo received, PDhcpMsgInfo reply);
static int OnReceivedRelease(PDhcpServerContext ctx, PDhcpMsgInfo received, PDhcpMsgInfo reply);
static int OnReceivedInform(PDhcpServerContext ctx, PDhcpMsgInfo received, PDhcpMsgInfo reply);
static int SendDhcpOffer(PDhcpServerContext ctx, PDhcpMsgInfo reply);
static int SendDhcpAck(PDhcpServerContext ctx, PDhcpMsgInfo reply);
static int SendDhcpNak(PDhcpServerContext ctx, PDhcpMsgInfo reply);
static int ParseMessageOptions(PDhcpMsgInfo msg);
static int TransmitOfferOrAckPacket(PDhcpServerContext ctx, PDhcpMsgInfo reply);

static int ParseReplyOptions(PDhcpMsgInfo reply);
struct sockaddr_in *BroadcastAddrIn(void);

using namespace OHOS::DHCP;

static struct ServerContext *GetServerInstance(const DhcpServerContext *ctx)
{
    if (!ctx || !ctx->instance) {
        return nullptr;
    }
    return reinterpret_cast<struct ServerContext *>(ctx->instance);
}

int HasFixSocket(int fd)
{
    int flags;
    if ((flags = fcntl(fd, F_GETFL)) == -1 || fcntl(fd, F_SETFL, static_cast<unsigned int>(flags) | O_NONBLOCK) == -1) {
        return DHCP_FALSE;
    }
    return DHCP_TRUE;
}

typedef struct ifreq ifreq;
typedef struct sockaddr sockaddr;

int BindNetInterface(int fd, const char *ifname)
{
    DHCP_LOGI("start %{public}s %{public}d   ifname = %{public}s ", __func__, __LINE__, ifname);
    if (!fd || !ifname) {
        return RET_FAILED;
    }
    ifreq iface;
    if (memset_s(&iface, sizeof(iface), 0, sizeof(iface)) != EOK) {
        return RET_FAILED;
    }
    ssize_t ifnameSize = strlen(ifname);
    if (strncpy_s(iface.ifr_ifrn.ifrn_name, sizeof(iface.ifr_ifrn.ifrn_name), ifname, ifnameSize) != EOK) {
        DHCP_LOGE("start %{public}s %{public}d   copy failed ", __func__, __LINE__);
        return RET_FAILED;
    };
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (char *)&iface, sizeof(iface)) == -1) {
        DHCP_LOGE("failed to bind network device interface[%s].", ifname);
        return RET_FAILED;
    }
    DHCP_LOGI("start %{public}s %{public}d   success ", __func__, __LINE__);
    return RET_SUCCESS;
}

int InitServer(const char *ifname)
{
    DHCP_LOGI("start %{public}s %{public}d   ifname = %{public}s ", __func__, __LINE__, ifname);
    sockaddr_in srvAddrIn = {0};
    int optval = 1;
    int optrval = 0;
    srvAddrIn.sin_family = AF_INET;
    srvAddrIn.sin_port = htons(DHCP_SERVER_PORT);
    srvAddrIn.sin_addr.s_addr = INADDR_ANY;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd == -1) {
        DHCP_LOGE("failed to create server socket!");
        return -1;
    }
    if (!HasFixSocket(fd)) {
        DHCP_LOGD("failed to fcntl O_NONBLOCK flag!");
    }
    if (BindNetInterface(fd, ifname) != RET_SUCCESS) {
        close(fd);
        return -1;
    }
    socklen_t optlen = sizeof(optrval);
    if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char *)&optrval, &optlen) == -1) {
        DHCP_LOGI("failed to receive buffer size.");
    } else {
        DHCP_LOGI("receive buffer size is %d", optrval);
    }
    if (REUSE_ADDRESS_ENABLE && setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) == -1) {
        DHCP_LOGW("failed to setsockopt 'SO_REUSEADDR' for server socket!");
    }
    if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval)) == -1) {
        DHCP_LOGE("failed to setsockopt 'SO_BROADCAST' for server socket!");
        close(fd);
        return -1;
    }
    if (int ret = bind(fd, (sockaddr *)&srvAddrIn, sizeof(sockaddr)) == -1) {
        DHCP_LOGE("failed to bind server  %{public}d!", ret);
        close(fd);
        return -1;
    }
    DHCP_LOGI("start %{public}s %{public}d   SUCCESSs ", __func__, __LINE__);
    return fd;
}

struct sockaddr_in *BroadcastAddrIn(void)
{
    static thread_local struct sockaddr_in broadcastAddrIn = {0};
    if (broadcastAddrIn.sin_port == 0) {
        broadcastAddrIn.sin_port = htons(DHCP_CLIENT_PORT);
        broadcastAddrIn.sin_family = AF_INET;
        broadcastAddrIn.sin_addr.s_addr = INADDR_BROADCAST;
    }
    return &broadcastAddrIn;
}

struct sockaddr_in *SourceAddrIn(void)
{
    static thread_local struct sockaddr_in nearlinkSourceAddrIn = {0};
    if (HasNearlinkBindingScope())
        return &nearlinkSourceAddrIn;
    static thread_local struct sockaddr_in sourceAddrIn = {0};
    sourceAddrIn.sin_port = htons(DHCP_CLIENT_PORT);
    sourceAddrIn.sin_family = AF_INET;
    sourceAddrIn.sin_addr.s_addr = INADDR_ANY;
    return &sourceAddrIn;
}

struct sockaddr_in *ResetSourceAddr(void)
{
    DHCP_LOGI("start %{public}s %{public}d", __func__, __LINE__);
    struct sockaddr_in *srcAddr = SourceAddrIn();
    srcAddr->sin_port = htons(DHCP_CLIENT_PORT);
    srcAddr->sin_family = AF_INET;
    srcAddr->sin_addr.s_addr = INADDR_ANY;
    return srcAddr;
}

uint32_t SourceIpAddress(void)
{
    uint32_t srcIp = SourceAddrIn()->sin_addr.s_addr;
    return srcIp;
}
struct sockaddr_in *DestinationAddrIn(void)
{
    static thread_local struct sockaddr_in destAddrIn = {0};
    if (destAddrIn.sin_port == 0) {
        destAddrIn.sin_port = htons(DHCP_CLIENT_PORT);
        destAddrIn.sin_family = AF_INET;
    }
    return &destAddrIn;
}

struct sockaddr_in *DestinationAddr(uint32_t ipAddress)
{
    struct sockaddr_in *destAddr = DestinationAddrIn();
    destAddr->sin_addr.s_addr = htonl(ipAddress);
    return destAddr;
}

int ReceiveDhcpMessage(int sock, PDhcpMsgInfo msgInfo)
{
    static thread_local uint8_t recvBuffer[RECV_BUFFER_SIZE] = {0};
    struct timeval tmt;
    fd_set recvFd;
    FD_ZERO(&recvFd);
    FD_SET(sock, &recvFd);
    tmt.tv_sec = 0;
    tmt.tv_usec = DHCP_SERVER_SLEEP_TIMEOUTS; // 600ms
    int ret = select(sock + 1, &recvFd, nullptr, nullptr, &tmt);
    if (ret < 0) {
        DHCP_LOGE("select error, %d", errno);
        return ERR_SELECT;
    }
    if (ret == 0) {
        return RET_SELECT_TIME_OUT;
    }
    if (!FD_ISSET(sock, &recvFd)) {
        DHCP_LOGE("failed to select isset.");
        return RET_ERROR;
    }
    socklen_t ssize = sizeof(sockaddr_in);
    struct sockaddr_in *srcAddrIn = ResetSourceAddr();
    srcAddrIn->sin_addr.s_addr = INADDR_ANY;
    DHCP_LOGI("start recv from");
    int rsize = recvfrom(sock, recvBuffer, RECV_BUFFER_SIZE, 0, (struct sockaddr *)srcAddrIn, (socklen_t *)&ssize);
    if (!rsize) {
        DHCP_LOGE("receive error, %d", errno);
        return RET_FAILED;
    }
    if (rsize > (int)sizeof(DhcpMessage) || rsize < DHCP_MSG_HEADER_SIZE) {
        DHCP_LOGW("message length error, received %d bytes.", rsize);
        return RET_FAILED;
    }
    DHCP_LOGI("recv over");
    msgInfo->length = rsize;
    if (memcpy_s(&msgInfo->packet, sizeof(DhcpMessage), recvBuffer, rsize) != EOK) {
        return RET_FAILED;
    }
    if (msgInfo->packet.op != BOOTREQUEST) {
        DHCP_LOGW("dhcp message type error!");
        return RET_FAILED;
    }
    if (msgInfo->packet.hlen > DHCP_HWADDR_LENGTH) {
        DHCP_LOGW("hlen error!");
        return RET_FAILED;
    }
    if (IsEmptyHWAddr(msgInfo->packet.chaddr)) {
        DHCP_LOGW("client hardware address error!");
        return RET_FAILED;
    }
    if (IsReserved(msgInfo->packet.chaddr)) {
        DHCP_LOGD("ignore client, %s", ParseLogMac(msgInfo->packet.chaddr));
        return RET_FAILED;
    }
    DHCP_LOGI("start %{public}s %{public}d  return success", __func__, __LINE__);
    return RET_SUCCESS;
}

void InitReply(PDhcpServerContext ctx, PDhcpMsgInfo received, PDhcpMsgInfo reply)
{
    DHCP_LOGI("start %{public}s %{public}d", __func__, __LINE__);
    if (!reply) {
        DHCP_LOGE("reply message pointer is null!");
        return;
    }
    reply->packet.op = BOOTREPLY;
    reply->packet.htype = ETHERNET;
    reply->packet.hlen = OPT_MAC_ADDR_LENGTH;
    reply->packet.secs = 0;
    reply->packet.ciaddr = 0;
    if (memset_s(reply->packet.sname, sizeof(reply->packet.sname), '\0', sizeof(reply->packet.sname)) != EOK) {
        DHCP_LOGE("failed to reset message packet[sname]!");
        return;
    };
    if (memset_s(reply->packet.file, sizeof(reply->packet.file), '\0', sizeof(reply->packet.file)) != EOK) {
        DHCP_LOGE("failed to reset message packet[file]!");
        return;
    }

    if (FillReply(ctx, received, reply) != RET_SUCCESS) {
        DHCP_LOGW("failed to fill reply message.");
    }
}

void OnUpdateServerConfig(PDhcpServerContext ctx)
{
    DHCP_LOGI("start %{public}s %{public}d", __func__, __LINE__);
    ServerContext *srvIns = GetServerInstance(ctx);
    if (!srvIns) {
        DHCP_LOGE("dhcp server context pointer is null.");
        return;
    }
    if (srvIns->callback) {
        srvIns->callback(ST_RELOADNG, 0, ctx->ifname);
    }
}

static void OnServerStoping(PDhcpServerContext ctx)
{
    DHCP_LOGI("start %{public}s %{public}d", __func__, __LINE__);
    ServerContext *srvIns = GetServerInstance(ctx);
    if (!srvIns) {
        DHCP_LOGE("dhcp server context pointer is null.");
        return;
    }
    if (srvIns->callback) {
        srvIns->callback(ST_STOPING, 0, ctx->ifname);
    }
}

void OnServerStoped(PDhcpServerContext ctx, int code)
{
    DHCP_LOGI("OnServerStoped.");
    ServerContext *srvIns = GetServerInstance(ctx);
    if (!srvIns) {
        DHCP_LOGE("dhcp server context pointer is null.");
        return;
    }
    if (srvIns->callback) {
        srvIns->callback(ST_STOPED, code, ctx->ifname);
    }
}

int SendDhcpReply(PDhcpServerContext ctx, int replyType, PDhcpMsgInfo reply)
{
    if (!reply) {
        DHCP_LOGE("reply message pointer is null.");
        return RET_FAILED;
    }
    int sendRet = -1;
    ServerContext *srvIns = GetServerInstance(ctx);
    if (!srvIns) {
        DHCP_LOGE("dhcp server context pointer is null.");
        return RET_FAILED;
    }
    switch (replyType) {
        case REPLY_OFFER:
            DHCP_LOGD("<== send reply dhcp offer.");
            sendRet = SendDhcpOffer(ctx, reply);
            break;
        case REPLY_ACK:
            DHCP_LOGD("<== send reply dhcp ack.");
            sendRet = SendDhcpAck(ctx, reply);
            break;
        case REPLY_NAK:
            DHCP_LOGD("<== send reply dhcp nak.");
            sendRet = SendDhcpNak(ctx, reply);
            break;
        default:
            break;
    }
    if (replyType && sendRet != RET_SUCCESS) {
        return RET_FAILED;
    }
    return  RET_SUCCESS;
}

static int MessageProcess(PDhcpServerContext ctx, PDhcpMsgInfo received, PDhcpMsgInfo reply)
{
    DHCP_LOGI("start %{public}s %{public}d", __func__, __LINE__);
    int replyType = REPLY_NONE;
    if (!received) {
        return replyType;
    }
    PDhcpOption opt = GetOption(&received->options, DHCP_MESSAGE_TYPE_OPTION);
    if (!opt || opt->length == 0) {
        DHCP_LOGE("error dhcp message, missing required message type option.");
        return replyType;
    }
    uint8_t messageType = opt->data[0];
    switch (messageType) {
        case DHCPDISCOVER: {
            DHCP_LOGD("==> Received DHCPDISCOVER message.");
            replyType = OnReceivedDiscover(ctx, received, reply);
            break;
        }
        case DHCPREQUEST: {
            DHCP_LOGD("==> Received DHCPREQUEST message.");
            replyType = OnReceivedRequest(ctx, received, reply);
            break;
        }
        case DHCPDECLINE: {
            DHCP_LOGD("==> Received DHCPDECLINE message.");
            replyType = OnReceivedDecline(ctx, received, reply);
            break;
        }
        case DHCPRELEASE: {
            DHCP_LOGD("==> Received DHCPRELEASE message.");
            replyType = OnReceivedRelease(ctx, received, reply);
            break;
        }
        case DHCPINFORM: {
            DHCP_LOGD("==> Received DHCPINFORM message.");
            replyType = OnReceivedInform(ctx, received, reply);
            break;
        }
        default:
            break;
    }
    return replyType;
}

int SaveLease(PDhcpServerContext ctx)
{
    ServerContext *srvIns = GetServerInstance(ctx);
    if (!srvIns) {
        DHCP_LOGE("dhcp server context pointer is null.");
        return RET_FAILED;
    }
    int saveRet = SaveBindingRecoders(&srvIns->addressPool, 1);
    if (saveRet == RET_FAILED) {
        DHCP_LOGD("failed to save lease recoders.");
    } else if (saveRet == RET_SUCCESS) {
        DHCP_LOGD("lease recoders saved.");
    }
    return saveRet;
}

static int OnLooperStateChanged(PDhcpServerContext ctx)
{
    ServerContext *srvIns = GetServerInstance(ctx);
    if (!srvIns) {
        DHCP_LOGE("dhcp server context pointer is null.");
        return RET_FAILED;
    }

    if (srvIns->looperState == LS_RELOADNG) {
        OnUpdateServerConfig(ctx);
        srvIns->looperState = LS_RUNNING;
    } else if (srvIns->looperState == LS_STOPING) {
        OnServerStoping(ctx);
        return RET_BREAK;
    }
    return RET_SUCCESS;
}

static int ContinueReceive(PDhcpMsgInfo from, int recvRet)
{
    if (!from) {
        return DHCP_TRUE;
    }
    if (recvRet != RET_SUCCESS) {
        return DHCP_TRUE;
    }
    DHCP_LOGD("received, length:%{public}d", from->length);
    if (ParseMessageOptions(from) != 0) {
        DHCP_LOGE("invalid dhcp message.");
        return DHCP_TRUE;
    }
    if (!GetOption(&from->options, DHCP_MESSAGE_TYPE_OPTION)) {
        DHCP_LOGW("can't found 'message type' option.");
        return DHCP_TRUE;
    }
    return DHCP_FALSE;
}

static void *BeginLooper(void *argc) __attribute__((no_sanitize("cfi")))
{
    PDhcpServerContext ctx = (PDhcpServerContext)argc;
    DhcpNearlinkBindingScope scope(ctx ? ctx->ifname : "");
    DHCP_LOGI("start %{public}s %{public}d", __func__, __LINE__);
    DhcpMsgInfo from;
    DhcpMsgInfo reply;
    ServerContext *srvIns = GetServerInstance(ctx);
    if (!srvIns) {
        DHCP_LOGE("dhcp server context pointer is null.");
        return nullptr;
    }
    {
        std::lock_guard<std::mutex> lock(srvIns->fdMutex);
        ctx->instance->serverFd = InitServer(ctx->ifname);
        if (ctx->instance->serverFd < 0) {
            srvIns->looperState = LS_STOPED;
            return nullptr;
        }
    }
    InitOptionList(&from.options);
    InitOptionList(&reply.options);
    if (IsNearlinkDhcpInterface(ctx->ifname)) {
        int expected = LS_STARING;
        srvIns->looperState.compare_exchange_strong(expected, LS_RUNNING);
    } else
        srvIns->looperState = LS_RUNNING;
    while (srvIns->looperState) {
        if (OnLooperStateChanged(ctx) != RET_SUCCESS) {
            DHCP_LOGI("OnLooperStateChanged break, looperState:%{public}d", srvIns->looperState.load());
            break;
        }
        ClearOptions(&from.options);
        ClearOptions(&reply.options);
        int recvRet = ReceiveDhcpMessage(ctx->instance->serverFd, &from);
        if (recvRet == RET_ERROR || recvRet == ERR_SELECT) {
            DHCP_LOGI("ReceiveDhcpMessage");
            continue;
        }
        if (ContinueReceive(&from, recvRet)) { continue; }
        InitReply(ctx, &from, &reply);
        int replyType = MessageProcess(ctx, &from, &reply);
        if (replyType && SendDhcpReply(ctx, replyType, &reply) != RET_SUCCESS) {
            DHCP_LOGE("failed to send reply message.");
        }
        NotifyConnetDeviceChanged(replyType, ctx);
    }
    FreeOptionList(&from.options);
    FreeOptionList(&reply.options);
    DHCP_LOGI("dhcp server message looper stopped.");
    {
        std::lock_guard<std::mutex> lock(srvIns->fdMutex);
        close(ctx->instance->serverFd);
        ctx->instance->serverFd = -1;
    }
    srvIns->looperState = LS_STOPED;
    return nullptr;
}

void NotifyConnetDeviceChanged(int replyType, PDhcpServerContext ctx)
{
    DHCP_LOGI("NotifyConnetDeviceChanged replyType:%{public}d", replyType);
    if (replyType == REPLY_ACK || replyType == REPLY_OFFER) {
        ServerContext *srvIns = GetServerInstance(ctx);
        if (srvIns == nullptr) {
            DHCP_LOGE("NotifyConnetDeviceChanged srvIns is nullptr");
            return;
        }
        int saveRet = SaveBindingRecoders(&srvIns->addressPool, 1);
        if (saveRet != RET_SUCCESS && saveRet != RET_WAIT_SAVE) {
            DHCP_LOGW("SaveBindingRecoders failed to save lease recoders.");
        }
        if (replyType == REPLY_ACK && srvIns->deviceConnectFun != nullptr) {
            DHCP_LOGI("NotifyConnetDeviceChanged deviceConnectFun");
            srvIns->deviceConnectFun(ctx->ifname);
        }
    }
}

static int CheckAddressRange(DhcpAddressPool *pool)
{
    uint32_t serverNetwork = NetworkAddress(pool->serverId, pool->netmask);
    uint32_t firstNetwork = NetworkAddress(pool->addressRange.beginAddress, pool->netmask);
    uint32_t secondNetwork = NetworkAddress(pool->addressRange.endAddress, pool->netmask);
    if (!serverNetwork || !firstNetwork || !secondNetwork) {
        DHCP_LOGE("network config error.");
        return DHCP_FALSE;
    }
    if (serverNetwork != firstNetwork || serverNetwork != secondNetwork) {
        DHCP_LOGE("server network and address pool network belong to different networks.");
        return DHCP_FALSE;
    }
    return DHCP_TRUE;
}

void InitBindingRecoders(DhcpAddressPool *pool)
{
    if (!pool) {
        DHCP_LOGE("address pool pointer is null.");
        return;
    }
    uint32_t realLeaseTotal = 0;
    std::lock_guard<std::mutex> leaseLock(g_leaseTableMutex);
    for (auto current: pool->leaseTable) {
        int invalidBindig;
        AddressBinding *binding = &current.second;
        if (binding && !IsEmptyHWAddr(binding->chaddr) && binding->ipAddress) {
            AddBinding(binding);
            realLeaseTotal++;
            invalidBindig = 0;
        } else {
            DHCP_LOGE("bad binding recoder.");
            invalidBindig = 1;
        }
        if (!invalidBindig && binding && pool->distribution < binding->ipAddress) {
            pool->distribution = binding->ipAddress;
        }
    }
    DHCP_LOGD("lease recoder total: %u", realLeaseTotal);
}

void InitLeaseFile(DhcpAddressPool *pool)
{
    const char *leasePath  = GetFilePath(DHCPD_LEASE_FILE);
    if (!leasePath || strlen(leasePath) == 0) {
        DHCP_LOGE("failed to get lease file path.");
        return;
    }
    if (access(leasePath, 0) != 0) {
        DHCP_LOGD("lease file path does not exist.");
        if (!CreatePath(leasePath)) {
            DHCP_LOGE("failed to create lease file directory.");
            return;
        } else {
            DHCP_LOGD("lease file directory created.");
        }
    }
    if (LoadBindingRecoders(pool) != RET_SUCCESS) {
        DHCP_LOGW("failed to load lease recoders.");
    }
    InitBindingRecoders(pool);
}

static void ExitProcess(void)
{
    DHCP_LOGD("dhcp server stopped.");
}

int StartDhcpServer(PDhcpServerContext ctx)
{
    DHCP_LOGI("%{public}s  %{public}d  start", __func__, __LINE__);
    if (!ctx) {
        DHCP_LOGE("server context pointer is null.");
        return RET_FAILED;
    }
    if (strlen(ctx->ifname) == 0) {
        DHCP_LOGE("context interface is null or empty.");
        return RET_FAILED;
    }
    ServerContext *srvIns = GetServerInstance(ctx);
    if (!srvIns) {
        DHCP_LOGE("dhcp server context instance pointer is null.");
        return RET_FAILED;
    }
    if (atexit(ExitProcess) != 0) {
        DHCP_LOGW("failed to regiester exit process function.");
    }
    if (!srvIns->initialized) {
        DHCP_LOGE("dhcp server no initialized.");
        return RET_FAILED;
    }
    DHCP_LOGD("bind interface: %{public}s, begin dhcp message looper", ctx->ifname);
    if (srvIns->callback) {
        srvIns->callback(ST_STARTING, 1, ctx->ifname);
    }
    if (IsNearlinkDhcpInterface(ctx->ifname))
        srvIns->looperState = LS_STARING;
    pthread_t threadId;
    int ret = pthread_create(&threadId, nullptr, BeginLooper, ctx);
    if (ret != RET_SUCCESS) {
        if (IsNearlinkDhcpInterface(ctx->ifname))
            srvIns->looperState = LS_IDLE;
        DHCP_LOGI("failed to start dhcp server.");
        return RET_FAILED;
    }
    pthread_detach(threadId);
    DHCP_LOGI("success to start dhcp server.");
    return RET_SUCCESS;
}

int StopDhcpServer(PDhcpServerContext ctx)
{
    ServerContext *srvIns = GetServerInstance(ctx);
    if (!srvIns) {
        DHCP_LOGE("StopDhcpServer GetServerInstance failed!");
        return RET_FAILED;
    }
    if (IsNearlinkDhcpInterface(ctx->ifname)) {
        // A timed-out free can be retried after the worker has finished. Never
        // resurrect STOPING from STOPED/IDLE: there is no worker left to drain it.
        int state = srvIns->looperState.load();
        while (state != LS_STOPED && state != LS_IDLE && state != LS_STOPING &&
               !srvIns->looperState.compare_exchange_weak(state, LS_STOPING)) {}
    } else {
        srvIns->looperState = LS_STOPING;
    }
    DHCP_LOGI("StopDhcpServer looperState LS_STOPING!");
    return RET_SUCCESS;
}

int GetServerStatus(PDhcpServerContext ctx)
{
    ServerContext *srvIns = GetServerInstance(ctx);
    if (!srvIns) {
        DHCP_LOGE("dhcp server context pointer is null.");
        return -1;
    }
    return srvIns->looperState.load();
}

int FillReply(PDhcpServerContext ctx, PDhcpMsgInfo received, PDhcpMsgInfo reply)
{
    if (!received || !reply) {
        return RET_ERROR;
    }
    ServerContext *srvIns = GetServerInstance(ctx);
    if (!srvIns) {
        DHCP_LOGE("dhcp server context pointer is null.");
        return RET_FAILED;
    }
    if (received->packet.ciaddr && received->packet.ciaddr != INADDR_BROADCAST) {
        reply->packet.ciaddr = received->packet.ciaddr;
    }
    reply->packet.flags = received->packet.flags;
    if (received->packet.xid) {
        reply->packet.xid = received->packet.xid;
    }
    if (received->packet.siaddr && received->packet.siaddr != INADDR_BROADCAST) {
        reply->packet.siaddr = received->packet.siaddr;
    } else {
        reply->packet.siaddr = srvIns->addressPool.serverId;
    }
    if (received->packet.giaddr && received->packet.giaddr != INADDR_BROADCAST) {
        reply->packet.giaddr = received->packet.giaddr;
    } else {
        if (srvIns->addressPool.gateway) {
            reply->packet.giaddr = srvIns->addressPool.gateway;
        }
    }
    if (received->packet.hlen) {
        reply->packet.hlen = received->packet.hlen;
        DHCP_LOGD("fill reply - chaddr:%s", ParseLogMac(received->packet.chaddr));
        if (memset_s(reply->packet.chaddr, sizeof(reply->packet.chaddr), 0, sizeof(reply->packet.chaddr)) != EOK) {
            DHCP_LOGE("failed to reset message packet[chaddr]!");
            return RET_ERROR;
        }
        if (memcpy_s(reply->packet.chaddr, sizeof(reply->packet.chaddr),
            received->packet.chaddr, sizeof(received->packet.chaddr)) != EOK) {
            DHCP_LOGE("failed to copy message packet[chaddr]!");
            return RET_ERROR;
        }
    }
    if (received->packet.giaddr) {
        reply->packet.giaddr = received->packet.giaddr;
    }
    return 0;
}

int AppendReplyTimeOptions(PDhcpServerContext ctx, PDhcpOptionList options)
{
    if (!ctx || !options) {
        DHCP_LOGE("server context or options pointer is null.");
        return RET_FAILED;
    }
    ServerContext *srvIns = GetServerInstance(ctx);
    if (!srvIns) {
        DHCP_LOGE("dhcp server context pointer is null.");
        return RET_FAILED;
    }
    uint32_t leaseTime = HostToNetwork(DHCP_LEASE_TIME);
    if (srvIns->addressPool.leaseTime) {
        leaseTime = HostToNetwork(srvIns->addressPool.leaseTime);
    }
    DhcpOption optLeaseTime = {IP_ADDRESS_LEASE_TIME_OPTION, OPT_TIME_LENGTH, {0}};
    FillU32Option(&optLeaseTime, leaseTime);
    PushBackOption(options, &optLeaseTime);

    uint32_t t1Time = HostToNetwork(DHCP_RENEWAL_TIME);
    if (srvIns->addressPool.renewalTime) {
        t1Time = HostToNetwork(srvIns->addressPool.renewalTime);
    }
    DhcpOption optRenewTime = {RENEWAL_TIME_VALUE_OPTION, OPT_TIME_LENGTH, {0}};
    FillU32Option(&optRenewTime, t1Time);
    PushBackOption(options, &optRenewTime);

    uint32_t t2Time = HostToNetwork(DHCP_REBINDING_TIME);
    if (srvIns->addressPool.rebindingTime) {
        t2Time = HostToNetwork(srvIns->addressPool.rebindingTime);
    }
    DhcpOption optRebindTime = {REBINDING_TIME_VALUE_OPTION, OPT_TIME_LENGTH, {0}};
    FillU32Option(&optRebindTime, t2Time);
    PushBackOption(options, &optRebindTime);

    return RET_SUCCESS;
}

static int Repending(DhcpAddressPool *pool, AddressBinding *binding)
{
    if (!pool) {
        return REPLY_NONE;
    }
    uint32_t bindingIp = binding->ipAddress;
    DHCP_LOGD(" binding found, bindIp:%s", ParseStrIp(bindingIp));
    binding->pendingInterval = NextPendingInterval(binding->pendingInterval);
    uint64_t curTime = Tmspsec();
    uint64_t tms = curTime > binding->pendingTime ? curTime - binding->pendingTime : 0;
    if (tms < binding->pendingInterval) {
        binding->pendingTime = curTime;
        DHCP_LOGW("message interval is too short, ignore the message.");
        return REPLY_NONE;
    }
    binding->pendingTime = curTime;
    binding->pendingInterval = 0;
    binding->bindingStatus = BIND_PENDING;
    uint32_t srcIp = SourceIpAddress();
    if (srcIp && srcIp != INADDR_BROADCAST && bindingIp != INADDR_BROADCAST && srcIp != bindingIp) {
        DHCP_LOGW("source ip address and bound ip address inconsistency.");
        return REPLY_NAK;
    }
    if (srcIp && srcIp == bindingIp) {
        std::lock_guard<std::mutex> leaseLock(g_leaseTableMutex);
        if (pool->leaseTable.count(srcIp) == 0) {
            DHCP_LOGD("can't find lease information.");
            pool->leaseTable[srcIp] = *binding;
        } else {
            pool->leaseTable[srcIp] = *binding;
        }
    }
    return REPLY_OFFER;
}

static int Rebinding(DhcpAddressPool *pool, AddressBinding *binding)
{
    uint64_t pendingTime = binding->pendingTime;
    int replyType = Repending(pool, binding);
    binding->bindingStatus = BIND_ASSOCIATED;
    if (!binding->leaseTime) {
        binding->leaseTime = pool->leaseTime;
    }
    binding->bindingTime = Tmspsec();
    binding->expireIn = binding->bindingTime + binding->leaseTime;
    binding->pendingTime = pendingTime;
    if (replyType == REPLY_OFFER) {
        replyType = REPLY_ACK;
    }
    return replyType;
}

static void AddAddressOption(PDhcpMsgInfo reply, uint8_t code, int32_t address)
{
    if (!reply) {
        return;
    }
    DhcpOption optAddress = {0, 0, {0}};
    optAddress.code = code;
    if (AppendAddressOption(&optAddress, address) != RET_SUCCESS) {
        DHCP_LOGE("failed to append address option.");
        return;
    };
    PushBackOption(&reply->options, &optAddress);
}

int AddReplyServerIdOption(PDhcpOptionList options, uint32_t serverId)
{
    if (!options) {
        DHCP_LOGE("option list pointer is null.");
        return RET_FAILED;
    }
    if (!serverId || serverId == INADDR_BROADCAST) {
        DHCP_LOGE("servier id error.");
        return RET_FAILED;
    }
    DhcpOption optSrvId = {SERVER_IDENTIFIER_OPTION, 0, {0}};
    if (AppendAddressOption(&optSrvId, serverId) != RET_SUCCESS) {
        DHCP_LOGE("failed to append server id option.");
        return RET_FAILED;
    }
    if (GetOption(options, SERVER_IDENTIFIER_OPTION)) {
        DHCP_LOGD("server identifier option exists.");
        return RET_SUCCESS;
    }
    PushBackOption(options, &optSrvId);
    return RET_SUCCESS;
}

static void AddReplyMessageTypeOption(PDhcpMsgInfo reply, uint8_t replyMessageType)
{
    if (!reply) {
        return;
    }
    DhcpOption optMsgType = {DHCP_MESSAGE_TYPE_OPTION, OPT_MESSAGE_TYPE_LEGTH, {replyMessageType, 0}};
    PushBackOption(&reply->options, &optMsgType);
}

AddressBinding *GetBinding(DhcpAddressPool *pool, PDhcpMsgInfo received)
{
    if (!pool) {
        return nullptr;
    }
    if (!received) {
        return nullptr;
    }
    AddressBinding *binding = pool->binding(received->packet.chaddr, &received->options);
    if (!binding) {
        binding = pool->newBinding(received->packet.chaddr, &received->options);
        if (binding == nullptr) {
            DHCP_LOGE("new binding is null");
            return nullptr;
        }
        if (pool->leaseTime) {
            binding->leaseTime = pool->leaseTime;
        }
        binding->ipAddress = pool->distribue(pool, received->packet.chaddr);
        DHCP_LOGI("new binding ip");
    } else {
        DHCP_LOGI("rebinding ip");
    }
    return binding;
}

int ReplyCommontOption(PDhcpServerContext ctx, PDhcpMsgInfo reply)
{
    if (!reply) {
        DHCP_LOGE("reply is nullptr!");
        return REPLY_NONE;
    }
    ServerContext *srvIns = GetServerInstance(ctx);
    if (!srvIns) {
        DHCP_LOGE("srvIns is nullptr!");
        return REPLY_NONE;
    }
    AddAddressOption(reply, SUBNET_MASK_OPTION, srvIns->addressPool.netmask);
    if (srvIns->addressPool.gateway) {
        AddAddressOption(reply, ROUTER_OPTION, srvIns->addressPool.gateway);
    }
    DhcpOption optVendorInfo = {VENDOR_SPECIFIC_INFO_OPTION, static_cast<uint8_t>(strlen(VNEDOR_OPEN_HARMONY)),
        VNEDOR_OPEN_HARMONY};
    PushBackOption(&reply->options, &optVendorInfo);
    uint32_t netAddress = reply->packet.yiaddr & srvIns->addressPool.netmask;
    uint32_t boastAddress = (~srvIns->addressPool.netmask) | netAddress;
    AddAddressOption(reply, BROADCAST_ADDRESS_OPTION, boastAddress);
    return REPLY_OFFER;
}

static int DiscoverReplyLeaseMessage(PDhcpServerContext ctx, PDhcpMsgInfo reply, ServerContext *srvIns,
    AddressBinding *binding)
{
    if (!ctx) {
        DHCP_LOGE("ctx pointer is null.");
        return REPLY_NONE;
    }
    if (!reply) {
        DHCP_LOGE("reply message pointer is null.");
        return REPLY_NONE;
    }
    if (!srvIns) {
        DHCP_LOGE("get server instance is nullptr!");
        return REPLY_NONE;
    }
    if (!binding) {
        DHCP_LOGI("Discover binding is null, reply none");
        return REPLY_NONE;
    }
    AddressBinding *lease = GetLease(&srvIns->addressPool, binding->ipAddress);
    if (!lease) {
        DHCP_LOGI("Discover add lease, binging ip:%{public}s mac:%{public}s",
            IntIpv4ToAnonymizeStr(binding->ipAddress).c_str(), ParseLogMac(binding->chaddr));
        AddLease(&srvIns->addressPool, binding);
        lease = GetLease(&srvIns->addressPool, binding->ipAddress);
    }
    if (!lease) {
        DHCP_LOGI("Discover lease is null, reply none");
        return REPLY_NONE;
    }
    AddReplyMessageTypeOption(reply, DHCPOFFER);
    reply->packet.yiaddr = lease->ipAddress;
    ReplyCommontOption(ctx, reply);
    DHCP_LOGI("Discover reply offer");
    return REPLY_OFFER;
}

static int OnReceivedDiscover(PDhcpServerContext ctx, PDhcpMsgInfo received, PDhcpMsgInfo reply)
{
    if (!received || !reply) {
        DHCP_LOGE("receive or reply message pointer is null.");
        return REPLY_NONE;
    }
    DHCP_LOGI("received 'Discover' message from:%{public}s", ParseLogMac(received->packet.chaddr));
    ServerContext *srvIns = GetServerInstance(ctx);
    if (!srvIns) {
        DHCP_LOGE("get server instance is nullptr!");
        return REPLY_NONE;
    }
    uint32_t reqIp = 0;
    PDhcpOption optReqIp = GetOption(&received->options, REQUESTED_IP_ADDRESS_OPTION);
    if (optReqIp) {
        reqIp = ParseIp(optReqIp->data);
        if (reqIp) {
            DHCP_LOGI("Discover request ip:%{public}s", IntIpv4ToAnonymizeStr(reqIp).c_str());
        }
    }
    uint32_t srcIp = SourceIpAddress();
    if (!srvIns->broadCastFlagEnable) {
        if (srcIp) {
            DHCP_LOGI("Discover client repending:%{public}s", IntIpv4ToAnonymizeStr(srcIp).c_str());
        } else {
            srcIp = INADDR_BROADCAST;
        }
        DestinationAddr(srcIp);
    }
    AddressBinding *binding = GetBinding(&srvIns->addressPool, received);
    if (!binding) {
        DHCP_LOGI("Discover binding is null, reply none");
        return REPLY_NONE;
    }
    if (!binding->ipAddress) {
        DHCP_LOGI("Discover binding ipAddress is null, reply none");
        return REPLY_NONE;
    }
    if (reqIp != 0 && reqIp != binding->ipAddress) {
        DHCP_LOGW("Discover package reqIp:%{public}s, binging ip:%{public}s",
            IntIpv4ToAnonymizeStr(reqIp).c_str(),
            IntIpv4ToAnonymizeStr(binding->ipAddress).c_str());
    }
    DeleteMacInLease(&srvIns->addressPool, binding);
    return DiscoverReplyLeaseMessage(ctx, reply, srvIns, binding);
}

static uint32_t GetRequestIpAddress(PDhcpMsgInfo received)
{
    uint32_t reqIp = 0;
    if (!received) {
        return reqIp;
    }
    PDhcpOption optReqIp = GetOption(&received->options, REQUESTED_IP_ADDRESS_OPTION);
    if (optReqIp) {
        reqIp = ParseIp(optReqIp->data);
    }
    return reqIp;
}

static int GetYourIpAddress(PDhcpMsgInfo received, uint32_t *yourIpAddr, DhcpAddressPool *pool)
{
    uint32_t cliIp = received->packet.ciaddr;
    uint32_t srcIp = SourceIpAddress();
    uint32_t reqIp = GetRequestIpAddress(received);
    DHCP_LOGI("cliIp:%{public}s srcIp:%{public}s reqIp:%{public}s",
        IntIpv4ToAnonymizeStr(cliIp).c_str(), IntIpv4ToAnonymizeStr(srcIp).c_str(),
        IntIpv4ToAnonymizeStr(reqIp).c_str());
    if (cliIp && srcIp && cliIp != srcIp) {
        DHCP_LOGE("error dhcp request message, missing required request option.");
        return RET_FAILED;
    }
    if (reqIp && srcIp && reqIp != srcIp) {
        DHCP_LOGE("error dhcp request message, request ip error.");
        return RET_FAILED;
    }
    if (cliIp && reqIp && cliIp != reqIp) {
        DHCP_LOGE("error dhcp request message, client ip error.");
        return RET_FAILED;
    }
    if (!srcIp && !cliIp && !reqIp) {
        DHCP_LOGE("no valid ip address found.");
        return RET_FAILED;
    }
    if (srcIp && srcIp != INADDR_BROADCAST) {
        *yourIpAddr = srcIp;
    } else if (cliIp && cliIp != INADDR_BROADCAST) {
        *yourIpAddr = cliIp;
    } else if (reqIp && reqIp != INADDR_BROADCAST) {
        *yourIpAddr = reqIp;
    }
    if ((ntohl(*yourIpAddr) < ntohl(pool->addressRange.beginAddress))
            || (ntohl(*yourIpAddr) > ntohl(pool->addressRange.endAddress))) {
        return RET_FAILED;
    }
    if (srcIp && srcIp != INADDR_BROADCAST) {
        DestinationAddr(srcIp);
    } else if (srcIp == INADDR_ANY) {
        DestinationAddr(INADDR_BROADCAST);
    }
    return RET_SUCCESS;
}

static int NotBindingRequest(DhcpAddressPool *pool, PDhcpMsgInfo received, PDhcpMsgInfo reply)
{
    uint32_t yourIpAddr = 0;
    if (GetYourIpAddress(received, &yourIpAddr, pool) != RET_SUCCESS) {
        DHCP_LOGI("GetYourIpAddress REPLY_NONE");
        return REPLY_NONE;
    }
    AddressBinding *lease = GetLease(pool, yourIpAddr);
    if (!lease) {
        if (SourceIpAddress()) {
            DHCP_LOGI("SourceIpAddress True REPLY_ACK");
            return REPLY_ACK;
        }
        DHCP_LOGI("SourceIpAddress REPLY_NAK");
        return REPLY_NAK;
    }
    int sameAddr = AddrEquels(lease->chaddr, received->packet.chaddr, MAC_ADDR_LENGTH);
    if (lease->bindingStatus == BIND_ASSOCIATED && !sameAddr) {
        if (!IsExpire(lease)) {
            DHCP_LOGI("Not IsExpire REPLY_NAK");
            return REPLY_NAK;
        }
        DHCP_LOGI("RemoveLease lease");
        RemoveLease(pool, lease);
    }
    AddressBinding *binding = pool->newBinding(received->packet.chaddr, &received->options);
    if (binding == nullptr) {
        DHCP_LOGE("Not binding request binding is null.");
        return REPLY_NONE;
    }
    binding->ipAddress = yourIpAddr;
    if (pool->leaseTime) {
        binding->leaseTime = pool->leaseTime;
    }
    int replyType = Repending(pool, binding);
    if (replyType != REPLY_OFFER) {
        DHCP_LOGI("replyType != REPLY_OFFER");
        return replyType;
    }
    lease = GetLease(pool, yourIpAddr);
    if (!lease) {
        DHCP_LOGI("add new lease recoder.");
        AddLease(pool, binding);
        lease = GetLease(pool, binding->ipAddress);
    }
    if (!lease) {
        DHCP_LOGI("failed to get lease.");
        return REPLY_NONE;
    }
    lease->bindingStatus = BIND_ASSOCIATED;
    lease->bindingTime = Tmspsec();
    lease->expireIn = lease->bindingTime + binding->leaseTime;
    reply->packet.yiaddr = lease->ipAddress;
    DHCP_LOGI("NotBindingRequest REPLY_ACK");
    return REPLY_ACK;
}

static int ValidateRequestMessage(const PDhcpServerContext ctx, const PDhcpMsgInfo received,
    PDhcpMsgInfo reply, uint32_t *yourIp)
{
    if (!received || !reply) {
        DHCP_LOGE("receive or reply message pointer is null.");
        return REPLY_NONE;
    }
    DHCP_LOGI("received 'Request' message from:%{public}s", ParseLogMac(received->packet.chaddr));
    uint32_t yourIpAddr = INADDR_BROADCAST;
    ServerContext *srvIns = GetServerInstance(ctx);
    if (!srvIns) {
        DHCP_LOGI("get server instance failed!");
        return RET_FAILED;
    }
    if (GetYourIpAddress(received, &yourIpAddr, &srvIns->addressPool) != RET_SUCCESS) {
        if (yourIpAddr && yourIpAddr != INADDR_BROADCAST) {
            AddressBinding *lease = GetLease(&srvIns->addressPool, yourIpAddr);
            if (lease) {
                RemoveLease(&srvIns->addressPool, lease);
                DHCP_LOGD("lease recoder has been removed.");
            } else {
                DHCP_LOGW("can't found lease recoder.");
            }
            RemoveBinding(received->packet.chaddr);
            return REPLY_NAK;
        }
        return REPLY_NONE;
    }
    PDhcpOption optReqSrvId = GetOption(&received->options, SERVER_IDENTIFIER_OPTION);
    if (optReqSrvId) {
        uint32_t reqSrvId = ParseIp(optReqSrvId->data);
        DHCP_LOGD(" reuquest server id is:%s", ParseStrIp(reqSrvId));
        if (reqSrvId != srvIns->addressPool.serverId) {
            DHCP_LOGW("other dhcp server process.");
            return REPLY_NONE;
        }
    } else {
        DHCP_LOGW("request message not specified server identifier option.");
    }
    *yourIp = yourIpAddr;
    return REPLY_ACK;
}

static int HasNobindgRequest(PDhcpServerContext ctx, PDhcpMsgInfo received, PDhcpMsgInfo reply)
{
    if (!received || !reply) {
        DHCP_LOGE("receive or reply message pointer is null.");
        return REPLY_NONE;
    }
    ServerContext *srvIns = GetServerInstance(ctx);
    if (!srvIns) {
        DHCP_LOGE("dhcp server context pointer is null.");
        return REPLY_NONE;
    }
    AddressBinding *binding = srvIns->addressPool.binding(received->packet.chaddr, &received->options);
    if (!binding && ALLOW_NOBINDING_REQUEST) {
        uint32_t srcIp = SourceIpAddress();
        uint32_t reqIp = GetRequestIpAddress(received);
        DHCP_LOGD("allow no binding request mode.");
        if (reqIp == 0 && srcIp == 0) {
            DHCP_LOGE("error dhcp message.");
            return REPLY_NONE;
        }
        if (!IpInNetwork(reqIp, srvIns->addressPool.serverId, srvIns->addressPool.netmask)) {
            DHCP_LOGE("error request ip.");
            return REPLY_NAK;
        }
        return NotBindingRequest(&srvIns->addressPool, received, reply);
    }
    return REPLY_NONE;
}

int GetVendorIdentifierOption(PDhcpMsgInfo received)
{
    PDhcpOption optVendorIdentifier = GetOption(&received->options, VENDOR_CLASS_IDENTIFIER_OPTION);
    if (optVendorIdentifier) {
        char strVendorIdentifier[DEVICE_NAME_STRING_LENGTH] = {0};
        if (memcpy_s(strVendorIdentifier, DEVICE_NAME_STRING_LENGTH, (char*)optVendorIdentifier->data,
            optVendorIdentifier->length) != EOK) {
            DHCP_LOGE("GetVendorIdentifierOption strClientIdentifier memcpy_s failed!");
            return REPLY_NONE;
        }
        DHCP_LOGD("GetVendorIdentifierOption strClientIdentifier:%{public}s", strVendorIdentifier);
    } else {
        DHCP_LOGD("GetVendorIdentifierOption pClientIdentifier is null");
    }
    return REPLY_NAK;
}

int GetHostNameOption(PDhcpMsgInfo received, AddressBinding *bindin)
{
    if (!bindin) {
        DHCP_LOGE("GetHostNameOption bindin is nullptr!");
        return REPLY_NONE;
    }
    PDhcpOption optHostName = GetOption(&received->options, HOST_NAME_OPTION);
    if (optHostName) {
        if (optHostName->length >= DEVICE_NAME_STRING_LENGTH) {
            DHCP_LOGE("GetHostNameOption length too large");
            return REPLY_NONE;
        }
        if (memchr(optHostName->data, '\n', optHostName->length) != NULL ||
            memchr(optHostName->data, '\r', optHostName->length) != NULL) {
            DHCP_LOGE("GetHostNameOption host name contains newline character");
            return REPLY_NONE;
        }
        if (memcpy_s(bindin->deviceName, DEVICE_NAME_STRING_LENGTH, (char*)optHostName->data,
            optHostName->length) != EOK) {
            DHCP_LOGE("GetHostNameOption pHost memcpy_s failed!");
            return REPLY_NONE;
        }
        bindin->deviceName[optHostName->length] = '\0';
        DHCP_LOGI("GetHostNameOption deviceName:%{public}s", bindin->deviceName);
    } else {
        if (strncpy_s(bindin->deviceName, sizeof(bindin->deviceName), "unknown-device",
            sizeof("unknown-device") - 1) != EOK) {
            DHCP_LOGE("set default name failed");
        }
        DHCP_LOGW("GetHostNameOption pHost is null, use default name");
        return REPLY_NONE;
    }
    return REPLY_ACK;
}

int GetUserClassOption(PDhcpMsgInfo received, AddressBinding *bindin)
{
    if (!bindin) {
        DHCP_LOGE("GetUserClassOption bindin is nullptr!");
        return REPLY_NONE;
    }
    PDhcpOption option = GetOption(&received->options, USER_CLASS_OPTION);
    if (option) {
        if (memcpy_s(bindin->userClass, DEVICE_NAME_STRING_LENGTH, (char*)option->data, option->length) != EOK) {
            DHCP_LOGE("GetUserClassOption memcpy_s failed!");
            return REPLY_NONE;
        }
        DHCP_LOGD("GetUserClassOption userClass:%{private}s", bindin->userClass);
    } else {
        DHCP_LOGD("GetUserClassOption pHost is null");
    }
    return REPLY_ACK;
}

int GetRapidCommitOption(PDhcpMsgInfo received, AddressBinding *bindin)
{
    if (!bindin) {
        DHCP_LOGE("GetRapidCommitOption bindin is nullptr!");
        return REPLY_NONE;
    }
    PDhcpOption option = GetOption(&received->options, RAPID_COMMIT_OPTION);
    if (option) {
        char value[DEVICE_NAME_STRING_LENGTH] = {0};
        if (memcpy_s(value, DEVICE_NAME_STRING_LENGTH, (char*)option->data, option->length) != EOK) {
            DHCP_LOGE("GetRapidCommitOption memcpy_s failed!");
            return REPLY_NONE;
        }
        DHCP_LOGD("GetRapidCommitOption value:%{public}s", value);
    } else {
        DHCP_LOGD("GetRapidCommitOption pHost is null");
    }
    return REPLY_ACK;
}

int GetOnlyIpv6Option(PDhcpMsgInfo received, AddressBinding *bindin)
{
    if (!bindin) {
        DHCP_LOGE("GetOnlyIpv6Option bindin is nullptr!");
        return REPLY_NONE;
    }
    PDhcpOption option = GetOption(&received->options, IPV6_ONLY_PREFERRED_OPTION);
    if (option) {
        char value[DEVICE_NAME_STRING_LENGTH] = {0};
        if (memcpy_s(value, DEVICE_NAME_STRING_LENGTH, (char*)option->data, option->length) != EOK) {
            DHCP_LOGE("GetOnlyIpv6Option memcpy_s failed!");
            return REPLY_NONE;
        }
        DHCP_LOGD("GetOnlyIpv6Option value:%{public}s", value);
    } else {
        DHCP_LOGD("GetOnlyIpv6Option pHost is null");
    }
    return REPLY_ACK;
}

int GetPortalUrlOption(PDhcpMsgInfo received, AddressBinding *bindin)
{
    if (!bindin) {
        DHCP_LOGE("GetPortalUrlOption bindin is nullptr!");
        return REPLY_NONE;
    }
    PDhcpOption option = GetOption(&received->options, IPV6_ONLY_PREFERRED_OPTION);
    if (option) {
        char value[DEVICE_NAME_STRING_LENGTH] = {0};
        if (memcpy_s(value, DEVICE_NAME_STRING_LENGTH, (char*)option->data, option->length) != EOK) {
            DHCP_LOGE("GetPortalUrlOption memcpy_s failed!");
            return REPLY_NONE;
        }
        DHCP_LOGD("GetPortalUrlOption value:%{public}s", value);
    } else {
        DHCP_LOGD("GetPortalUrlOption pHost is null");
    }
    return REPLY_ACK;
}

int ParseDhcpOption(PDhcpMsgInfo received, AddressBinding *bindin)
{
    if (!bindin) {
        DHCP_LOGE("ParseDhcpOption bindin is nullptr!");
        return REPLY_NONE;
    }
    DHCP_LOGE("enter ParseDhcpOption");
    GetHostNameOption(received, bindin);
    GetVendorIdentifierOption(received);
    GetUserClassOption(received, bindin);
    GetRapidCommitOption(received, bindin);
    GetOnlyIpv6Option(received, bindin);
    GetPortalUrlOption(received, bindin);
    return REPLY_ACK;
}

static int OnReceivedRequest(PDhcpServerContext ctx, PDhcpMsgInfo received, PDhcpMsgInfo reply)
{
    int ret;
    uint32_t yourIpAddr;
    if ((ret = ValidateRequestMessage(ctx, received, reply, &yourIpAddr)) != REPLY_ACK) {
        DHCP_LOGE("Request validateRequestMessage ret:%{public}d", ret);
        return ret;
    }
    ServerContext *srvIns = GetServerInstance(ctx);
    if (srvIns == nullptr) {
        DHCP_LOGE("OnReceivedRequest, srvIns is null");
        return REPLY_NONE;
    }
    AddressBinding *binding = srvIns->addressPool.binding(received->packet.chaddr, &received->options);
    if (binding == nullptr) {
        DHCP_LOGI("Request enter HasNobindgRequest!");
        return HasNobindgRequest(ctx, received, reply);
    }
    Rebinding(&srvIns->addressPool, binding);
    AddressBinding *lease = GetLease(&srvIns->addressPool, yourIpAddr);
    if (lease) {
        ParseDhcpOption(received, lease);
        DHCP_LOGI("request in lease, yourIpAddr:%{public}s, mac:%{public}s",
            IntIpv4ToAnonymizeStr(yourIpAddr).c_str(), ParseLogMac(lease->chaddr));
        int sameAddr = AddrEquels(lease->chaddr, received->packet.chaddr, MAC_ADDR_LENGTH);
        if (!sameAddr && !IsExpire(lease)) {
            DHCP_LOGW("invalid request ip address, reply nak, sameAddr:%{public}d", sameAddr);
            return REPLY_NAK;
        }
        if (!sameAddr && IsExpire(lease)) {
            if (memcpy_s(lease->chaddr, DHCP_HWADDR_LENGTH, binding->chaddr, MAC_ADDR_LENGTH) != EOK) {
                DHCP_LOGW("failed to update lease client address, sameAddr:%{public}d", sameAddr);
            }
        }
        lease->bindingStatus = BIND_ASSOCIATED;
        lease->bindingTime = binding->bindingTime;
        lease->expireIn = binding->expireIn;
        DHCP_LOGI("Request found lease recoder, sameAddr:%{public}d", sameAddr);
    } else {
        DHCP_LOGW("Request can not found lease recoder.");
    }
    uint32_t bindingIp = binding->ipAddress;
    if (bindingIp && yourIpAddr != INADDR_BROADCAST && yourIpAddr != bindingIp) {
        DHCP_LOGE("error request ip binding. reply nak");
        return REPLY_NAK;
    }
    reply->packet.yiaddr = bindingIp;
    ReplyCommontOption(ctx, reply);
    DHCP_LOGI("Request reply ack!");
    return REPLY_ACK;
}

static int OnReceivedDecline(PDhcpServerContext ctx, PDhcpMsgInfo received, PDhcpMsgInfo reply)
{
    if (!received || !reply) {
        return REPLY_NONE;
    }
    ServerContext *srvIns = GetServerInstance(ctx);
    if (!srvIns) {
        return REPLY_NONE;
    }
    DHCP_LOGI("received 'Decline' message from: %s.", ParseLogMac(received->packet.chaddr));
    uint32_t reqIp = 0;
    PDhcpOption optReqIp = GetOption(&received->options, REQUESTED_IP_ADDRESS_OPTION);
    if (optReqIp) {
        reqIp = ParseIp(optReqIp->data);
    }
    if (!reqIp) {
        DHCP_LOGD("invalid request ip address.");
        return REPLY_NONE;
    }
    AddressBinding* binding = srvIns->addressPool.binding(received->packet.chaddr, &received->options);
    if (!binding) {
        DHCP_LOGD("client not binding.");
        return REPLY_NONE;
    }
    if (binding->ipAddress != reqIp) {
        DHCP_LOGD("invalid request ip address.");
        return REPLY_NONE;
    }
    {
        std::lock_guard<std::mutex> leaseLock(g_leaseTableMutex);
        if (srvIns->addressPool.leaseTable.count(reqIp) > 0) {
            AddressBinding *lease = &srvIns->addressPool.leaseTable[reqIp];
            if (lease) {
                lease->bindingStatus = BIND_MODE_RESERVED;
                lease->expireIn = Tmspsec() + lease->leaseTime;
            } else {
                DHCP_LOGE("failed to get lease info.");
            }
        }
    }
    RemoveBinding(received->packet.chaddr);
    return REPLY_NONE;
}

static int OnReceivedRelease(PDhcpServerContext ctx, PDhcpMsgInfo received, PDhcpMsgInfo reply)
{
    if (!received || !reply) { return REPLY_NONE; }
    DHCP_LOGI("received 'Release' message from: %s", ParseLogMac(received->packet.chaddr));
    if (!ctx || !ctx->instance) {
        return RET_FAILED;
    }
    PDhcpOption optReqIp = GetOption(&received->options, REQUESTED_IP_ADDRESS_OPTION);
    if (!optReqIp) {
        DHCP_LOGW("missing required request option.");
    }
    ServerContext *srvIns = GetServerInstance(ctx);
    if (!srvIns) {
        DHCP_LOGE("dhcp server context pointer is null.");
        return RET_FAILED;
    }
    AddressBinding *binding = srvIns->addressPool.binding(received->packet.chaddr, &received->options);
    if (!binding) {
        DHCP_LOGD("client not binding.");
        return REPLY_NONE;
    }
    uint32_t bindIp = binding->ipAddress;
    uint32_t reqIp = 0;
    if (optReqIp) {
        reqIp = ParseIp(optReqIp->data);
    }
    uint32_t srcIp = SourceIpAddress();
    if (srcIp != 0 && reqIp != 0 && reqIp != srcIp) {
        DHCP_LOGE("error release message, invalid request ip address.");
        return REPLY_NONE;
    }
    if (bindIp != 0 && reqIp != 0 && reqIp != bindIp) {
        DHCP_LOGE("error release message, invalid request ip address.");
        return REPLY_NONE;
    }
    AddressBinding *lease = GetLease(&srvIns->addressPool, bindIp);
    if (lease) {
        RemoveLease(&srvIns->addressPool, lease);
        DHCP_LOGD("lease recoder has been removed.");
    } else {
        DHCP_LOGW("can't found lease recoder.");
    }

    if (ReleaseBinding(received->packet.chaddr) != RET_SUCCESS) {
        DHCP_LOGW("failed to release client[%s] bind.", ParseLogMac(received->packet.chaddr));
    }
    DHCP_LOGD("client released.");
    return REPLY_NONE;
}

static int OnReceivedInform(PDhcpServerContext ctx, PDhcpMsgInfo received, PDhcpMsgInfo reply)
{
    if (!received || !reply) {
        return REPLY_NONE;
    }
    ServerContext *srvIns = GetServerInstance(ctx);
    if (!srvIns) {
        DHCP_LOGE("dhcp server context pointer is null.");
        return RET_FAILED;
    }
    DHCP_LOGI("received 'Inform' message from: %s", ParseLogMac(received->packet.chaddr));
    if (IsEmptyHWAddr(received->packet.chaddr)) {
        DHCP_LOGD("error dhcp 'Inform' message.");
    }
    return REPLY_ACK;
}

static int AppendFixedOptions(PDhcpServerContext ctx, PDhcpMsgInfo reply)
{
    ServerContext *srvIns = GetServerInstance(ctx);
    if (!srvIns) {
        return RET_FAILED;
    }
    if (!reply) {
        return RET_FAILED;
    }
    if (srvIns->addressPool.fixedOptions.size > 0) {
        DhcpOptionNode *pNode = srvIns->addressPool.fixedOptions.first->next;
        for (size_t i = 0; pNode != nullptr && i < srvIns->addressPool.fixedOptions.size; i++) {
            PDhcpOption opt = nullptr;
            if (pNode->option.code) {
                opt = GetOption(&reply->options, pNode->option.code);
            }
            if (opt == nullptr) {
                PushBackOption(&reply->options, &pNode->option);
            }
            pNode = pNode->next;
        }
    }
    return RET_SUCCESS;
}
int AppendReplyTypeOption(PDhcpMsgInfo reply, int replyType)
{
    if (!reply) {
        return RET_FAILED;
    }
    if (!replyType) {
        return RET_FAILED;
    }
    uint8_t msgType = 0;
    switch (replyType) {
        case REPLY_OFFER:
            msgType = DHCPOFFER;
            break;
        case REPLY_ACK:
            msgType = DHCPACK;
            break;
        case REPLY_NAK:
            msgType = DHCPNAK;
            break;
        default:
            break;
    }
    PDhcpOption pOptMsgType = GetOption(&reply->options, DHCP_MESSAGE_TYPE_OPTION);
    if (!pOptMsgType) {
        DHCP_LOGD("append message type option for reply message, type:%hhu", msgType);
        DhcpOption optMsgType = {DHCP_MESSAGE_TYPE_OPTION, OPT_MESSAGE_TYPE_LEGTH, {msgType, 0}};
        PushFrontOption(&reply->options, &optMsgType);
    } else {
        if (pOptMsgType->data[0] != msgType) {
            DHCP_LOGD("error dhcp nak message type.");
            return RET_FAILED;
        }
    }
    return RET_SUCCESS;
}

static int SendDhcpOffer(PDhcpServerContext ctx, PDhcpMsgInfo reply)
{
    ServerContext *srvIns = GetServerInstance(ctx);
    if (!srvIns) {
        DHCP_LOGE("failed to get server instance");
        return RET_FAILED;
    }
    if (AppendReplyTypeOption(reply, REPLY_OFFER) != RET_SUCCESS) {
        DHCP_LOGE("failed to append reply type options");
        return RET_FAILED;
    }
    if (AppendReplyTimeOptions(ctx, &reply->options) != RET_SUCCESS ||
        AddReplyServerIdOption(&reply->options, srvIns->addressPool.serverId) != RET_SUCCESS) {
        DHCP_LOGE("failed to append reply time options");
        return RET_FAILED;
    }
    if (AppendFixedOptions(ctx, reply) != RET_SUCCESS) {
        DHCP_LOGW("failed to append fixed reply options.");
    }
    if (ParseReplyOptions(reply) != RET_SUCCESS) {
        DHCP_LOGE("failed to parse reply options.");
        return RET_FAILED;
    }
    if (TransmitOfferOrAckPacket(ctx, reply) != RET_SUCCESS) {
        DHCP_LOGE("send reply offer failed");
        return RET_FAILED;
    }
    DHCP_LOGI("send reply offer, length:%d", reply->length);
    return RET_SUCCESS;
}

static bool GetBroadCastFlag(PDhcpMsgInfo reply)
{
    bool broadcastFlag = false;
    if (reply->packet.flags >> (DHCP_MESSAGE_FLAG_LENGTH - 1)) {
        broadcastFlag = true;
    }

    if ((reply->packet.ciaddr == 0) && (broadcastFlag || (reply->packet.yiaddr == 0))) {
        return true;
    }
    return false;
}

static int32_t TransmitOfferOrAckPacket(PDhcpServerContext ctx, PDhcpMsgInfo reply)
{
    ServerContext *srvIns = GetServerInstance(ctx);
    if (!srvIns) {
        DHCP_LOGE("TransmitOfferOrAckPacket failed to get server instance");
        return RET_FAILED;
    }
    int ret = 0;
    sockaddr_in *bcastAddrIn = BroadcastAddrIn();
    sockaddr_in *destAddrIn = DestinationAddrIn();
    if (srvIns->broadCastFlagEnable == 1 && destAddrIn) {
        bool broadCastFlag = GetBroadCastFlag(reply);
        DHCP_LOGI("TransmitOfferOrAckPacket, broadCastFlag: %{public}d", broadCastFlag);
        if (!broadCastFlag) {
            destAddrIn->sin_addr.s_addr = reply->packet.yiaddr;
            std::string ipAddr = Ip4IntConvertToStr(reply->packet.yiaddr, false);
            const char *mac = ParseStrMac(reply->packet.chaddr, sizeof(reply->packet.chaddr));
            if (mac == nullptr) {
                return RET_FAILED;
            }
            std::string macAddr(mac);
            if (macAddr.empty()) {
                DHCP_LOGE("Failed to parse MAC address.");
                return RET_FAILED;
            }
            if (AddArpEntry(ctx->ifname, ipAddr, macAddr) < 0) {
                DHCP_LOGE("AddArpEntry failed");
                return RET_FAILED;
            }
            if (reply->length > 0 && reply->length <= REPLY_PACKET_MAX_LEN) {
                ret = sendto(srvIns->serverFd, &reply->packet,
                    reply->length, 0,
                    reinterpret_cast<struct sockaddr *>(destAddrIn),
                    sizeof(*destAddrIn));
            }
        } else {
            ret = sendto(srvIns->serverFd, &reply->packet, reply->length, 0,
                reinterpret_cast<struct sockaddr *>(bcastAddrIn),
                sizeof(*bcastAddrIn));
        }
    } else {
        ret = sendto(
            srvIns->serverFd, &reply->packet, reply->length, 0, reinterpret_cast<struct sockaddr *>(bcastAddrIn),
                sizeof(*bcastAddrIn));
    }
    if (!ret) {
        DHCP_LOGE("failed to send dhcp message.");
        return RET_FAILED;
    }
    return RET_SUCCESS;
}

static int SendDhcpAck(PDhcpServerContext ctx, PDhcpMsgInfo reply)
{
    if (AppendReplyTypeOption(reply, REPLY_ACK) != RET_SUCCESS) {
        DHCP_LOGE("failed to append reply type options");
        return RET_FAILED;
    }
    if (AppendFixedOptions(ctx, reply) != RET_SUCCESS) {
        DHCP_LOGW("failed to append fixed reply options.");
    }
    if (!ctx || !ctx->instance) {
        DHCP_LOGE("dhcp server context pointer is null.");
        return RET_FAILED;
    }
    ServerContext *srvIns = GetServerInstance(ctx);
    if (!srvIns) {
        DHCP_LOGE("dhcp server ServerContext pointer is null.");
        return RET_FAILED;
    }

    if (AppendReplyTimeOptions(ctx, &reply->options) != RET_SUCCESS) {
        DHCP_LOGE("failed to append reply time options");
        return RET_FAILED;
    }
    if (AddReplyServerIdOption(&reply->options, srvIns->addressPool.serverId) != RET_SUCCESS) {
        DHCP_LOGE("failed to add reply server options");
        return RET_FAILED;
    }
    if (ParseReplyOptions(reply) != RET_SUCCESS) {
        DHCP_LOGE("failed to parse reply options");
        return RET_FAILED;
    }
    if (TransmitOfferOrAckPacket(ctx, reply) != RET_SUCCESS) {
        DHCP_LOGE("failed to send dhcp ack message");
        return RET_FAILED;
    }
    DHCP_LOGI("send reply ack, size:%d", reply->length);
    return RET_SUCCESS;
}

static int SendDhcpNak(PDhcpServerContext ctx, PDhcpMsgInfo reply)
{
    if (AppendReplyTypeOption(reply, REPLY_NAK) != RET_SUCCESS) {
        DHCP_LOGE("failed to append reply type options");
        return RET_FAILED;
    }
    ServerContext *srvIns = GetServerInstance(ctx);
    if (srvIns == nullptr) {
        DHCP_LOGE("SendDhcpNak, srvIns is null");
        return RET_FAILED;
    }
    if (AddReplyServerIdOption(&reply->options, srvIns->addressPool.serverId) != RET_SUCCESS) {
        DHCP_LOGE("SendDhcpNak serverId fail!");
        return RET_FAILED;
    }
    DhcpOption optVendorInfo = {MESSAGE_OPTION, static_cast<uint8_t>(strlen("wrong network")), "wrong network"};
    PushBackOption(&reply->options, &optVendorInfo);
    if (ParseReplyOptions(reply) != RET_SUCCESS) {
        DHCP_LOGE("failed to parse reply options");
        return RET_FAILED;
    }

    struct sockaddr_in *destAddrIn = BroadcastAddrIn();
    int ret = sendto(srvIns->serverFd, &reply->packet, reply->length, 0,
        reinterpret_cast<struct sockaddr *>(destAddrIn),
        sizeof(*destAddrIn));
    if (!ret) {
        DHCP_LOGD("failed to send dhcp ack message.");
        return RET_FAILED;
    }
    DHCP_LOGI("send reply nak, size:%d", reply->length);
    return RET_SUCCESS;
}

static int ParseMessageOptions(PDhcpMsgInfo msg)
{
    DHCP_LOGI("start %{public}s %{public}d", __func__, __LINE__);
    if (msg->length < (DHCP_MSG_HEADER_SIZE + MAGIC_COOKIE_LENGTH)) {
        DHCP_LOGE("ParseMessageOptions, msg length:%{public}d error", msg->length);
        return RET_FAILED;
    }
    DhcpOption *current, *end;
    current = (DhcpOption *)msg->packet.options;
    end = (DhcpOption *)(((uint8_t *)msg->packet.options) + (msg->length - DHCP_MSG_HEADER_SIZE));
    if (memcmp(current, MAGIC_COOKIE_DATA, sizeof(MAGIC_COOKIE_DATA)) != 0) {
        DHCP_LOGE("bad magic cookie.");
        return RET_FAILED;
    }
    current = reinterpret_cast<DhcpOption *>(reinterpret_cast<uint8_t *>(current) + MAGIC_COOKIE_LENGTH);
    uint8_t *pos = ((reinterpret_cast<uint8_t *>(current)) + MAGIC_COOKIE_LENGTH);
    uint8_t *maxPos = ((reinterpret_cast<uint8_t *>(current)) +
        (DHCP_OPTION_SIZE - MAGIC_COOKIE_LENGTH - OPT_HEADER_LENGTH -1));
    int optTotal = 0;
    while (current < end && current->code != END_OPTION) {
        if (((uint8_t *)end) - ((uint8_t *)current) - current->length < OPT_HEADER_LENGTH) {
            DHCP_LOGE("current->code:%{public}d out of option range.", current->code);
            return RET_FAILED;
        }
        DHCP_LOGD("ParseMessageOptions, current code:%{public}d, len:%{public}d.", current->code, current->length);
        if (current->code == PAD_OPTION) {
            current = (DhcpOption *)(((uint8_t *)current) + 1);
            DHCP_LOGI("ParseMessageOptions, pad filed, continue.");
            continue;
        }
        if (current->code == TIME_OFFSET_OPTION) {
            current = (DhcpOption *)(((uint8_t *)current) + OPT_HEADER_LENGTH + current->length);
            DHCP_LOGI("ParseMessageOptions, time offset filed, len:%{public}d, continue.", current->length);
            continue;
        }
        pos += (OPT_HEADER_LENGTH + current->length);
        if (pos >= maxPos) {
            DHCP_LOGE("out of option max pos.");
            return RET_FAILED;
        }
        if (PushBackOption(&msg->options, current) != RET_SUCCESS) { DHCP_LOGD("failed to PushOption."); }
        current = (DhcpOption *)(((uint8_t *)current) + OPT_HEADER_LENGTH + current->length);
        optTotal++;
    }
    if (current < end && current->code == END_OPTION) {
        return RET_SUCCESS;
    }
    DHCP_LOGE("option list parse failed.");
    return RET_FAILED;
}

static int ResetMessageOptions(PDhcpMsgInfo reply)
{
    if (!reply || reply->options.size == 0) {
        DHCP_LOGE("message pointer is null.");
        return RET_ERROR;
    }
    if (memset_s(reply->packet.options, DHCP_OPTIONS_SIZE, 0, DHCP_OPTIONS_SIZE) != EOK) {
        DHCP_LOGE("failed to reset message options!");
        return RET_ERROR;
    }
    return RET_SUCCESS;
}

static int ValidateReplyOptions(PDhcpMsgInfo reply)
{
    if (!reply) {
        DHCP_LOGE("reply message pointer is null.");
        return RET_FAILED;
    }
    int ret = RET_FAILED;
    if ((ret = ResetMessageOptions(reply)) != RET_SUCCESS) {
        return ret;
    }
    reply->length = DHCP_MSG_HEADER_SIZE;
    PDhcpOptionNode pNode = reply->options.first;
    if (!pNode) {
        return RET_ERROR;
    }
    PDhcpOption pOptMsgType = GetOption(&reply->options, DHCP_MESSAGE_TYPE_OPTION);
    if (!pOptMsgType) {
        DHCP_LOGE("unknown reply message type.");
        return ret;
    }
    return RET_SUCCESS;
}

static int ParseReplyOptions(PDhcpMsgInfo reply)
{
    int ret = RET_FAILED;
    if ((ret = ValidateReplyOptions(reply)) != RET_SUCCESS) {
        return ret;
    }
    PDhcpOptionNode pNode = reply->options.first->next;
    DhcpOption endOpt = {END_OPTION, 0, {0}};
    PushBackOption(&reply->options, &endOpt);
    int replyOptsLength = 0;
    uint8_t *current = reply->packet.options, olen = MAGIC_COOKIE_LENGTH;
    size_t remainingSize = sizeof(reply->packet.options);
    uint32_t cookie = htonl(DHCP_MAGIC_COOKIE);
    if (memcpy_s(current, remainingSize, &cookie, olen) != EOK) {
        DHCP_LOGE("memcpy cookie out of options buffer!");
        return RET_FAILED;
    }
    replyOptsLength += olen;
    remainingSize -= olen;
    current += olen;
    ret = RET_SUCCESS;
    while (pNode) {
        if ((uint32_t)pNode->option.code == END_OPTION) {
            olen = OPT_HEADER_LENGTH + 1;
        } else {
            olen = OPT_HEADER_LENGTH + pNode->option.length;
        }
        if (memcpy_s(current, remainingSize, &pNode->option, olen) != EOK) {
            DHCP_LOGE("memcpy current option out of options buffer!");
            ret = RET_FAILED;
            break;
        }
        remainingSize -= olen;
        current += olen;
        replyOptsLength += olen;
        if ((uint32_t)pNode->option.code == END_OPTION) {
            break;
        }
        pNode = pNode->next;
        if (replyOptsLength >= DHCP_OPTIONS_SIZE) {
            DHCP_LOGE("current option out of options buffer!");
            ret = RET_FAILED;
            break;
        }
    }
    reply->length += replyOptsLength;
    return ret;
}

void RegisterDhcpCallback(PDhcpServerContext ctx, DhcpServerCallback callback)
{
    DHCP_LOGI("start %{public}s   %{public}d.", __func__, __LINE__);
    ServerContext *srvIns = GetServerInstance(ctx);
    if (!srvIns) {
        DHCP_LOGE("dhcp server context pointer is null.");
        return;
    }
    srvIns->callback = callback;
}

void RegisterDeviceChangedCallback(PDhcpServerContext ctx, DeviceConnectFun func)
{
    DHCP_LOGI("start %{public}s %{public}d.", __func__, __LINE__);
    ServerContext *srvIns = GetServerInstance(ctx);
    if (!srvIns) {
        DHCP_LOGE("dhcp server context pointer is null.");
        return;
    }
    srvIns->deviceConnectFun = func;
}

static int InitServerContext(DhcpConfig *config, DhcpServerContext *ctx)
{
    if (!config) {
        DHCP_LOGE("server configure pointer is null.");
        return RET_FAILED;
    }
    ServerContext *srvIns = GetServerInstance(ctx);
    if (!srvIns) {
        DHCP_LOGE("dhcp server context pointer is null.");
        return RET_FAILED;
    }
    if (InitAddressPool(&srvIns->addressPool, config->ifname, nullptr) != RET_SUCCESS) {
        DHCP_LOGD("failed to init address pool.");
        return RET_FAILED;
    }
    if (memcpy_s(ctx->ifname, sizeof(ctx->ifname), config->ifname, strlen(config->ifname)) != EOK) {
        DHCP_LOGD("failed to set interface name.");
        return RET_FAILED;
    }
    {
        std::lock_guard<std::mutex> lock(srvIns->fdMutex);
        srvIns->serverFd = 0;
    }
    srvIns->callback = 0;
    srvIns->looperState = LS_IDLE;
    srvIns->broadCastFlagEnable = static_cast<int>(config->broadcast);
    srvIns->addressPool.serverId = config->serverId;
    srvIns->addressPool.netmask = config->netmask;
    srvIns->addressPool.gateway = config->gateway;
    if (config->pool.beginAddress && config->pool.endAddress) {
        srvIns->addressPool.addressRange.beginAddress = config->pool.beginAddress;
        srvIns->addressPool.addressRange.endAddress = config->pool.endAddress;
    } else {
        srvIns->addressPool.addressRange.beginAddress = FirstIpAddress(config->serverId, config->netmask);
        srvIns->addressPool.addressRange.endAddress = LastIpAddress(config->serverId, config->netmask);
    }
    if (memcpy_s(srvIns->addressPool.ifname, sizeof(srvIns->addressPool.ifname),
        config->ifname, strlen(config->ifname)) != EOK) {
        DHCP_LOGD("failed to set interface name.");
        return RET_FAILED;
    }
    if (!CheckAddressRange(&srvIns->addressPool)) {
        DHCP_LOGE("failed to validate address range.");
        return RET_FAILED;
    }
    InitLeaseFile(&srvIns->addressPool);
    srvIns->addressPool.leaseTime = config->leaseTime;
    srvIns->addressPool.renewalTime = config->renewalTime;
    srvIns->addressPool.rebindingTime = config->rebindingTime;
    return RET_SUCCESS;
}

int InitServerFixedOptions(DhcpConfig *config, DhcpServerContext *ctx)
{
    if (!config) {
        DHCP_LOGE("server configure pointer is null.");
        return RET_FAILED;
    }
    ServerContext *srvIns = GetServerInstance(ctx);
    if (!srvIns) {
        DHCP_LOGE("dhcp server context pointer is null.");
        return RET_FAILED;
    }

    if (!HasInitialized(&config->options)) {
        DHCP_LOGE("dhcp configure has not been initialized.");
        return RET_FAILED;
    }
    if (InitOptionList(&srvIns->addressPool.fixedOptions) != RET_SUCCESS) {
        return RET_FAILED;
    }
    if (config->options.first != nullptr && config->options.size > 0) {
        DhcpOptionNode *pNode = config->options.first->next;
        for (size_t i = 0; pNode != nullptr && i < config->options.size; i++) {
            PushBackOption(&srvIns->addressPool.fixedOptions, &pNode->option);
            DHCP_LOGD("append fixed option ==> %hhu,%d", pNode->option.code,
                pNode->option.length);
            pNode = pNode->next;
        }
    }
    return RET_SUCCESS;
}

PDhcpServerContext InitializeServer(DhcpConfig *config)
{
    DHCP_LOGI("start %{public}s   %{public}d.", __func__, __LINE__);
    DhcpServerContext *context = nullptr;
    if (!config) {
        DHCP_LOGE("dhcp server config pointer is null.");
        return nullptr;
    }
    if (strlen(config->ifname) == 0) {
        DHCP_LOGE("can't found interface name config.");
        return nullptr;
    }
    if (!config->serverId || !config->netmask) {
        DHCP_LOGE("missing required parameter or config item: \"serverId\", \"netmask\"");
        return nullptr;
    }
    if ((context = (DhcpServerContext *)calloc(1, sizeof(DhcpServerContext))) == nullptr) {
        DHCP_LOGE("failed to calloc server context.");
        return nullptr;
    }
    if (IsNearlinkDhcpInterface(config->ifname) &&
        strcpy_s(context->ifname, sizeof(context->ifname), config->ifname) != EOK) {
        free(context);
        return nullptr;
    }
    DhcpNearlinkBindingScope scope(config->ifname);
    bool nearlink = IsNearlinkDhcpInterface(config->ifname);
    context->instance =
        nearlink ? new (std::nothrow) ServerContext{} : static_cast<ServerContext *>(calloc(1, sizeof(ServerContext)));
    if (context->instance == nullptr) {
        DHCP_LOGE("failed to calloc server instance.");
        FreeServerContext(&context);
        return nullptr;
    }
    if (InitServerContext(config, context) != RET_SUCCESS) {
        DHCP_LOGE("failed initialize dhcp server context.");
        FreeServerContext(&context);
        return nullptr;
    }
    if (InitServerFixedOptions(config, context) != RET_SUCCESS) {
        DHCP_LOGE("failed initialize dhcp server fixed options.");
        FreeServerContext(&context);
        return nullptr;
    }
    DHCP_LOGI("server id: %{private}s", ParseStrIp(config->serverId));
    DHCP_LOGI("netmask: %{private}s", ParseStrIp(config->netmask));
    if (config->gateway) {
        DHCP_LOGI("gateway: %{private}s", ParseStrIp(config->gateway));
    }
    DHCP_LOGI("address range begin of: %{private}s", ParseStrIp(config->pool.beginAddress));
    DHCP_LOGI("address range end of: %{private}s", ParseStrIp(config->pool.endAddress));
    context->instance->initialized = 1;
    return context;
}

int FreeServerContext(PDhcpServerContext *ctx)
{
    if (ctx == nullptr || *ctx == nullptr) {
        DHCP_LOGE("dhcp server context pointer is null.");
        return RET_FAILED;
    }
    ServerContext *srvIns = GetServerInstance(*ctx);
    if (!srvIns) {
        DHCP_LOGE("dhcp server instance pointer is null.");
        return RET_FAILED;
    }
    int times = 5;
    while (srvIns->looperState != LS_STOPED && srvIns->looperState != LS_IDLE) {
        DHCP_LOGE("FreeServerContext wait 300ms.");
        usleep(300000);
        times--;
        if (times <= 0) {
            return RET_FAILED;
        }
    }
    FreeAddressPool(&srvIns->addressPool);
    if ((*ctx)->instance != nullptr) {
        if (IsNearlinkDhcpInterface((*ctx)->ifname))
            delete (*ctx)->instance;
        else
            free((*ctx)->instance);
        (*ctx)->instance = nullptr;
    }
    free(*ctx);
    *ctx = nullptr;
    return RET_SUCCESS;
}
