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
#include <linux/if_link.h>
#include <linux/rtnetlink.h>
#include "dhcp_ipv6_client.h"
#include "dhcp_ipv6_define.h"
#include "securec.h"
#include <unistd.h>
#include "dhcp_logger.h"
#include <net/if.h>
#include "dhcp_ipv6_dns_repository.h"
#include "dhcp_common_utils.h"
#if DHCPV6_ENABLE
#include "dhcp_v6_constants.h"
#endif
#include <map>
#include <algorithm>
#include <chrono>

namespace OHOS {
namespace DHCP {
DEFINE_DHCPLOG_DHCP_LABEL("WifiDhcpIpv6Event");

const int KERNEL_SOCKET_FAMILY = 16;
const int KERNEL_SOCKET_IFA_FAMILY = 10;
const int KERNEL_ICMP_TYPE = 134;
constexpr int ND_OPT_HDR_LENGTH_BYTES = 2;
// Reason: Router typically sends RA within 3 seconds after link-local address is configured.
// Waiting avoids querying old RA flags from the previous network before new RA arrives.
const int WAIT_RA_DELAY = 3;
#ifndef USER_HZ
#define USER_HZ 100
#endif
#ifndef IFA_F_TEMPORARY
#define IFA_F_TEMPORARY 0x01
#endif
void DhcpIpv6Client::setSocketFilter(void* addr)
{
    if (!addr) {
        DHCP_LOGE("setSocketFilter failed, addr invalid.");
        return;
    }
    struct sockaddr_nl *nladdr = reinterpret_cast<struct sockaddr_nl*>(addr);
    nladdr->nl_family = KERNEL_SOCKET_FAMILY;
    nladdr->nl_pid = 0;
    nladdr->nl_groups = RTMGRP_LINK | RTMGRP_IPV6_IFADDR | RTMGRP_IPV6_ROUTE | (1 << (RTNLGRP_ND_USEROPT - 1));
}

void DhcpIpv6Client::parseNdUserOptMessage(void* data, int len)
{
    if (!data) {
        DHCP_LOGE("parseNdUserOptMessage failed, msg invalid.");
        return;
    }
    if (len < (static_cast<int>(sizeof(struct nduseroptmsg)) + ND_OPT_HDR_LENGTH_BYTES)) {
        DHCP_LOGE("parseNdUserOptMessage invalid len:%{public}d.", len);
        return;
    }
    struct nduseroptmsg *msg = (struct nduseroptmsg *)data;
    if (msg->nduseropt_opts_len > len) {
        DHCP_LOGE("invalid len msg->nduseropt_opts_len:%{public}d > len:%{public}d",
            msg->nduseropt_opts_len, len);
        return;
    }
    int optlen = msg->nduseropt_opts_len;
    if (msg->nduseropt_family != KERNEL_SOCKET_IFA_FAMILY) {
        DHCP_LOGE("invalid nduseropt_family:%{public}d", msg->nduseropt_family);
        return;
    }
    if (msg->nduseropt_icmp_type != KERNEL_ICMP_TYPE || msg->nduseropt_icmp_code != 0) {
        DHCP_LOGE("invalid nduseropt_icmp_type:%{public}d, nduseropt_icmp_type:%{public}d",
            msg->nduseropt_icmp_type, msg->nduseropt_icmp_code);
        return;
    }
    onIpv6DnsAddEvent((void*)(msg + 1), optlen, msg->nduseropt_ifindex);
}

void DhcpIpv6Client::parseRouteAttributes(void* rtMsgPtr, size_t size, char* dst, char* gateway, int& ifindex)
{
    if (!rtMsgPtr || !dst || !gateway) {
        return;
    }
    struct rtmsg* rtMsg = reinterpret_cast<struct rtmsg*>(rtMsgPtr);
    int32_t rtmFamily = rtMsg->rtm_family;
    rtattr *rtaInfo = NULL;
    for (rtaInfo = RTM_RTA(rtMsg); RTA_OK(rtaInfo, (int)size); rtaInfo = RTA_NEXT(rtaInfo, size)) {
        switch (rtaInfo->rta_type) {
            case RTA_GATEWAY:
                if (rtaInfo->rta_len < (RTA_LENGTH(IPV6_LENGTH_BYTES))) {
                    return;
                }
                if (GetIpFromS6Address(RTA_DATA(rtaInfo), rtmFamily, gateway, DHCP_INET6_ADDRSTRLEN) != 0) {
                    DHCP_LOGE("inet_ntop RTA_GATEWAY failed.");
                    return;
                }
                break;
            case RTA_DST:
                if (rtaInfo->rta_len < (RTA_LENGTH(IPV6_LENGTH_BYTES))) {
                    return;
                }
                if (GetIpFromS6Address(RTA_DATA(rtaInfo), rtmFamily, dst, DHCP_INET6_ADDRSTRLEN) != 0) {
                    DHCP_LOGE("inet_ntop RTA_DST failed.");
                    return;
                }
                break;
            case RTA_OIF:
                if (rtaInfo->rta_len < (RTA_LENGTH(sizeof(int32_t)))) {
                    return;
                }
                ifindex = *(reinterpret_cast<int32_t*>(RTA_DATA(rtaInfo)));
                break;
            case RTA_CACHEINFO:
                if (rtaInfo->rta_len < RTA_LENGTH(sizeof(struct rta_cacheinfo))) {
                    return;
                } else {
                    struct rta_cacheinfo *cacheInfo = (struct rta_cacheinfo *)RTA_DATA(rtaInfo);
                    if (cacheInfo->rta_expires > 0) { //if expires < 0, it means invalid
                        uint32_t sec = static_cast<uint32_t>(cacheInfo->rta_expires / USER_HZ);
                        std::lock_guard<std::mutex> lock(mutex_);
                        DhcpIpv6InfoManager::AddLifetime(dhcpIpv6Info, sec, LifeType::ROUTE_LIFE);
                    }
                }
                break;
            default:
                break;
        }
    }
}

void DhcpIpv6Client::parseNDRouteMessage(void* msg)
{
    if (msg == NULL) {
        return;
    }
    struct nlmsghdr *hdrMsg = (struct nlmsghdr*)msg;
    if (hdrMsg->nlmsg_len < sizeof(struct ndmsg) + sizeof(struct rtmsg)) {
        return;
    }
    struct rtmsg* rtMsg = reinterpret_cast<struct rtmsg*>(NLMSG_DATA(hdrMsg));
    if (hdrMsg->nlmsg_len < sizeof(struct rtmsg) + NLMSG_LENGTH(0)) {
        DHCP_LOGE("invalid msglen:%{public}d", hdrMsg->nlmsg_len);
        return;
    }
    DHCP_LOGI("parseNDRouteMessage rtm_protocol: %{public}d, rtm_scope: %{public}d, rtm_type: %{public}d, "
              "rtm_src_len: %{public}d, rtm_flags: %{public}d",
              rtMsg->rtm_protocol, rtMsg->rtm_scope, rtMsg->rtm_type, rtMsg->rtm_src_len, rtMsg->rtm_flags);
    // Ignore static routes we've set up ourselves.
    if ((rtMsg->rtm_protocol != RTPROT_KERNEL && rtMsg->rtm_protocol != RTPROT_RA) ||
     // We're only interested in global unicast routes.
        (rtMsg->rtm_scope != RT_SCOPE_UNIVERSE) || (rtMsg->rtm_type != RTN_UNICAST) ||
        // We don't support source routing.
        // Cloned routes aren't real routes.
        (rtMsg->rtm_src_len != 0) || (rtMsg->rtm_flags & RTM_F_CLONED)) {
        DHCP_LOGE("invalid arg");
        return;
    }
    char dst[DHCP_INET6_ADDRSTRLEN] = {0};
    char gateway[DHCP_INET6_ADDRSTRLEN] = {0};
    int ifindex = -1;
    size_t size = RTM_PAYLOAD(hdrMsg);
    parseRouteAttributes(rtMsg, size, dst, gateway, ifindex);
    OnIpv6RouteUpdateEvent(gateway, dst, ifindex, hdrMsg->nlmsg_type == RTM_NEWROUTE);
}

void DhcpIpv6Client::parseNewneighMessage(void* msg)
{
    if (!msg) {
        return;
    }
    struct nlmsghdr *nlh = (struct nlmsghdr*)msg;
    if (nlh->nlmsg_len < sizeof(struct ndmsg) + sizeof(struct nlmsghdr)) {
        return;
    }
    struct ndmsg *ndm = (struct ndmsg *)NLMSG_DATA(nlh);
    if (!ndm) {
        return;
    }
    if (ndm->ndm_family != KERNEL_SOCKET_IFA_FAMILY ||
        ndm->ndm_state != NUD_REACHABLE) {
        return;
    }
    struct rtattr *rta = RTM_RTA(ndm);
    int rtl = static_cast<int>(RTM_PAYLOAD(nlh));
    while (RTA_OK(rta, rtl)) {
        if (rta->rta_type == NDA_DST) {
            if (rta->rta_len < (RTA_LENGTH(IPV6_LENGTH_BYTES))) {
                return;
            }
            struct in6_addr *addr = (struct in6_addr *)RTA_DATA(rta);
            char gateway[DHCP_INET6_ADDRSTRLEN] = {0};
            if (GetIpFromS6Address(addr, ndm->ndm_family, gateway,
                DHCP_INET6_ADDRSTRLEN) != 0) {
                DHCP_LOGE("inet_ntop routeAddr failed.");
                return;
            }
            DHCP_LOGD("parseNewneighMessage: %{public}s", gateway);
            break;
        }
        rta = RTA_NEXT(rta, rtl);
    }
}

void DhcpIpv6Client::fillRouteData(char* buff, int &len)
{
    if (!buff) {
        return;
    }
    struct nlmsghdr *nlh = (struct nlmsghdr *)buff;
    nlh->nlmsg_len = NLMSG_SPACE(sizeof(struct ndmsg));
    nlh->nlmsg_type = RTM_GETNEIGH;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_seq = 1;
    nlh->nlmsg_pid = static_cast<unsigned int>(getpid());
    len = nlh->nlmsg_len;
}

void DhcpIpv6Client::handleKernelEvent(const uint8_t* data, int len)
{
    if (!data || len < static_cast<int32_t>(sizeof(struct nlmsghdr))) {
        DHCP_LOGE("handleKernelEvent failed, data invalid, len:%{public}d.", len);
        return;
    }
    struct nlmsghdr *nlh = (struct nlmsghdr*)data;
    while (nlh && NLMSG_OK(nlh, len) && nlh->nlmsg_type != static_cast<__u32>(NLMSG_DONE)) {
        DHCP_LOGD("handleKernelEvent nlmsg_type:%{public}d.", nlh->nlmsg_type);
        if (nlh->nlmsg_type == RTM_NEWADDR) {
            DHCP_LOGI("handleKernelEvent nlmsg_type: RTM_NEWADDR.");
            ParseAddrMessage((void *)nlh);
        } else if (nlh->nlmsg_type == RTM_DELADDR) {
            DHCP_LOGI("handleKernelEvent nlmsg_type: RTM_DELADDR");
            ParseAddrMessage((void *)nlh);
        } else if (nlh->nlmsg_type == RTM_NEWNDUSEROPT) {
            DHCP_LOGI("handleKernelEvent nlmsg_type: RTM_NEWNDUSEROPT.");
            if (nlh->nlmsg_len < (sizeof(struct nlmsghdr) + sizeof(struct nduseroptmsg))) {
                DHCP_LOGE("handleKernelEvent nlmsg_len:%{public}u is invalid.", nlh->nlmsg_len);
                return;
            }
            struct nduseroptmsg* ndmsg = (struct nduseroptmsg*)NLMSG_DATA(nlh);
            size_t optsize = NLMSG_PAYLOAD(nlh, sizeof(*ndmsg));
            parseNdUserOptMessage((void*)ndmsg, optsize);
        } else if (nlh->nlmsg_type == RTM_NEWROUTE) {
            DHCP_LOGI("handleKernelEvent nlmsg_type: RTM_NEWROUTE.");
            parseNDRouteMessage((void*)nlh);
        } else if (nlh->nlmsg_type == RTM_DELROUTE) {
            DHCP_LOGI("handleKernelEvent nlmsg_type: RTM_DELROUTE");
            parseNDRouteMessage((void*)nlh);
        } else if (nlh->nlmsg_type == RTM_NEWNEIGH) {
            parseNewneighMessage((void*)nlh);
        } else if (nlh->nlmsg_type == RTM_NEWLINK) {
            DHCP_LOGI("handleKernelEvent nlmsg_type: RTM_NEWLINK.");
            ParseLinkMessage((void*)nlh);
        }
        nlh = NLMSG_NEXT(nlh, len);
    }
}
void DhcpIpv6Client::ParseAddrAttributes(void *addrMsgptr, int32_t len, char *addresses, int &scope, bool &isTemporary)
{
    if (addrMsgptr == nullptr || addresses == nullptr) {
        DHCP_LOGE("ParseAddrAttributes addrMsg or addresses is nullptr.");
        return;
    }
    struct ifaddrmsg *addrMsg = reinterpret_cast<ifaddrmsg *>(addrMsgptr);
    uint32_t preferredLifetime = 0;
    uint32_t validLifetime = 0;
    isTemporary = false;
    for (rtattr *rtAttr = IFA_RTA(addrMsg); RTA_OK(rtAttr, len); rtAttr = RTA_NEXT(rtAttr, len)) {
        if (rtAttr == nullptr) {
            DHCP_LOGE("Invalid ifaddrmsg\n");
            return;
        }
        if (rtAttr->rta_type == IFA_ADDRESS) {
            if (rtAttr->rta_len < RTA_LENGTH(IPV6_LENGTH_BYTES)) {
                DHCP_LOGI("handleKernelEvent rta_len:%{public}u is invalid.", rtAttr->rta_len);
                continue;
            }
            if (GetIpFromS6Address(RTA_DATA(rtAttr), addrMsg->ifa_family, addresses, DHCP_INET6_ADDRSTRLEN) != 0) {
                DHCP_LOGE("inet_ntop addresses failed.");
                return;
            }
            scope = GetAddrScope(RTA_DATA(rtAttr));
            isTemporary = (addrMsg->ifa_flags & IFA_F_TEMPORARY) != 0;
            DHCP_LOGI("ParseAddrMessage %{private}s, isTemporary: %{public}d\n", addresses, isTemporary);
        } else if (rtAttr->rta_type == IFA_CACHEINFO) {
            if (rtAttr->rta_len < RTA_LENGTH(sizeof(struct ifa_cacheinfo))) {
                DHCP_LOGI("handleKernelEvent ifa_cacheinfo rta_len:%{public}u is invalid.", rtAttr->rta_len);
                continue;
            }
            struct ifa_cacheinfo *cacheInfo = (struct ifa_cacheinfo *)RTA_DATA(rtAttr);
            preferredLifetime = cacheInfo->ifa_prefered;
            validLifetime = cacheInfo->ifa_valid;
            DHCP_LOGI("ParseAddrMessage preferredLifetime:%{public}u, validLifetime:%{public}u\n",
                preferredLifetime, validLifetime);
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (isTemporary) {
                    DhcpIpv6InfoManager::AddLifetime(dhcpIpv6Info, preferredLifetime, LifeType::TEMP_PREF_LIFE);
                    DhcpIpv6InfoManager::AddLifetime(dhcpIpv6Info, validLifetime, LifeType::TEMP_VALID_LIFE);
                    DhcpIpv6InfoManager::UpdateUseTempAddr(dhcpIpv6Info.lifetime, interfaceName);
                } else {
                    DhcpIpv6InfoManager::AddLifetime(dhcpIpv6Info, preferredLifetime, LifeType::PREF_LIFE);
                    DhcpIpv6InfoManager::AddLifetime(dhcpIpv6Info, validLifetime, LifeType::VALID_LIFE);
                }
            }
        }
    }
}

void DhcpIpv6Client::ParseAddrMessage(void *msg)
{
    if (msg == nullptr) {
        DHCP_LOGE("ParseAddrMessage msg is nullptr.");
        return;
    }

    struct nlmsghdr *hdrMsg = (struct nlmsghdr*)msg;
    if (hdrMsg->nlmsg_len < (sizeof(struct nlmsghdr) + sizeof(struct ifaddrmsg))) {
        DHCP_LOGE("ParseAddrMessage nlmsg_len:%{public}u is invalid.", hdrMsg->nlmsg_len);
        return;
    }

    int32_t nlType = hdrMsg->nlmsg_type;
    if (nlType != RTM_NEWADDR && nlType != RTM_DELADDR) {
        DHCP_LOGE("ParseAddrMessage on incorrect message nlType 0x%{public}x\n", nlType);
        return;
    }
    ifaddrmsg *addrMsg = reinterpret_cast<ifaddrmsg *>(NLMSG_DATA(hdrMsg));
    if (addrMsg->ifa_family != AF_INET6 || addrMsg->ifa_index != if_nametoindex(interfaceName.c_str())) return;
    if (layer3_) {
        if (ParseL3Address(msg)) PublishIpv6Result();
        return;
    }
    char addresses[DHCP_INET6_ADDRSTRLEN];
    memset_s(addresses, DHCP_INET6_ADDRSTRLEN, 0, DHCP_INET6_ADDRSTRLEN);
    int scope = IPV6_ADDR_LINKLOCAL;
    bool isTemporary = false;
    int32_t len = static_cast<int32_t>(IFA_PAYLOAD(hdrMsg));
    ParseAddrAttributes(addrMsg, len, addresses, scope, isTemporary);
    if (addresses[0] == '\0') {
        return;
    }

    DHCP_LOGI("ParseAddrMessage: parsed addr %{public}s, scope %{public}d (0=global, 0x20=linklocal)",
              Ipv6Anonymize(addresses).c_str(), scope);

    // Notify DHCPv6 client about global address deletion for DAD handling
    if (scope == IPV6_ADDR_SCOPE_GLOBAL && nlType == RTM_DELADDR) {
        bool dadFailed = (addrMsg->ifa_flags & IFA_F_DADFAILED);
        if (dadFailed) {
            decltype(onIpv6DadResult_) callback;
            std::string ifname;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                ifname = interfaceName;
            }
            {
                std::lock_guard<std::mutex> lock(ipv6CallbackMutex_);
                callback = onIpv6DadResult_;
            }
            if (callback) {
                DHCP_LOGI("ParseAddrMessage: DAD failure for %{public}s", Ipv6Anonymize(addresses).c_str());
                callback(ifname, std::string(addresses), true);  // true = DAD failure
            }
        }
    }
    OnIpv6AddressUpdateEvent(addresses, DHCP_INET6_ADDRSTRLEN, addrMsg->ifa_prefixlen, addrMsg->ifa_index,
        scope, nlType == RTM_NEWADDR);
    return;
}

bool DhcpIpv6Client::ParseL3Address(void *msg)
{
    auto header = static_cast<nlmsghdr *>(msg);
    auto info = reinterpret_cast<ifaddrmsg *>(NLMSG_DATA(header));
    L3Ipv6Address address;
    address.observedAt = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    address.ifindex = info->ifa_index;
    address.prefixLength = info->ifa_prefixlen;
    address.flags = info->ifa_flags;
    bool haveAddress = false, haveLifetime = false;
    int length = IFA_PAYLOAD(header);
    for (auto attr = IFA_RTA(info); RTA_OK(attr, length); attr = RTA_NEXT(attr, length)) {
        if (attr->rta_type == IFA_ADDRESS) {
            if (RTA_PAYLOAD(attr) != 16) return false;
            char text[DHCP_INET6_ADDRSTRLEN]{};
            if (GetIpFromS6Address(RTA_DATA(attr), AF_INET6, text, sizeof(text)) != 0) return false;
            address.address = text; haveAddress = true;
        } else if (attr->rta_type == IFA_CACHEINFO) {
            if (static_cast<size_t>(RTA_PAYLOAD(attr)) < sizeof(ifa_cacheinfo)) return false;
            ifa_cacheinfo cache{}; memcpy_s(&cache, sizeof(cache), RTA_DATA(attr), sizeof(cache));
            address.preferredLifetime = cache.ifa_prefered; address.validLifetime = cache.ifa_valid;
            haveLifetime = true;
        } else if (attr->rta_type == IFA_FLAGS) {
            if (RTA_PAYLOAD(attr) != sizeof(uint32_t)) return false;
            memcpy_s(&address.flags, sizeof(address.flags), RTA_DATA(attr), sizeof(address.flags));
        }
    }
    if (length != 0 || !haveAddress || address.prefixLength > 128 ||
        (header->nlmsg_type == RTM_NEWADDR && (!haveLifetime || address.preferredLifetime > address.validLifetime)))
        return false;
    std::lock_guard<std::mutex> lock(mutex_);
    auto &records = dhcpIpv6Info.l3Addresses;
    auto found = std::find_if(records.begin(), records.end(), [&address](const L3Ipv6Address &a) {
        return a.address == address.address;
    });
    if (header->nlmsg_type == RTM_DELADDR) {
        if (found != records.end()) records.erase(found);
        dhcpIpv6Info.IpAddrMap.erase(address.address);
    } else {
        if (found == records.end()) {
            if (records.size() >= 8) return false;
            records.push_back(address);
        } else *found = address;
        if ((address.flags & (IFA_F_TENTATIVE | IFA_F_DADFAILED)) == 0 && address.validLifetime != 0)
            dhcpIpv6Info.IpAddrMap[address.address] = static_cast<int>(AddrType::GLOBAL);
        else dhcpIpv6Info.IpAddrMap.erase(address.address);
    }
    dhcpIpv6Info.l3Ipv6 = true;
    return true;
}

void DhcpIpv6Client::NotifyRaFlagsChanged(bool managed, bool other)
{
    // flags bit layout: bit0=M(Managed), bit1=O(Other)
    // 0x00: M=0,O=0 (SLAAC only)
    // 0x01: M=1,O=0 (DHCPv6 stateful)
    // 0x02: M=0,O=1 (DHCPv6 stateless)
    // 0x03: M=1,O=1 (DHCPv6 stateful, O is meaningless when M=1)
    uint8_t flags = (managed ? RA_FLAG_MANAGED_MASK : 0) | (other ? RA_FLAG_OTHER_MASK : 0);

    std::string ifname;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        ifname = interfaceName;
    }
    if (ifname.empty() || !onRaFlagsChanged_) {
        // No callback, still store the flags
        raFlags_.store(flags);
        return;
    }
    // Copy callback under lock, then release lock before calling
    decltype(onRaFlagsChanged_) callback;
    {
        std::lock_guard<std::mutex> lock(ipv6CallbackMutex_);
        callback = onRaFlagsChanged_;
    }
    if (callback) {
        callback(ifname, managed, other);
    }
    // Store RA flags after callback completes
    raFlags_.store(flags);
}

#ifndef IFLA_INET6_FLAGS
#define IFLA_INET6_FLAGS 1
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif
// RA flag bits in the high byte of IFLA_INET6_FLAGS (big-endian network order)
#ifndef ND_RA_FLAG_MANAGED
#define ND_RA_FLAG_MANAGED 0x80  // M flag - DHCPv6 should be used
#endif
#ifndef ND_RA_FLAG_OTHER
#define ND_RA_FLAG_OTHER 0x40  // O flag - Other config via DHCPv6
#endif
// Byte shift for extracting high byte from uint32_t (big-endian network order)
#ifndef BYTE_SHIFT_24
#define BYTE_SHIFT_24 24
#endif
#ifndef BYTE_MASK
#define BYTE_MASK 0xFF
#endif

void DhcpIpv6Client::ParseAfSpecAttributes(struct rtattr *afRta, int afLen, unsigned int ifIndex)
{
    DHCP_LOGI("ParseAfSpecAttributes: afLen %{public}d, ifIndex %{public}u", afLen, ifIndex);
    for (; RTA_OK(afRta, afLen); afRta = RTA_NEXT(afRta, afLen)) {
        if (afRta->rta_type != AF_INET6) {
            continue;
        }
        int innerLen = RTA_PAYLOAD(afRta);
        struct rtattr *innerRta = static_cast<struct rtattr *>(RTA_DATA(afRta));
        for (; RTA_OK(innerRta, innerLen); innerRta = RTA_NEXT(innerRta, innerLen)) {
            if (innerRta->rta_type != IFLA_INET6_FLAGS) {
                continue;
            }
            if (RTA_PAYLOAD(innerRta) < sizeof(uint32_t)) {
                DHCP_LOGE("ParseAfSpecAttributes: IFLA_INET6_FLAGS payload too small");
                continue;
            }
            uint32_t flags = *static_cast<uint32_t *>(RTA_DATA(innerRta));
            // IFLA_INET6_FLAGS is a single byte, extract low byte for M/O bits
            uint8_t flagByte = flags & BYTE_MASK;
            bool other = (flagByte & ND_RA_FLAG_MANAGED) != 0;
            bool managed = (flagByte & ND_RA_FLAG_OTHER) != 0;
            DHCP_LOGI("ParseAfSpecAttributes: flags=0x%{public}x, flagByte=0x%{public}x, "
                "managed=%{public}d, other=%{public}d", flags, flagByte, managed, other);
            NotifyRaFlagsChanged(managed, other);
        }
    }
}

void DhcpIpv6Client::ParseLinkMessage(void *msg)
{
    if (msg == nullptr) {
        DHCP_LOGE("ParseLinkMessage msg nullptr.");
        return;
    }
    struct nlmsghdr *hdrMsg = static_cast<struct nlmsghdr *>(msg);
    if (hdrMsg->nlmsg_len < NLMSG_LENGTH(sizeof(struct ifinfomsg))) {
        DHCP_LOGE("ParseLinkMessage nlmsg_len:%{public}u is invalid.", hdrMsg->nlmsg_len);
        return;
    }

    struct ifinfomsg *ifi = static_cast<struct ifinfomsg *>(NLMSG_DATA(hdrMsg));
    if (ifi->ifi_family != AF_UNSPEC && ifi->ifi_family != AF_INET6) {
        DHCP_LOGI("ParseLinkMessage: skip family %{public}d (not AF_UNSPEC/AF_INET6)", ifi->ifi_family);
        return;
    }

    unsigned int ifIndex = static_cast<unsigned int>(ifi->ifi_index);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (interfaceName.empty()) {
            return;
        }
        unsigned int myIfIndex = if_nametoindex(interfaceName.c_str());
        if (myIfIndex == 0 || ifIndex != myIfIndex) {
            return;
        }
    }

    if (!(ifi->ifi_flags & IFF_RUNNING) || !(ifi->ifi_flags & IFF_UP)) {
        DHCP_LOGI("ParseLinkMessage: interface not running/up (flags=0x%{public}x), skip RA flags", ifi->ifi_flags);
        return;
    }

    unsigned int len = hdrMsg->nlmsg_len - NLMSG_ALIGN(sizeof(struct nlmsghdr));
    if (len < sizeof(struct ifinfomsg)) {
        DHCP_LOGE("ParseLinkMessage: invalid payload length %{public}u", len);
        return;
    }
    len -= sizeof(struct ifinfomsg);

    struct rtattr *rta = IFLA_RTA(ifi);
    bool foundAfSpec = false;
    for (; RTA_OK(rta, static_cast<int>(len)); rta = RTA_NEXT(rta, len)) {
        if (rta->rta_type == IFLA_AF_SPEC) {
            foundAfSpec = true;
            int afLen = RTA_PAYLOAD(rta);
            struct rtattr *afRta = static_cast<struct rtattr *>(RTA_DATA(rta));
            ParseAfSpecAttributes(afRta, afLen, ifIndex);
        }
    }
    if (!foundAfSpec) {
        DHCP_LOGI("ParseLinkMessage: IFLA_AF_SPEC not found in message");
    }
}

void DhcpIpv6Client::QueryInterfaceRaFlags()
{
    if (!raReceived_.load()) {
        return;
    }
    std::string ifname;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        ifname = interfaceName;
    }
    if (ifname.empty()) {
        DHCP_LOGE("QueryInterfaceRaFlags: interface name is empty");
        return;
    }

    unsigned int ifIndex = if_nametoindex(ifname.c_str());
    if (ifIndex == 0) {
        DHCP_LOGE("QueryInterfaceRaFlags: if_nametoindex failed for %{public}s", ifname.c_str());
        return;
    }

    std::vector<uint8_t> response;
    if (!BuildAndSendNetlinkRequest(ifIndex, response)) {
        DHCP_LOGE("QueryInterfaceRaFlags: BuildAndSendNetlinkRequest failed");
        return;
    }

    // Parse response to find RA flags
    int len = static_cast<int>(response.size());
    for (struct nlmsghdr* nlh = reinterpret_cast<struct nlmsghdr*>(response.data());
        NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
        if (nlh->nlmsg_type == NLMSG_DONE || nlh->nlmsg_type != RTM_NEWLINK) {
            break;
        }
        struct ifinfomsg* ifm = reinterpret_cast<struct ifinfomsg*>(NLMSG_DATA(nlh));
        if (static_cast<unsigned int>(ifm->ifi_index) != ifIndex) {
            continue;
        }
        if (!(ifm->ifi_flags & IFF_RUNNING) || !(ifm->ifi_flags & IFF_UP)) {
            DHCP_LOGI("QueryInterfaceRaFlags: interface not running/up, skip RA flags");
            return;
        }
        int remaining = static_cast<int>(RTM_PAYLOAD(nlh));
        for (struct rtattr* rta = IFLA_RTA(ifm); RTA_OK(rta, remaining);
             rta = RTA_NEXT(rta, remaining)) {
            if (rta->rta_type == IFLA_AF_SPEC) {
                int afLen = RTA_PAYLOAD(rta);
                struct rtattr* afRta = reinterpret_cast<struct rtattr*>(RTA_DATA(rta));
                ParseAfSpecAttributes(afRta, afLen, ifIndex);
                return;
            }
        }
    }
    DHCP_LOGI("QueryInterfaceRaFlags: IFLA_AF_SPEC not found in query response");
}

bool DhcpIpv6Client::BuildAndSendNetlinkRequest(unsigned int ifIndex, std::vector<uint8_t>& response)
{
    struct {
        struct nlmsghdr nlh;
        struct ifinfomsg ifm;
    } request = {};
    request.nlh.nlmsg_len = static_cast<unsigned int>(NLMSG_LENGTH(sizeof(struct ifinfomsg)));
    request.nlh.nlmsg_type = RTM_GETLINK;
    request.nlh.nlmsg_flags = NLM_F_REQUEST;
    request.nlh.nlmsg_seq = 1;
    request.ifm.ifi_family = AF_UNSPEC;
    request.ifm.ifi_index = static_cast<int>(ifIndex);

    int sockFd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sockFd < 0) {
        DHCP_LOGE("BuildAndSendNetlinkRequest: socket failed");
        return false;
    }

    struct sockaddr_nl addr = { .nl_family = AF_NETLINK, .nl_pid = 0, .nl_groups = 0 };
    if (sendto(sockFd, &request, request.nlh.nlmsg_len, 0,
        reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        DHCP_LOGE("BuildAndSendNetlinkRequest: sendto failed");
        close(sockFd);
        return false;
    }

    response.resize(NETLINK_RECV_BUFFER_SIZE);
    int len = recv(sockFd, response.data(), response.size(), 0);
    close(sockFd);
    if (len < 0) {
        DHCP_LOGE("BuildAndSendNetlinkRequest: recv failed");
        return false;
    }
    response.resize(len);
    return true;
}

void DhcpIpv6Client::StartRaFlagsQueryTimer()
{
    if (!raFlagsQueried_) {
        raFlagsQueried_ = true;
        std::thread([this]() {
            std::this_thread::sleep_for(std::chrono::seconds(WAIT_RA_DELAY));
            DHCP_LOGI("StartRaFlagsQueryTimer: querying RA flags");
            QueryInterfaceRaFlags();
        }).detach();
    }
}
}  // namespace DHCP
}  // namespace OHOS
