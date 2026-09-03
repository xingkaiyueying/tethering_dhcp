/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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
#include "dhcp_client_proxy.h"
#include "dhcp_manager_service_ipc_interface_code.h"
#include "dhcp_client_callback_stub_lite.h"
#include "dhcp_c_utils.h"
#include "dhcp_errcode.h"
#include "dhcp_logger.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpClientProxyLite");

namespace OHOS {
namespace DHCP {
static SvcIdentity g_sid;
static IpcObjectStub g_objStub;
static DhcpClientCallBackStub g_dhcpClientCallBackStub;

DhcpClientProxy *DhcpClientProxy::g_instance = nullptr;
DhcpClientProxy::DhcpClientProxy() : remoteDied_(false)
{
    DHCP_LOGI("enter ~DhcpClientProxy!");
}

DhcpClientProxy::~DhcpClientProxy()
{
    DHCP_LOGI("enter ~DhcpClientProxy!");
}

DhcpClientProxy *DhcpClientProxy::GetInstance(void)
{
    if (g_instance != nullptr) {
        return g_instance;
    }

    DhcpClientProxy *tempInstance = new DhcpClientProxy();
    g_instance = tempInstance;
    return g_instance;
}

void DhcpClientProxy::ReleaseInstance(void)
{
    if (g_instance != nullptr) {
        delete g_instance;
        g_instance = nullptr;
    }
}

static int IpcCallback(void *owner, int code, IpcIo *reply)
{
    if (code != 0 || owner == nullptr || reply == nullptr) {
        DHCP_LOGE("Callback error, code:%{public}d, owner:%{public}d, reply:%{public}d",
            code, owner == nullptr, reply == nullptr);
        return ERR_FAILED;
    }

    struct IpcOwner *data = (struct IpcOwner *)owner;
    (void)ReadInt32(reply, &data->exception);
    (void)ReadInt32(reply, &data->retCode);
    if (data->exception != 0 || data->retCode != DHCP_OPT_SUCCESS || data->variable == nullptr) {
        return ERR_FAILED;
    }
    return ERR_NONE;
}

static int AsyncCallback(uint32_t code, IpcIo *data, IpcIo *reply, MessageOption option)
{
    if (data == nullptr) {
        DHCP_LOGE("AsyncCallback error, data is null");
        return DHCP_E_FAILED;
    }
    return g_dhcpClientCallBackStub.OnRemoteRequest(code, data);
}

ErrCode DhcpClientProxy::RegisterDhcpClientCallBack(const std::string& ifname,
    const std::shared_ptr<IDhcpClientCallBack> &callback)
{
    if (remoteDied_ || remote_ == nullptr) {
        DHCP_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return DHCP_OPT_FAILED;
    }
    g_objStub.func = AsyncCallback;
    g_objStub.args = nullptr;
    g_objStub.isRemote = false;

    g_sid.handle = IPC_INVALID_HANDLE;
    g_sid.token = SERVICE_TYPE_ANONYMOUS;
    g_sid.cookie = reinterpret_cast<uintptr_t>(&g_objStub);

    IpcIo req;
    char data[IPC_DATA_SIZE_SMALL];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&req, data, IPC_DATA_SIZE_SMALL, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&req, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        DHCP_LOGE("Write interface token error: %{public}s", __func__);
        return DHCP_OPT_FAILED;
    }
    (void)WriteInt32(&req, 0);
    bool writeRemote = WriteRemoteObject(&req, &g_sid);
    if (!writeRemote) {
        DHCP_LOGE("WriteRemoteObject failed.");
        return DHCP_OPT_FAILED;
    }

    (void)WriteString(&req, ifname.c_str());
    owner.funcId = static_cast<int32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_SVR_CMD_REG_CALL_BACK);
    int error = remote_->Invoke(remote_,
        static_cast<int32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_SVR_CMD_REG_CALL_BACK),
        &req, &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        DHCP_LOGE("Set Attr(%{public}d) failed, code is %{public}d",
            static_cast<int32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_SVR_CMD_REG_CALL_BACK), error);
        return DHCP_E_FAILED;
    }
    if (owner.exception) {
        DHCP_LOGE("exception failed, exception:%{public}d", owner.exception);
        return DHCP_E_FAILED;
    }
    g_dhcpClientCallBackStub.RegisterCallBack(callback);
    DHCP_LOGI("RegisterDhcpClientCallBack ok, exception:%{public}d", owner.exception);
    return DHCP_E_SUCCESS;
}

ErrCode DhcpClientProxy::StartDhcpClient(const RouterConfig &config)
{
    if (remoteDied_ || remote_ == nullptr) {
        DHCP_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return DHCP_OPT_FAILED;
    }

    IpcIo req;
    char data[IPC_DATA_SIZE_SMALL];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&req, data, IPC_DATA_SIZE_SMALL, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&req, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        DHCP_LOGE("Write interface token error: %{public}s", __func__);
        return DHCP_OPT_FAILED;
    }

    (void)WriteInt32(&req, 0);
    (void)WriteString(&req, config.ifname.c_str());
    (void)WriteString(&req, config.bssid.c_str());
    (void)WriteBool(&req, config.prohibitUseCacheIp);
    (void)WriteBool(&req, config.bIpv6);
    (void)WriteBool(&req, config.bSpecificNetwork);
    (void)WriteBool(&req, config.isStaticIpv4);
    (void)WriteBool(&req, config.bIpv4);
    (void)WriteInt32(&req, static_cast<int32_t>(config.linkMode));
    (void)WriteInt32(&req, static_cast<int32_t>(config.clientKey.size()));
    for (uint8_t value : config.clientKey) {
        (void)WriteInt32(&req, value);
    }
    owner.funcId = static_cast<int32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_SVR_CMD_START_DHCP_CLIENT);
    int error = remote_->Invoke(remote_,
        static_cast<int32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_SVR_CMD_START_DHCP_CLIENT), &req,
        &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        DHCP_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_SVR_CMD_START_DHCP_CLIENT), error);
        return DHCP_E_FAILED;
    }
    if (owner.exception) {
        DHCP_LOGE("exception failed, exception:%{public}d", owner.exception);
        return DHCP_E_FAILED;
    }
    DHCP_LOGI("StartDhcpClient completed, ret:%{public}d", owner.retCode);
    return owner.retCode;
}

ErrCode DhcpClientProxy::DealWifiDhcpCache(int32_t cmd, const IpCacheInfo &ipCacheInfo)
{
    if (remoteDied_ || remote_ == nullptr) {
        DHCP_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return DHCP_OPT_FAILED;
    }

    IpcIo req;
    char data[IPC_DATA_SIZE_SMALL];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&req, data, IPC_DATA_SIZE_SMALL, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&req, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        DHCP_LOGE("Write interface token error: %{public}s", __func__);
        return DHCP_OPT_FAILED;
    }

    (void)WriteInt32(&req, 0);
    (void)WriteInt32(&req, cmd);
    (void)WriteString(&req, ipCacheInfo.ssid.c_str());
    (void)WriteString(&req, ipCacheInfo.bssid.c_str());
    owner.funcId = static_cast<int32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_SVR_CMD_DEAL_DHCP_CACHE);
    int error = remote_->Invoke(remote_,
        static_cast<int32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_SVR_CMD_DEAL_DHCP_CACHE), &req,
        &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        DHCP_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_SVR_CMD_DEAL_DHCP_CACHE), error);
        return DHCP_E_FAILED;
    }
    if (owner.exception) {
        DHCP_LOGE("exception failed, exception:%{public}d", owner.exception);
        return DHCP_E_FAILED;
    }
    DHCP_LOGI("DealWifiDhcpCache ok, exception:%{public}d", owner.exception);
    return DHCP_E_SUCCESS;
}

ErrCode DhcpClientProxy::StopDhcpClient(const std::string& ifname, bool bIpv6, bool bIpv4)
{
    if (remoteDied_ || remote_ == nullptr) {
        DHCP_LOGE("failed to %{public}s, remoteDied_: %{public}d, remote_: %{public}d",
            __func__, remoteDied_, remote_ == nullptr);
        return DHCP_OPT_FAILED;
    }
    IpcIo req;
    char data[IPC_DATA_SIZE_SMALL];
    struct IpcOwner owner = {.exception = -1, .retCode = 0, .variable = nullptr};

    IpcIoInit(&req, data, IPC_DATA_SIZE_SMALL, MAX_IPC_OBJ_COUNT);
    if (!WriteInterfaceToken(&req, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        DHCP_LOGE("Write interface token error: %{public}s", __func__);
        return DHCP_OPT_FAILED;
    }

    (void)WriteInt32(&req, 0);
    (void)WriteString(&req, ifname.c_str());
    (void)WriteBool(&req, bIpv6);
    (void)WriteBool(&req, bIpv4);
    owner.funcId = static_cast<int32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_SVR_CMD_STOP_DHCP_CLIENT);
    int error = remote_->Invoke(remote_,
        static_cast<int32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_SVR_CMD_STOP_DHCP_CLIENT), &req,
        &owner, IpcCallback);
    if (error != EC_SUCCESS) {
        DHCP_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_SVR_CMD_STOP_DHCP_CLIENT), error);
        return DHCP_E_FAILED;
    }
    
    if (owner.exception) {
        DHCP_LOGE("exception failed, exception:%{public}d", owner.exception);
        return DHCP_E_FAILED;
    }
    DHCP_LOGI("StopDhcpClient ok, exception:%{public}d", owner.exception);
    return DHCP_E_SUCCESS;
}
}  // namespace DHCP
}  // namespace OHOS
