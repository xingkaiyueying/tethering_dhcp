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
#include "dhcp_client_stub_lite.h"
#include "dhcp_client_callback_proxy.h"
#include "dhcp_manager_service_ipc_interface_code.h"
#include "dhcp_sdk_define.h"
#ifndef  OHOS_EUPDATER
#include "ipc_skeleton.h"
#include "rpc_errno.h"
#endif
#include "dhcp_client_state_machine.h"
#include "dhcp_logger.h"
#include "dhcp_errcode.h"

#ifndef OHOS_EUPDATER
DEFINE_DHCPLOG_DHCP_LABEL("DhcpClientStub");
#endif
namespace OHOS {
namespace DHCP {
DhcpClientStub::DhcpClientStub()
{
#ifndef OHOS_EUPDATER
    InitHandleMap();
#endif
}

DhcpClientStub::~DhcpClientStub()
{}

#ifndef OHOS_EUPDATER
void DhcpClientStub::InitHandleMap()
{
    handleFuncMap[static_cast<uint32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_SVR_CMD_REG_CALL_BACK)] = &DhcpClientStub::OnRegisterCallBack;
    handleFuncMap[static_cast<uint32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_SVR_CMD_START_DHCP_CLIENT)] = &DhcpClientStub::OnStartDhcpClient;
    handleFuncMap[static_cast<uint32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_SVR_CMD_STOP_DHCP_CLIENT)] = &DhcpClientStub::OnStopDhcpClient;
    handleFuncMap[static_cast<uint32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_SVR_CMD_DEAL_DHCP_CACHE)] =
        &DhcpClientStub::OnDealWifiDhcpCache;
}

int DhcpClientStub::OnRemoteRequest(uint32_t code, IpcIo *req, IpcIo *reply)
{
    DHCP_LOGI("run: %{public}s code: %{public}u L1", __func__, code);
    if (req == nullptr || reply == nullptr) {
        DHCP_LOGD("req:%{public}d, reply:%{public}d", req == nullptr, reply == nullptr);
        return DHCP_OPT_FAILED;
    }

    DHCP_LOGI("run ReadInterfaceToken L1 code %{public}u", code);
    size_t length;
    uint16_t* interfaceRead = nullptr;
    interfaceRead = ReadInterfaceToken(req, &length);
    for (size_t i = 0; i < length; i++) {
        if (i >= DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH || interfaceRead[i] != DECLARE_INTERFACE_DESCRIPTOR_L1[i]) {
            DHCP_LOGE("Sta stub token verification error: %{public}d", code);
            return DHCP_OPT_FAILED;
        }
    }

    int exception = 0;
    (void)ReadInt32(req, &exception);
    if (exception) {
        (void)WriteInt32(reply, 0);
        (void)WriteInt32(reply, DHCP_OPT_NOT_SUPPORTED);
        return DHCP_OPT_FAILED;
    }

    HandleFuncMap::iterator iter = handleFuncMap.find(code);
    if (iter == handleFuncMap.end()) {
        DHCP_LOGE("not find function to deal, code %{public}u", code);
        (void)WriteInt32(reply, 0);
        (void)WriteInt32(reply, DHCP_OPT_NOT_SUPPORTED);
    } else {
        (this->*(iter->second))(code, req, reply);
    }
    return DHCP_OPT_SUCCESS;
}

int DhcpClientStub::OnRegisterCallBack(uint32_t code, IpcIo *req, IpcIo *reply)
{
    DHCP_LOGI("run %{public}s code %{public}u", __func__, code);
    ErrCode ret = DHCP_E_FAILED;
    SvcIdentity sid;
    bool readSid = ReadRemoteObject(req, &sid);
    if (!readSid) {
        DHCP_LOGE("read SvcIdentity failed");
        (void)WriteInt32(reply, 0);
        (void)WriteInt32(reply, ret);
        return DHCP_OPT_FAILED;
    }

    std::shared_ptr<IDhcpClientCallBack> callback_ = std::make_shared<DhcpClientCallbackProxy>(&sid);
    DHCP_LOGI("create new DhcpClientCallbackProxy!");

    size_t readLen;
    const char* rawIfname = (char *)ReadString(req, &readLen);
    if (rawIfname == nullptr) {
        DHCP_LOGE("OnRegisterCallBack ReadString ifname failed");
        return DHCP_OPT_FAILED;
    }
    std::string ifname(rawIfname);
    DHCP_LOGI("ifname:%{public}s", ifname.c_str());

    ret = RegisterDhcpClientCallBack(ifname, callback_);
    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);
    return DHCP_OPT_SUCCESS;
}

int DhcpClientStub::OnStartDhcpClient(uint32_t code, IpcIo *req, IpcIo *reply)
{
    DHCP_LOGI("run %{public}s code %{public}u", __func__, code);
    ErrCode ret = DHCP_E_FAILED;
    SvcIdentity sid;
    bool readSid = ReadRemoteObject(req, &sid);
    if (!readSid) {
        DHCP_LOGE("read SvcIdentity failed");
        (void)WriteInt32(reply, 0);
        (void)WriteInt32(reply, ret);
        return DHCP_OPT_FAILED;
    }

    size_t readLen;
    RouterConfig config;
    bool bIpv6;
    std::string ifname = (char *)ReadString(req, &readLen);
    std::string bssid = (char *)ReadString(req, &readLen);
    (void)ReadBool(req, &config.prohibitUseCacheIp);
    (void)ReadBool(req, &config.bIpv6);
    (void)ReadBool(req, &config.bSpecificNetwork);
    (void)ReadBool(req, &config.isStaticIpv4);
    (void)ReadBool(req, &config.bIpv4);
    int32_t linkMode = 0;
    int32_t clientKeyLen = 0;
    if (!ReadInt32(req, &linkMode) || !ReadInt32(req, &clientKeyLen) ||
        linkMode < 0 || linkMode > static_cast<int32_t>(DhcpLinkMode::L3_TUN) ||
        clientKeyLen != static_cast<int32_t>(config.clientKey.size())) {
        (void)WriteInt32(reply, 0);
        (void)WriteInt32(reply, DHCP_E_INVALID_PARAM);
        return DHCP_OPT_FAILED;
    }
    config.linkMode = static_cast<DhcpLinkMode>(linkMode);
    for (uint8_t &value : config.clientKey) {
        int32_t item = 0;
        if (!ReadInt32(req, &item) || item < 0 || item > 0xFF) {
            (void)WriteInt32(reply, 0);
            (void)WriteInt32(reply, DHCP_E_INVALID_PARAM);
            return DHCP_OPT_FAILED;
        }
        value = static_cast<uint8_t>(item);
    }
    DHCP_LOGI("ifname:%{public}s prohibitUseCacheIp:%{public}d, bIpv6:%{public}d, bSpecificNetwork:%{public}d",
        ifname.c_str(), config.prohibitUseCacheIp, config.bIpv6, config.bSpecificNetwork);

    config.ifname = ifname;
    config.bssid = bssid;
    ret = StartDhcpClient(config);
    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);
    return DHCP_OPT_SUCCESS;
}

int DhcpClientStub::OnStopDhcpClient(uint32_t code, IpcIo *req, IpcIo *reply)
{
    DHCP_LOGI("run %{public}s code %{public}u", __func__, code);
    ErrCode ret = DHCP_E_FAILED;
    SvcIdentity sid;
    bool readSid = ReadRemoteObject(req, &sid);
    if (!readSid) {
        DHCP_LOGE("read SvcIdentity failed");
        (void)WriteInt32(reply, 0);
        (void)WriteInt32(reply, ret);
        return DHCP_OPT_FAILED;
    }

    size_t readLen;
    bool bIpv6;
    const char* rawIfname = (char *)ReadString(req, &readLen);
    if (rawIfname == nullptr) {
        DHCP_LOGE("OnStopDhcpClient ReadString ifname failed");
        return DHCP_OPT_FAILED;
    }
    std::string ifname(rawIfname);
    (void)ReadBool(req, &bIpv6);
    bool bIpv4 = true;
    (void)ReadBool(req, &bIpv4);
    DHCP_LOGI("ifname:%{public}s bIpv6:%{public}d bIpv4:%{public}d", ifname.c_str(), bIpv6, bIpv4);

    ret = StopDhcpClient(ifname, bIpv6, bIpv4);
    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);
    return 0;
}

int DhcpClientStub::OnDealWifiDhcpCache(uint32_t code, IpcIo *req, IpcIo *reply)
{
    DHCP_LOGI("run %{public}s code %{public}u", __func__, code);
    ErrCode ret = DHCP_E_FAILED;
    SvcIdentity sid;
    bool readSid = ReadRemoteObject(req, &sid);
    if (!readSid) {
        DHCP_LOGE("read SvcIdentity failed");
        (void)WriteInt32(reply, 0);
        (void)WriteInt32(reply, ret);
        return DHCP_OPT_FAILED;
    }
    int32_t cmd = 0;
    (void)ReadInt32(req, &cmd);
    size_t readLen;
    IpCacheInfo ipCacheInfo;
    ipCacheInfo.ssid = (char *)ReadString(req, &readLen);
    ipCacheInfo.bssid = (char *)ReadString(req, &readLen);
    ret = DealWifiDhcpCache(cmd, ipCacheInfo);
    (void)WriteInt32(reply, 0);
    (void)WriteInt32(reply, ret);
    return 0;
}
#endif
}
}
