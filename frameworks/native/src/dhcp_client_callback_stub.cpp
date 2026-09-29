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
#include "dhcp_client_callback_stub.h"
#include "dhcp_manager_service_ipc_interface_code.h"
#include "dhcp_logger.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpClientCallBackStub");
namespace OHOS {
namespace DHCP {
DhcpClientCallBackStub::DhcpClientCallBackStub() : callback_(nullptr), mRemoteDied_(false)
{
    DHCP_LOGD("Enter DhcpClientCallBackStub");
}

DhcpClientCallBackStub::~DhcpClientCallBackStub()
{
    DHCP_LOGD("Enter ~DhcpClientCallBackStub");
}

int DhcpClientCallBackStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    DHCP_LOGI("OnRemoteRequest, code:%{public}d", code);
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        DHCP_LOGE("Sta callback stub token verification error: %{public}d", code);
        return DHCP_E_FAILED;
    }
    int exception = data.ReadInt32();
    if (exception) {
        DHCP_LOGE("OnRemoteRequest, got exception: %{public}d!", exception);
        return DHCP_E_FAILED;
    }
    int ret = -1;
    switch (code) {
        case static_cast<uint32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_CBK_CMD_IP_SUCCESS_CHANGE): {
            ret = RemoteOnIpSuccessChanged(code, data, reply);
            break;
        }
        case static_cast<uint32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_CBK_CMD_IP_FAIL_CHANGE): {
            ret = RemoteOnIpFailChanged(code, data, reply);
            break;
        }
        case static_cast<uint32_t>(DhcpClientInterfaceCode::DHCP_CLIENT_CBK_CMD_DHCP_OFFER): {
            ret = RemoteOnDhcpOfferReport(code, data, reply);
            break;
        }
        default: {
            ret = IPCObjectStub::OnRemoteRequest(code, data, reply, option);
            break;
        }
    }
    DHCP_LOGI("OnRemoteRequest, ret:%{public}d", ret);
    return ret;
}

void DhcpClientCallBackStub::RegisterCallBack(const sptr<IDhcpClientCallBack> &callBack)
{
    std::unique_lock<std::mutex> lock(callbackMutex_);
    if (callBack == nullptr) {
        DHCP_LOGE("callBack is nullptr!");
        return;
    }
    callback_ = callBack;
}

bool DhcpClientCallBackStub::IsRemoteDied() const
{
    return mRemoteDied_.load();
}

void DhcpClientCallBackStub::SetRemoteDied(bool val)
{
    DHCP_LOGI("SetRemoteDied, state:%{public}d!", val);
    mRemoteDied_.store(val);
}

void DhcpClientCallBackStub::OnIpSuccessChanged(int status, const std::string& ifname, DhcpResult& result)
{
    DHCP_LOGI("[DHCP][CallbackStub] success callback received, ifname:%{public}s status:%{public}d",
        ifname.c_str(), status);
    sptr<IDhcpClientCallBack> tempCallback;
    {
        std::unique_lock<std::mutex> lock(callbackMutex_);
        tempCallback = callback_;
    }
    if (tempCallback) {
        tempCallback->OnIpSuccessChanged(status, ifname, result);
        DHCP_LOGI("[DHCP][CallbackStub] success callback dispatched, ifname:%{public}s", ifname.c_str());
    } else {
        DHCP_LOGE("[DHCP][CallbackStub] success callback dropped: target is null, ifname:%{public}s", ifname.c_str());
    }
}

void DhcpClientCallBackStub::OnIpFailChanged(int status, const std::string& ifname, const std::string& reason)
{
    DHCP_LOGI("[DHCP][CallbackStub] failure callback received, ifname:%{public}s status:%{public}d",
        ifname.c_str(), status);
    sptr<IDhcpClientCallBack> tempCallback;
    {
        std::unique_lock<std::mutex> lock(callbackMutex_);
        tempCallback = callback_;
    }
    if (tempCallback) {
        tempCallback->OnIpFailChanged(status, ifname, reason);
        DHCP_LOGI("[DHCP][CallbackStub] failure callback dispatched, ifname:%{public}s", ifname.c_str());
    } else {
        DHCP_LOGE("[DHCP][CallbackStub] failure callback dropped: target is null, ifname:%{public}s", ifname.c_str());
    }
}

void DhcpClientCallBackStub::OnDhcpOfferReport(int status, const std::string& ifname, DhcpResult& result)
{
    DHCP_LOGI("OnDhcpOfferReport, status:%{public}d!", status);
    sptr<IDhcpClientCallBack> tempCallback;
    {
        std::unique_lock<std::mutex> lock(callbackMutex_);
        tempCallback = callback_;
    }
    if (tempCallback) {
        tempCallback->OnDhcpOfferReport(status, ifname, result);
    }
}

int DhcpClientCallBackStub::RemoteOnIpSuccessChanged(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    DHCP_LOGI("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int state = data.ReadInt32();
    std::string ifname = data.ReadString();
    DhcpResult result = DeserializeDhcpResult(data);
    if (result.iptype != 0 && result.iptype != 1) return -1;
    OnIpSuccessChanged(state, ifname, result);
    reply.WriteInt32(0);
    return 0;
}

DhcpResult DhcpClientCallBackStub::DeserializeDhcpResult(MessageParcel &data)
{
    DhcpResult result;
    if (!data.ReadInt32(result.iptype) || !data.ReadBool(result.isOptSuc) ||
        !data.ReadUint32(result.uLeaseTime) || !data.ReadUint32(result.uAddTime) ||
        !data.ReadUint32(result.uGetTime)) return DhcpResult{};
    if (!data.ReadString(result.strYourCli)) return DhcpResult{};
    if (!data.ReadString(result.strServer)) return DhcpResult{};
    if (!data.ReadString(result.strSubnet)) return DhcpResult{};
    if (!data.ReadString(result.strDns1)) return DhcpResult{};
    if (!data.ReadString(result.strDns2)) return DhcpResult{};
    if (!data.ReadString(result.strRouter1)) return DhcpResult{};
    if (!data.ReadString(result.strRouter2)) return DhcpResult{};
    if (!data.ReadString(result.strVendor)) return DhcpResult{};
    if (!data.ReadString(result.strLinkIpv6Addr)) return DhcpResult{};
    if (!data.ReadString(result.strRandIpv6Addr)) return DhcpResult{};
    if (!data.ReadString(result.strLocalAddr1)) return DhcpResult{};
    if (!data.ReadString(result.strLocalAddr2)) return DhcpResult{};
    if (!data.ReadUint8(result.raFlags)) return DhcpResult{};
    int32_t size = 0;
    if (!data.ReadInt32(size) || size < 0 || size > DHCP_MAX_DNS_SIZE) return DhcpResult{};
    for (int32_t i = 0; i < size; ++i) {
        std::string value;
        if (!data.ReadString(value)) return DhcpResult{};
        if (!value.empty()) result.vectorDnsAddr.push_back(value);
    }
    int32_t addrCnt = 0;
    if (!data.ReadInt32(addrCnt) || addrCnt < 0 || addrCnt > DHCP_MAX_ADDR_SIZE) return DhcpResult{};
    for (int32_t i = 0; i < addrCnt; ++i) {
        std::string address; int32_t type = 0;
        if (!data.ReadString(address) || !data.ReadInt32(type)) return DhcpResult{};
        if (!address.empty()) result.IpAddrMap[address] = type;
    }
    if (data.GetReadableBytes() != 0) {
        uint32_t count = 0;
        if (!data.ReadBool(result.l3Ipv6) || !result.l3Ipv6 || !data.ReadUint32(count) || count > 8)
            return DhcpResult{};
        for (uint32_t i = 0; i < count; ++i) {
            L3Ipv6Address a;
            if (!data.ReadString(a.address) || a.address.empty() || a.address.size() > 45 ||
                !data.ReadUint32(a.ifindex) || a.ifindex == 0 || !data.ReadUint32(a.prefixLength) || a.prefixLength > 128 ||
                !data.ReadUint32(a.flags) || !data.ReadUint32(a.preferredLifetime) || !data.ReadUint32(a.validLifetime) ||
                a.preferredLifetime > a.validLifetime) return DhcpResult{};
            result.l3Addresses.push_back(a);
        }
        if (data.GetReadableBytes() != 0) return DhcpResult{};
    }
    return result;
}

int DhcpClientCallBackStub::RemoteOnIpFailChanged(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    DHCP_LOGI("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int state = data.ReadInt32();
    std::string ifname = data.ReadString();
    std::string reason = data.ReadString();
    OnIpFailChanged(state, ifname, reason);
    reply.WriteInt32(0);
    return 0;
}

int DhcpClientCallBackStub::RemoteOnDhcpOfferReport(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    DHCP_LOGI("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int state = data.ReadInt32();
    std::string ifname = data.ReadString();
    DhcpResult result = DeserializeDhcpResult(data);
    if (result.iptype != 0 && result.iptype != 1) return -1;
    OnDhcpOfferReport(state, ifname, result);
    reply.WriteInt32(0);
    return 0;
}
}  // namespace DHCP
}  // namespace OHOS
