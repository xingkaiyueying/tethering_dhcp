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
#include "dhcp_server_proxy.h"
#include "dhcp_manager_service_ipc_interface_code.h"
#include "dhcp_server_callback_stub.h"
#include "dhcp_c_utils.h"
#include "dhcp_errcode.h"
#include "dhcp_logger.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpServerProxy");

namespace OHOS {
namespace DHCP {
constexpr int MAX_SIZE = 512;

static sptr<DhcpServreCallBackStub> g_dhcpServerCallBackStub =
    sptr<DhcpServreCallBackStub>(new (std::nothrow)DhcpServreCallBackStub());

DhcpServerProxy::DhcpServerProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<IDhcpServer>(impl),
    remote_(nullptr), mRemoteDied(false), deathRecipient_(nullptr)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (impl) {
        if (!impl->IsProxyObject()) {
            DHCP_LOGW("not proxy object!");
            return;
        }
        deathRecipient_ = new (std::nothrow)DhcpServerDeathRecipient(*this);
        if (deathRecipient_ == nullptr) {
            DHCP_LOGW("deathRecipient_ is nullptr!");
            return;
        }
        if (!impl->AddDeathRecipient(deathRecipient_)) {
            DHCP_LOGW("AddDeathRecipient failed!");
            return;
        }
        remote_ = impl;
        DHCP_LOGI("AddDeathRecipient success! ");
    }
}

DhcpServerProxy::~DhcpServerProxy()
{
    DHCP_LOGI("enter ~DhcpServerProxy!");
    RemoveDeathRecipient();
}

void DhcpServerProxy::RemoveDeathRecipient(void)
{
    DHCP_LOGI("enter RemoveDeathRecipient!");
    std::lock_guard<std::mutex> lock(mutex_);
    if (remote_ == nullptr) {
        DHCP_LOGI("remote_ is nullptr!");
        return;
    }
    if (deathRecipient_ == nullptr) {
        DHCP_LOGI("deathRecipient_ is nullptr!");
        return;
    }
    remote_->RemoveDeathRecipient(deathRecipient_);
    remote_ = nullptr;
}

void DhcpServerProxy::OnRemoteDied(const wptr<IRemoteObject> &remoteObject)
{
    DHCP_LOGI("Remote service is died! remoteObject: %{private}p", &remoteObject);
    mRemoteDied = true;
    RemoveDeathRecipient();
    if (g_dhcpServerCallBackStub == nullptr) {
        DHCP_LOGE("g_dhcpServerCallBackStub is nullptr");
        return;
    }
    if (g_dhcpServerCallBackStub != nullptr) {
        g_dhcpServerCallBackStub->SetRemoteDied(true);
    }
}

bool DhcpServerProxy::IsRemoteDied(void)
{
    if (mRemoteDied) {
        DHCP_LOGI("IsRemoteDied! remote is died now!");
    }
    return mRemoteDied;
}

ErrCode DhcpServerProxy::RegisterDhcpServerCallBack(const std::string& ifname,
    const sptr<IDhcpServerCallBack> &callback)
{
    DHCP_LOGI("DhcpServerProxy enter RegisterDhcpServerCallBack mRemoteDied:%{public}d", mRemoteDied);
    if (mRemoteDied) {
        DHCP_LOGE("failed to `%{public}s`,remote service is died!", __func__);
        return DHCP_E_FAILED;
    }
    MessageParcel data, reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        DHCP_LOGE("Write interface token error: %{public}s", __func__);
        return DHCP_E_FAILED;
    }
    data.WriteInt32(0);
    if (g_dhcpServerCallBackStub == nullptr) {
        DHCP_LOGE("g_dhcpServerCallBackStub is nullptr");
        return DHCP_E_FAILED;
    }
    g_dhcpServerCallBackStub->RegisterCallBack(callback);

    if (!data.WriteRemoteObject(g_dhcpServerCallBackStub->AsObject())) {
        DHCP_LOGE("DhcpServerProxy::RegisterCallBack WriteRemoteObject failed!");
        return DHCP_E_FAILED;
    }

    int pid = GetCallingPid();
    int tokenId = GetCallingTokenId();
    data.WriteInt32(pid);
    data.WriteInt32(tokenId);
    data.WriteString(ifname);
    DHCP_LOGI("%{public}s, calling uid:%{public}d, pid:%{public}d, ifname:%{public}s",
        __func__, GetCallingUid(), pid, ifname.c_str());
    int error = Remote()->SendRequest(static_cast<uint32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_REG_CALL_BACK),
        data, reply, option);
    if (error != ERR_NONE) {
        DHCP_LOGE("Set Attr(%{public}d) failed, code is %{public}d",
            static_cast<int32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_REG_CALL_BACK), error);
        return DHCP_E_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        DHCP_LOGE("exception failed, exception:%{public}d", exception);
        return DHCP_E_FAILED;
    }
    DHCP_LOGI("DhcpServerProxy RegisterDhcpServerCallBack ok, exception:%{public}d", exception);
    return DHCP_E_SUCCESS;
}

ErrCode DhcpServerProxy::StartDhcpServer(const std::string& ifname)
{
    DHCP_LOGI("[DHCP][ServerProxy] start begin, ifname:%{public}s remoteDied:%{public}d", ifname.c_str(),
        mRemoteDied);
    if (mRemoteDied) {
        DHCP_LOGE("failed to `%{public}s`,remote service is died!", __func__);
        return DHCP_E_FAILED;
    }
    MessageParcel data, reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        DHCP_LOGE("Write interface token error: %{public}s", __func__);
        return DHCP_E_FAILED;
    }
    data.WriteInt32(0);

    int pid = GetCallingPid();
    int tokenId = GetCallingTokenId();
    data.WriteInt32(pid);
    data.WriteInt32(tokenId);
    data.WriteString(ifname);
    DHCP_LOGI("%{public}s, calling uid:%{public}d, pid:%{public}d, ifname:%{public}s",
        __func__, GetCallingUid(), pid, ifname.c_str());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_START_DHCP_SERVER), data, reply, option);
    if (error != ERR_NONE) {
        DHCP_LOGE("Set Attr(%{public}d) failed, code is %{public}d",
            static_cast<int32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_START_DHCP_SERVER), error);
        return DHCP_E_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        DHCP_LOGE("exception failed, exception:%{public}d", exception);
        return DHCP_E_FAILED;
    }
    ErrCode ret = static_cast<ErrCode>(reply.ReadInt32());
    if (ret != DHCP_E_SUCCESS) {
        DHCP_LOGE("[DHCP][ServerProxy] start service failed, ifname:%{public}s ret:%{public}d", ifname.c_str(),
            static_cast<int32_t>(ret));
    } else {
        DHCP_LOGI("[DHCP][ServerProxy] start succeeded, ifname:%{public}s", ifname.c_str());
    }
    return ret;
}

ErrCode DhcpServerProxy::SetDhcpRange(const std::string& ifname, const DhcpRange& range)
{
    DHCP_LOGI("[DHCP][ServerProxy] set range begin, ifname:%{public}s remoteDied:%{public}d", ifname.c_str(),
        mRemoteDied);
    if (mRemoteDied) {
        DHCP_LOGE("failed to `%{public}s`,remote service is died!", __func__);
        return DHCP_E_FAILED;
    }
    MessageParcel data, reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        DHCP_LOGE("Write interface token error: %{public}s", __func__);
        return DHCP_E_FAILED;
    }
    data.WriteInt32(0);

    data.WriteInt32(range.iptype);
    data.WriteInt32(range.leaseHours);
    data.WriteString(range.strTagName);
    data.WriteString(range.strStartip);
    data.WriteString(range.strEndip);
    data.WriteString(range.strSubnet);
    data.WriteString(ifname);
    DHCP_LOGI("%{public}s, LINE :%{public}d ifname:%{public}s iptype %{public}d leaseHours %{public}d"
        "TagName:%{public}s Startip:%{private}s strEndip:%{private}s strSubnet:%{private}s",
        __func__, __LINE__, ifname.c_str(), range.iptype, range.leaseHours, range.strTagName.c_str(),
        range.strStartip.c_str(), range.strEndip.c_str(), range.strSubnet.c_str());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_SET_DHCP_RANGE), data, reply, option);
    if (error != ERR_NONE) {
        DHCP_LOGE("Set Attr(%{public}d) failed, code is %{public}d",
            static_cast<int32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_SET_DHCP_RANGE), error);
        return DHCP_E_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        DHCP_LOGE("exception failed, exception:%{public}d", exception);
        return DHCP_E_FAILED;
    }
    ErrCode ret = static_cast<ErrCode>(reply.ReadInt32());
    if (ret != DHCP_E_SUCCESS) {
        DHCP_LOGE("[DHCP][ServerProxy] set range service failed, ifname:%{public}s ret:%{public}d", ifname.c_str(),
            static_cast<int32_t>(ret));
    } else {
        DHCP_LOGI("[DHCP][ServerProxy] set range succeeded, ifname:%{public}s", ifname.c_str());
    }
    return ret;
}

ErrCode DhcpServerProxy::SetDhcpName(const std::string& ifname, const std::string& tagName)
{

    DHCP_LOGI("DhcpServerProxy enter SetDhcpName mRemoteDied:%{public}d", mRemoteDied);
    if (mRemoteDied) {
        DHCP_LOGE("failed to `%{public}s`,remote service is died!", __func__);
        return DHCP_E_FAILED;
    }
    MessageParcel data, reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        DHCP_LOGE("Write interface token error: %{public}s", __func__);
        return DHCP_E_FAILED;
    }
    data.WriteInt32(0);

    data.WriteString(tagName);
    data.WriteString(ifname);
     DHCP_LOGI("%{public}s, LINE :%{public}d ifname:%{public}s tagName %{public}s", __func__, __LINE__, ifname.c_str(),
        tagName.c_str());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_SET_DHCP_NAME), data, reply, option);
    if (error != ERR_NONE) {
        DHCP_LOGE("Set Attr(%{public}d) failed, code is %{public}d",
            static_cast<int32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_SET_DHCP_NAME), error);
        return DHCP_E_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        DHCP_LOGE("exception failed, exception:%{public}d", exception);
        return DHCP_E_FAILED;
    }
    DHCP_LOGI("DhcpServerProxy SetDhcpName ok, exception:%{public}d", exception);
    return DHCP_E_SUCCESS;
}
ErrCode DhcpServerProxy::PutDhcpRange(const std::string& tagName, const DhcpRange& range)
{
    DHCP_LOGI("DhcpServerProxy enter PutDhcpRange mRemoteDied:%{public}d", mRemoteDied);
    if (mRemoteDied) {
        DHCP_LOGE("failed to `%{public}s`,remote service is died!", __func__);
        return DHCP_E_FAILED;
    }
    MessageParcel data, reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        DHCP_LOGE("Write interface token error: %{public}s", __func__);
        return DHCP_E_FAILED;
    }
    data.WriteInt32(0);
    data.WriteInt32(range.iptype);
    data.WriteInt32(range.leaseHours);
    data.WriteString(range.strTagName);
    data.WriteString(range.strStartip);
    data.WriteString(range.strEndip);
    data.WriteString(range.strSubnet);
    data.WriteString(tagName);
    DHCP_LOGI("%{public}s, LINE :%{public}d tagName:%{public}s iptype %{public}d  leaseHours %{public}d"
        "strTagName:%{public}s strStartip:%{private}s strEndip:%{private}s strSubnet:%{private}s",
        __func__, __LINE__, tagName.c_str(), range.iptype, range.leaseHours, range.strTagName.c_str(),
        range.strStartip.c_str(), range.strEndip.c_str(), range.strSubnet.c_str());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_PUT_DHCP_RANGE), data, reply, option);
    if (error != ERR_NONE) {
        DHCP_LOGE("Set Attr(%{public}d) failed, code is %{public}d",
            static_cast<int32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_PUT_DHCP_RANGE), error);
        return DHCP_E_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        DHCP_LOGE("exception failed, exception:%{public}d", exception);
        return DHCP_E_FAILED;
    }
    DHCP_LOGI("DhcpServerProxy SetDhcpRange ok, exception:%{public}d", exception);
    return DHCP_E_SUCCESS;
}

ErrCode DhcpServerProxy::RemoveAllDhcpRange(const std::string& tagName)
{
    if (tagName.empty()) {
        DHCP_LOGE("RemoveAllDhcpRange invalid tagName");
        return DHCP_E_FAILED;
    }
    DHCP_LOGI("DhcpServerProxy enter RemoveAllDhcpRange mRemoteDied:%{public}d", mRemoteDied);
    if (mRemoteDied) {
        DHCP_LOGE("failed to `%{public}s`,remote service is died!", __func__);
        return DHCP_E_FAILED;
    }
    MessageParcel data, reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        DHCP_LOGE("Write interface token error: %{public}s", __func__);
        return DHCP_E_FAILED;
    }
    data.WriteInt32(0);

    data.WriteString(tagName);
    DHCP_LOGI("%{public}s, calling tagName:%{public}s", __func__, tagName.c_str());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_REMOVE_ALL_DHCP_RANGE), data, reply, option);
    if (error != ERR_NONE) {
        DHCP_LOGE("Set Attr(%{public}d) failed, code is %{public}d",
            static_cast<int32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_REMOVE_ALL_DHCP_RANGE), error);
        return DHCP_E_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        DHCP_LOGE("exception failed, exception:%{public}d", exception);
        return DHCP_E_FAILED;
    }
    DHCP_LOGI("DhcpServerProxy RemoveAllDhcpRange ok, exception:%{public}d", exception);
    return DHCP_E_SUCCESS;
}

ErrCode DhcpServerProxy::UpdateLeasesTime(const std::string& leaseTime)
{
    DHCP_LOGI("DhcpServerProxy enter UpdateLeasesTime mRemoteDied:%{public}d", mRemoteDied);
    if (mRemoteDied) {
        DHCP_LOGE("failed to `%{public}s`,remote service is died!", __func__);
        return DHCP_E_FAILED;
    }
    MessageParcel data, reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        DHCP_LOGE("Write interface token error: %{public}s", __func__);
        return DHCP_E_FAILED;
    }
    data.WriteInt32(0);

    data.WriteString(leaseTime);
    DHCP_LOGI("%{public}s, calling  leaseTime:%{public}s", __func__, leaseTime.c_str());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_UPDATE_RENEW_TIME), data, reply, option);
    if (error != ERR_NONE) {
        DHCP_LOGE("Set Attr(%{public}d) failed, code is %{public}d",
            static_cast<int32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_UPDATE_RENEW_TIME), error);
        return DHCP_E_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        DHCP_LOGE("exception failed, exception:%{public}d", exception);
        return DHCP_E_FAILED;
    }
    DHCP_LOGI("DhcpServerProxy UpdateLeasesTime ok, exception:%{public}d", exception);
    return DHCP_E_SUCCESS;
}

ErrCode DhcpServerProxy::StopDhcpServer(const std::string& ifname)
{
    DHCP_LOGI("DhcpServerProxy enter StopDhcpServer mRemoteDied:%{public}d", mRemoteDied);
    if (mRemoteDied) {
        DHCP_LOGE("failed to `%{public}s`,remote service is died!", __func__);
        return DHCP_E_FAILED;
    }
    MessageParcel data, reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        DHCP_LOGE("Write interface token error: %{public}s", __func__);
        return DHCP_E_FAILED;
    }
    data.WriteInt32(0);
    data.WriteString(ifname);
    DHCP_LOGI("%{public}s, calling tagName:%{public}s", __func__, ifname.c_str());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_STOP_DHCP_SERVER), data, reply, option);
    if (error != ERR_NONE) {
        DHCP_LOGE("Set Attr(%{public}d) failed, code is %{public}d",
            static_cast<int32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_STOP_DHCP_SERVER), error);
        return DHCP_E_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        DHCP_LOGE("exception failed, exception:%{public}d", exception);
        return DHCP_E_FAILED;
    }
    DHCP_LOGI("DhcpServerProxy StopDhcpServer ok, exception:%{public}d", exception);
    return DHCP_E_SUCCESS;
}

ErrCode DhcpServerProxy::StopServerSa(void)
{
    DHCP_LOGI("DhcpServerProxy enter StopServerSa mRemoteDied:%{public}d", mRemoteDied);
    if (mRemoteDied) {
        DHCP_LOGE("failed to %{public}s,remote service is died!", __func__);
        return DHCP_E_FAILED;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        DHCP_LOGE("Write interface token error: %{public}s", __func__);
        return DHCP_E_FAILED;
    }
    data.WriteInt32(0);
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_STOP_SA), data, reply, option);
    if (error != ERR_NONE) {
        DHCP_LOGE("Set Attr(%{public}d) failed, code is %{public}d",
            static_cast<int32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_STOP_SA), error);
        return DHCP_E_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        DHCP_LOGE("exception failed, exception:%{public}d", exception);
        return DHCP_E_FAILED;
    }
    DHCP_LOGI("DhcpServerProxy StopServerSa ok, exception:%{public}d", exception);
    return DHCP_E_SUCCESS;
}

ErrCode DhcpServerProxy::RemoveDhcpRange(const std::string& tagName, const DhcpRange& range)
{
    DHCP_LOGI("DhcpServerProxy enter RemoveDhcpRange mRemoteDied:%{public}d", mRemoteDied);
    if (mRemoteDied) {
        DHCP_LOGE("failed to `%{public}s`,remote service is died!", __func__);
        return DHCP_E_FAILED;
    }
    MessageParcel data, reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        DHCP_LOGE("Write interface token error: %{public}s", __func__);
        return DHCP_E_FAILED;
    }
    data.WriteInt32(0);
    data.WriteInt32(range.iptype);
    data.WriteInt32(range.leaseHours);
    data.WriteString(range.strTagName);
    data.WriteString(range.strStartip);
    data.WriteString(range.strEndip);
    data.WriteString(range.strSubnet);
    data.WriteString(tagName);
    DHCP_LOGI("%{public}s, LINE :%{public}d ifname:%{public}s iptype %{public}d leaseHours %{public}d"
        "strTagName:%{public}s strStartip:%{private}s strEndip:%{private}s strSubnet:%{private}s",
        __func__, __LINE__, tagName.c_str(), range.iptype, range.leaseHours, range.strTagName.c_str(),
        range.strStartip.c_str(), range.strEndip.c_str(), range.strSubnet.c_str());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_REMOVE_DHCP_RANGE), data, reply, option);
    if (error != ERR_NONE) {
        DHCP_LOGE("Set Attr(%{public}d) failed, code is %{public}d",
            static_cast<int32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_REMOVE_DHCP_RANGE), error);
        return DHCP_E_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        DHCP_LOGE("exception failed, exception:%{public}d", exception);
        return DHCP_E_FAILED;
    }
    DHCP_LOGI("DhcpServerProxy SetDhcpRange ok, exception:%{public}d", exception);
    return DHCP_E_SUCCESS;
}
ErrCode DhcpServerProxy::GetDhcpClientInfos(const std::string& ifname, std::vector<std::string>& dhcpClientInfo)
{
    DHCP_LOGI("DhcpServerProxy enter GetDhcpClientInfos mRemoteDied:%{public}d", mRemoteDied);
    if (mRemoteDied) {
        DHCP_LOGE("failed to `%{public}s`,remote service is died!", __func__);
        return DHCP_E_FAILED;
    }
    MessageParcel data, reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        DHCP_LOGE("Write interface token error: %{public}s", __func__);
        return DHCP_E_FAILED;
    }
    data.WriteInt32(0);
    data.WriteString(ifname);
    DHCP_LOGI("%{public}s, LINE :%{public}d %{public}s", __func__, __LINE__, ifname.c_str());
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_GET_DHCP_CLIENT_INFO), data, reply, option);
    if (error != ERR_NONE) {
        DHCP_LOGE("Set Attr(%{public}d) failed, code is %{public}d",
            static_cast<int32_t>(DhcpServerInterfaceCode::DHCP_SERVER_SVR_CMD_GET_DHCP_CLIENT_INFO), error);
        return DHCP_E_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        DHCP_LOGE("exception failed, exception:%{public}d", exception);
        return DHCP_E_FAILED;
    }
    int ret = reply.ReadInt32();
    if (ret == DHCP_E_SUCCESS) {
        int tmpsize = reply.ReadInt32();
        DHCP_LOGI("DhcpServerProxy GetDhcpClientInfos ok, exception:%{public}d, reply data size:%{public}d", exception,
            tmpsize);
        if (tmpsize < 0 || tmpsize > MAX_SIZE) {
            DHCP_LOGE("GetDhcpClientInfos tmpsize error: %{public}d", tmpsize);
            return DHCP_E_FAILED;
        }
        for (int i = 0; i < tmpsize; i++) {
            std::string str = reply.ReadString();
            dhcpClientInfo.push_back(str);
        }
    }
    DHCP_LOGI("DhcpServerProxy GetDhcpClientInfos 1");
    return DHCP_E_SUCCESS;
}
}  // namespace DHCP
}  // namespace OHOS
