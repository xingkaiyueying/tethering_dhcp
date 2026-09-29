/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#ifndef OHOS_DHCP_CLIENT_CALLBACK_PROXY_H
#define OHOS_DHCP_CLIENT_CALLBACK_PROXY_H

#include "i_dhcp_client_callback.h"
#ifdef OHOS_ARCH_LITE
    #ifndef  OHOS_EUPDATER
        #include "serializer.h"
    #endif
#else
#include "iremote_proxy.h"
#endif
#include "dhcp_define.h"

namespace OHOS {
namespace DHCP {

#ifdef OHOS_ARCH_LITE
class DhcpClientCallbackProxy : public IDhcpClientCallBack {
public:
    #ifndef  OHOS_EUPDATER
    explicit DhcpClientCallbackProxy(SvcIdentity *sid);
    #endif
    virtual ~DhcpClientCallbackProxy();
#else
class DhcpClientCallbackProxy : public IRemoteProxy<IDhcpClientCallBack> {
public:
    explicit DhcpClientCallbackProxy(const sptr<IRemoteObject> &impl);
    virtual ~DhcpClientCallbackProxy();
    void OnDhcpOfferReport(int status, const std::string& ifname, DhcpResult& result) override;
#endif

    void OnIpSuccessChanged(int status, const std::string& ifname, DhcpResult& result) override;
    void OnIpFailChanged(int status, const std::string& ifname, const std::string& reason) override;
private:
#ifdef OHOS_ARCH_LITE
    #ifndef  OHOS_EUPDATER
    SvcIdentity sid_;
    #endif
    static const int DEFAULT_IPC_SIZE = 256;
#else
    static inline BrokerDelegator<DhcpClientCallbackProxy> g_delegator;
    bool WriteDhcpResult(const DhcpResult& result, MessageParcel &data);
#endif
};
}  // namespace DHCP
}  // namespace OHOS
#endif
