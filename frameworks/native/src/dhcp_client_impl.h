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
#ifndef OHOS_DHCP_CLIENT_IMPL_H
#define OHOS_DHCP_CLIENT_IMPL_H

#include <string>
#include "singleton.h"
#include "i_dhcp_client.h"
#include "i_dhcp_client_callback.h"
#include "inner_api/dhcp_client.h"

namespace OHOS {
namespace DHCP {
class DhcpClientImpl : public DhcpClient {
    DECLARE_DELAYED_SINGLETON(DhcpClientImpl);
public:
    bool Init(int systemAbilityId);
    bool IsRemoteDied();
#ifdef OHOS_ARCH_LITE
    ErrCode RegisterDhcpClientCallBack(const std::string& ifname,
        const std::shared_ptr<IDhcpClientCallBack> &callback) override;
#else
    ErrCode RegisterDhcpClientCallBack(const std::string& ifname,
        const sptr<IDhcpClientCallBack> &callback) override;
#endif
    
    ErrCode StartDhcpClient(const RouterConfig &config) override;
    ErrCode StartDhcpClientL3(const RouterConfig &config, const uint8_t *clientKey, uint32_t keyLength);
    ErrCode DealWifiDhcpCache(int32_t cmd, const IpCacheInfo &ipCacheInfo) override;
    ErrCode StopDhcpClient(const std::string& ifname, bool bIpv6, bool bIpv4 = true) override;
    ErrCode StopClientSa(void) override;
private:
    bool GetDhcpClientProxy();
    int systemAbilityId_;
    std::mutex mutex_;
#ifdef OHOS_ARCH_LITE
    IDhcpClient *client_;
#else
    sptr<IDhcpClient> client_;
#endif
};
}  // namespace DHCP
}  // namespace OHOS
#endif
