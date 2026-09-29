/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#include "dhcp_client_impl.h"
#include "dhcp_l3_client_internal.h"
#include "dhcp_c_utils.h"
#include "dhcp_logger.h"
#include "inner_api/dhcp_client.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpClient");

namespace OHOS {
namespace DHCP {
NO_SANITIZE("cfi") std::shared_ptr<DhcpClient> DhcpClient::GetInstance(int systemAbilityId)
{
    std::shared_ptr<DhcpClientImpl> pImpl = DelayedSingleton<DhcpClientImpl>::GetInstance();
    if (pImpl && pImpl->Init(systemAbilityId)) {
        DHCP_LOGI("init successfully!");
        return pImpl;
    }
    DHCP_LOGI("new dhcp client failed");
    return nullptr;
}

DhcpClient::~DhcpClient()
{
    DHCP_LOGI("~DhcpClient()");
}

ErrCode StartDhcpClientL3Internal(const RouterConfig &config, const uint8_t *clientKey, uint32_t keyLength)
{
#ifdef OHOS_ARCH_LITE
    return DHCP_E_FAILED;
#else
    auto impl = DelayedSingleton<DhcpClientImpl>::GetInstance();
    return impl ? impl->StartDhcpClientL3(config, clientKey, keyLength) : DHCP_E_FAILED;
#endif
}
}  // namespace DHCP
}  // namespace OHOS
