/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#ifndef DHCP_L3_CLIENT_INTERNAL_H
#define DHCP_L3_CLIENT_INTERNAL_H

#include <cstdint>
#include "dhcp_define.h"
#include "dhcp_errcode.h"

namespace OHOS {
namespace DHCP {
// Called only by the C adapter. The public DhcpClient vtable remains unchanged.
ErrCode StartDhcpClientL3Internal(const RouterConfig &config, const uint8_t *clientKey, uint32_t keyLength);
} // namespace DHCP
} // namespace OHOS
#endif // DHCP_L3_CLIENT_INTERNAL_H
