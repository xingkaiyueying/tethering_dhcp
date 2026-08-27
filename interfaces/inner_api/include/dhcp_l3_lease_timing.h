/*
 * Copyright (C) 2024-2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_DHCP_L3_LEASE_TIMING_H
#define OHOS_DHCP_L3_LEASE_TIMING_H

#include <cstdint>

namespace OHOS {
namespace DHCP {

inline bool DeriveAndValidateLeaseTiming(uint32_t leaseSeconds, uint32_t &renewalSeconds, uint32_t &rebindSeconds)
{
    if (leaseSeconds == 0) {
        return false;
    }
    uint32_t t1 = renewalSeconds;
    uint32_t t2 = rebindSeconds;
    if (t1 == 0) {
        t1 = leaseSeconds / 2;
    }
    if (t2 == 0) {
        t2 = static_cast<uint32_t>((static_cast<uint64_t>(leaseSeconds) * 7U) / 8U);
    }
    if (!(t1 > 0 && t2 > t1 && t2 < leaseSeconds)) {
        return false;
    }
    renewalSeconds = t1;
    rebindSeconds = t2;
    return true;
}

}  // namespace DHCP
}  // namespace OHOS
#endif
