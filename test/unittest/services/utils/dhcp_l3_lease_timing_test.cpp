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

#include <gtest/gtest.h>

#include "dhcp_l3_lease_timing.h"

using namespace testing::ext;
using OHOS::DHCP::DeriveAndValidateLeaseTiming;

namespace OHOS {
namespace DHCP {
class DhcpL3LeaseTimingTest : public testing::Test {};

HWTEST_F(DhcpL3LeaseTimingTest, RejectZeroLeaseSeconds, TestSize.Level1)
{
    uint32_t t1 = 0;
    uint32_t t2 = 0;
    EXPECT_FALSE(DeriveAndValidateLeaseTiming(0, t1, t2));
}

HWTEST_F(DhcpL3LeaseTimingTest, DeriveDefaultT1T2For86400And120, TestSize.Level1)
{
    uint32_t t1 = 0;
    uint32_t t2 = 0;
    ASSERT_TRUE(DeriveAndValidateLeaseTiming(86400, t1, t2));
    EXPECT_EQ(t1, 43200u);
    EXPECT_EQ(t2, 75600u);
    t1 = 0;
    t2 = 0;
    ASSERT_TRUE(DeriveAndValidateLeaseTiming(120, t1, t2));
    EXPECT_EQ(t1, 60u);
    EXPECT_EQ(t2, 105u);
}

HWTEST_F(DhcpL3LeaseTimingTest, RejectInvalidT1T2Order, TestSize.Level1)
{
    uint32_t t1 = 80;
    uint32_t t2 = 40;
    EXPECT_FALSE(DeriveAndValidateLeaseTiming(120, t1, t2));
    t1 = 0;
    t2 = 120;
    EXPECT_FALSE(DeriveAndValidateLeaseTiming(120, t1, t2));
}
}  // namespace DHCP
}  // namespace OHOS
