/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

#include <gtest/gtest.h>

#include "dhcp_l3_v2.h"

namespace OHOS {
namespace DHCP {
namespace {
bool IsValidServerTiming(const DhcpServerConfigV2 &config)
{
    if (config.leaseSeconds == 0) {
        return false;
    }
    const uint32_t renewal = config.renewalSeconds == 0 ? config.leaseSeconds / 2 : config.renewalSeconds;
    const uint32_t rebind = config.rebindSeconds == 0 ? config.leaseSeconds * 7 / 8 : config.rebindSeconds;
    return renewal > 0 && renewal < rebind && rebind < config.leaseSeconds;
}
}

TEST(DhcpL3V2ContractTest, DefaultsPreserveLegacyTransport)
{
    EXPECT_EQ(DhcpTransportMode::L2_PACKET, DhcpClientConfigV2().transport);
    EXPECT_EQ(DhcpTransportMode::L2_PACKET, DhcpServerConfigV2().transport);
}

TEST(DhcpL3V2ContractTest, ServerLeaseTimingDerivesT1AndT2InSeconds)
{
    DhcpServerConfigV2 config;
    config.ifname = "sleip0";
    config.transport = DhcpTransportMode::L3_TUN;
    config.leaseSeconds = 120;
    EXPECT_TRUE(IsValidServerTiming(config));

    config.leaseSeconds = 0;
    EXPECT_FALSE(IsValidServerTiming(config));

    config.leaseSeconds = 120;
    config.renewalSeconds = 110;
    config.rebindSeconds = 100;
    EXPECT_FALSE(IsValidServerTiming(config));
}
} // namespace DHCP
} // namespace OHOS
