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

#ifndef OHOS_DHCP_L3_CONFIG_V2_H
#define OHOS_DHCP_L3_CONFIG_V2_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "dhcp_define.h"
#include "dhcp_l3_lease_timing.h"

namespace OHOS {
namespace DHCP {

enum class DhcpTransportMode : uint8_t {
    L2_PACKET = 0,
    L3_TUN = 1,
};

enum class LeaseEventType : uint8_t {
    OFFERED = 0,
    BOUND,
    RENEWED,
    REBOUND,
    RELEASED,
    DECLINED,
    EXPIRED,
    NAK,
};

enum class DhcpLeaseInvalidReason : uint8_t {
    MAPPING_CONFLICT = 1,
    SESSION_STALE = 2,
    PEER_RELEASED = 3,
};

struct DhcpClientTransportConfig {
    DhcpTransportMode mode { DhcpTransportMode::L2_PACKET };
    std::string ifname;
    std::array<uint8_t, 6> clientKey {};
    bool forceInitialBroadcast { true };
};

struct DhcpClientConfigV2 {
    RouterConfig base;
    DhcpClientTransportConfig transport;
};

struct DhcpServerConfigV2 {
    std::string ifname;
    DhcpTransportMode mode { DhcpTransportMode::L2_PACKET };
    DhcpRange range;
    uint32_t leaseSeconds { 86400 };
    uint32_t renewalSeconds { 0 };
    uint32_t rebindSeconds { 0 };
    bool forceInitialBroadcast { true };
};

struct DhcpLease {
    std::string address;
    uint8_t prefixLength { 24 };
    std::string gateway;
    std::vector<std::string> dnsServers;
    uint32_t leaseSeconds { 0 };
    uint32_t renewalSeconds { 0 };
    uint32_t rebindSeconds { 0 };
    uint64_t expiryMonotonicMs { 0 };
};

struct DhcpLeaseEvent {
    LeaseEventType type { LeaseEventType::BOUND };
    std::string ifname;
    std::array<uint8_t, 6> clientKey {};
    uint32_t xid { 0 };
    DhcpLease lease;
    int32_t cause { 0 };
};

/*
 * Derive T1/T2 when zero, then require 0 < T1 < T2 < leaseSeconds.
 * leaseSeconds == 0 is rejected. This is the V2 per-instance rule and must
 * not write DhcpRange::leaseHours or call UpdateLeasesTime().
 */
inline bool ValidateDhcpServerConfigV2(const DhcpServerConfigV2 &config, uint32_t &renewalSeconds,
    uint32_t &rebindSeconds)
{
    renewalSeconds = config.renewalSeconds;
    rebindSeconds = config.rebindSeconds;
    return DeriveAndValidateLeaseTiming(config.leaseSeconds, renewalSeconds, rebindSeconds);
}

class IDhcpPacketTransport {
public:
    virtual ~IDhcpPacketTransport() = default;
    virtual int32_t Open(const DhcpClientTransportConfig &config) = 0;
    virtual int32_t Send(const uint8_t *packet, size_t length, uint32_t sourceIpv4, uint32_t destinationIpv4) = 0;
    virtual int32_t Receive(uint8_t *packet, size_t length, size_t &outLength) = 0;
    virtual void Close() = 0;
};

class IDhcpConflictDetector {
public:
    virtual ~IDhcpConflictDetector() = default;
    virtual int32_t CheckCandidate(const std::string &ifname, const std::array<uint8_t, 6> &clientKey,
        uint32_t candidate) = 0;
};

}  // namespace DHCP
}  // namespace OHOS
#endif
