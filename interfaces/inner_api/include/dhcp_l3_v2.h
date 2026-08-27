/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_DHCP_L3_V2_H
#define OHOS_DHCP_L3_V2_H

#include <array>
#include <cstdint>
#include <functional>
#include <string>

namespace OHOS {
namespace DHCP {

constexpr size_t DHCP_CLIENT_KEY_SIZE = 6;

enum class DhcpTransportMode : uint8_t {
    L2_PACKET = 0,
    L3_TUN = 1,
};

enum class DhcpLeaseEventType : uint8_t {
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
    UNSPECIFIED = 0,
    CLIENT_DISCONNECTED,
    ADDRESS_MAPPING_CONFLICT,
    ADMINISTRATIVE_STOP,
};

struct DhcpClientConfigV2 {
    std::string ifname;
    DhcpTransportMode transport = DhcpTransportMode::L2_PACKET;
    std::array<uint8_t, DHCP_CLIENT_KEY_SIZE> clientKey {};
    bool forceInitialBroadcast = true;
    bool enableIpv4 = true;
    bool enableIpv6 = false;
};

struct DhcpServerConfigV2 {
    std::string ifname;
    DhcpTransportMode transport = DhcpTransportMode::L2_PACKET;
    uint32_t leaseSeconds = 0;
    uint32_t renewalSeconds = 0;
    uint32_t rebindSeconds = 0;
};

struct DhcpLeaseEventV2 {
    std::string ifname;
    DhcpLeaseEventType type = DhcpLeaseEventType::OFFERED;
    std::array<uint8_t, DHCP_CLIENT_KEY_SIZE> clientKey {};
    uint32_t transactionId = 0;
    uint32_t address = 0;
    uint32_t serverAddress = 0;
    uint32_t leaseSeconds = 0;
    uint32_t renewalSeconds = 0;
    uint32_t rebindSeconds = 0;
    int32_t cause = 0;
};

using DhcpLeaseCallbackV2 = std::function<void(const DhcpLeaseEventV2 &event)>;

class IDhcpPacketTransport {
public:
    virtual ~IDhcpPacketTransport() = default;
    virtual int Open(const std::string &ifname) = 0;
    virtual int Send(const uint8_t *packet, size_t packetLength, uint32_t sourceAddress,
        uint32_t destinationAddress) = 0;
    virtual int Receive(uint8_t *packet, size_t packetCapacity, size_t &packetLength) = 0;
    virtual void Close() = 0;
};

enum class DhcpConflictResult : uint8_t {
    AVAILABLE = 0,
    IN_USE,
    ERROR,
};

class IDhcpConflictDetector {
public:
    virtual ~IDhcpConflictDetector() = default;
    virtual DhcpConflictResult Probe(const std::string &ifname, uint32_t candidateAddress) = 0;
};

// Phase-0 contract draft. Implementations and IPC transactions are intentionally added in the next phase.
int32_t StartDhcpClientV2(const DhcpClientConfigV2 &config);
int32_t StartDhcpServerV2(const DhcpServerConfigV2 &config);
int32_t RegisterDhcpLeaseCallbackV2(const std::string &ifname, DhcpLeaseCallbackV2 callback);
int32_t InvalidateDhcpLeaseV2(const std::string &ifname,
    const std::array<uint8_t, DHCP_CLIENT_KEY_SIZE> &clientKey, uint32_t address,
    DhcpLeaseInvalidReason reason);

} // namespace DHCP
} // namespace OHOS

#endif // OHOS_DHCP_L3_V2_H
