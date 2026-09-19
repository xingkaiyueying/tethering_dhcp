/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#ifndef OHOS_DHCP_DNS_REPOSITORY_H
#define OHOS_DHCP_DNS_REPOSITORY_H
#include <string>
#include <vector>
#include <unordered_set>
#include <mutex>
#include "dhcp_ipv6_define.h"
#include "dhcp_ipv6_info.h"
namespace OHOS {
namespace DHCP {
class DnsServerRepository {
private:
    static const int NUM_CURRENT_SERVERS = 3;
    static const int NUM_SERVERS = 12;
    static const int DEFAULT_MIN_RDNSS_LIFETIME = 120;
    std::unordered_set<std::string> currentServers_;  // curent use server
    std::vector<DnsServerEntry> allServers_;          // all existing server
    uint32_t minLifetime_ = DEFAULT_MIN_RDNSS_LIFETIME;
    std::mutex mutex;
    size_t currentLimit_ = NUM_CURRENT_SERVERS;
    size_t allLimit_ = NUM_SERVERS;

public:
    DnsServerRepository(int minLifeTime = DEFAULT_MIN_RDNSS_LIFETIME,
        size_t currentLimit = NUM_CURRENT_SERVERS, size_t allLimit = NUM_SERVERS);
    ~DnsServerRepository();
    bool Clear(); // clear all dns server info
    bool Expire();
    bool AddServers(uint32_t lifetime, const std::vector<std::string>& addresses);  // add new dns server info
    bool SetCurrentServers(DhcpIpv6Info &ipv6Info); //set current servers to ipv6Info
private:
    bool UpdateExistingEntry(const std::string& address, uint64_t expiry);
    bool UpdateCurrentServers();
};
}
}
#endif
