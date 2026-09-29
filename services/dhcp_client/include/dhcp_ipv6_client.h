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
#ifndef OHOS_DHCP_IP6_H
#define OHOS_DHCP_IP6_H

#include <mutex>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <sys/types.h>
#include "dhcp_ipv6_dns_repository.h"
#include "dhcp_define.h"

namespace OHOS {
namespace DHCP {

#if DHCPV6_ENABLE
class DhcpV6Client;
#endif

class DhcpIpv6Client {
public:
    DhcpIpv6Client(std::string ifname);
    virtual ~DhcpIpv6Client();

    bool IsRunning();
    bool IsLayer3() const { return layer3_; }
    void SetLayer3(bool enabled)
    {
        layer3_ = enabled;
        if (enabled) dhcpIpv6DnsRepository_ = std::make_unique<DnsServerRepository>(0, 4, 4);
    }
    void SetCallback(std::function<void(const std::string ifname, DhcpIpv6Info &info)> callback);
    void SetRaFlagsCallback(std::function<void(const std::string ifname, bool managed, bool other)> callback);
    bool GetIpv6InfoSnapshot(DhcpIpv6Info &info);
    void SetAcceptRa(const std::string &content);
    void SetRouterSolicitations(const std::string &content);
    void SetRouterSolicitationInterval(const std::string &content);
    void *DhcpIpv6Start();
    void DhcpIPV6Stop(void);
    void Reset();
    void RunIpv6ThreadFunc();
    int StartIpv6();
    int StartIpv6Thread(const std::string &ifname, bool isIpv6);
    void SetDadResultCallback(
        std::function<void(const std::string ifname, const std::string addr, bool isTentative)> callback);
    void SetAddrRemovedCallback(
        std::function<void(const std::string ifname, const std::string addr)> callback);
    void GetRaFlags(uint8_t &raFlags) const;
    void ResetRaFlags();
#if DHCPV6_ENABLE
    void SetDhcpV6Client(DhcpV6Client* client);
    void UnRegisterDhcpV6Callbacks();
#endif

private:
    int32_t createKernelSocket(void);
    void GetIpv6Prefix(const char* ipv6Addr, char* ipv6PrefixBuf, uint8_t prefixLen);
    int GetIpFromS6Address(void* addr, int family, char* buf, int buflen);
    int GetAddrScope(void *addr);
    int GetAddrType(const struct in6_addr *addr);
    AddrType AddIpv6Address(char *ipv6addr, int len);
    bool GetInterfaceInfo(int &ifaceIndex, unsigned char *ifaceMac);
    unsigned int ipv6AddrScope2Type(unsigned int scope);
    void onIpv6DnsAddEvent(void* data, int len, int ifaIndex);
    void OnIpv6RouteUpdateEvent(char* gateway, char* dst, int ifaIndex, bool isAdd = true);
    void OnIpv6AddressUpdateEvent(char *addr, int addrlen, int prefixLen,
                                int ifaIndex, int scope, bool isUpdate);
    void ProcessAddressChange(char *addr, AddrType type, bool isUpdate);
    int SendRouterSolicitation();
    void setSocketFilter(void* addr);
    void handleKernelEvent(const uint8_t* data, int len);
    void parseNdUserOptMessage(void* msg, int len);
    void ParseAddrMessage(void *msg);
    bool ParseL3Address(void *msg);
    void ParseAddrAttributes(void *addrMsgptr, int32_t len, char *addresses, int &scope, bool &isTemporary);
    void NotifyRaFlagsChanged(bool managed, bool other);
    void parseRouteAttributes(void* rtMsgPtr, size_t size, char* dst, char* gateway, int& ifindex);
    void parseNDRouteMessage(void* msg);
    void parseNewneighMessage(void* msg);
    void ParseLinkMessage(void *msg);
    void QueryInterfaceRaFlags();
    void StartRaFlagsQueryTimer();// // Query RA flags after delay when link-local address is added
    bool BuildAndSendNetlinkRequest(unsigned int ifIndex, std::vector<uint8_t>& response);
    void ParseAfSpecAttributes(struct rtattr *afRta, int afLen, unsigned int ifIndex);
    void getIpv6RouteAddr();
    void fillRouteData(char* buff, int &len);
    bool IsEui64ModeIpv6Address(const char *ipv6addr, int len, const unsigned char *ifaceMac, int macLen);
    void PublishIpv6Result();
    bool IsGlobalIpv6Address(const char *ipv6addr, int len);
    bool IsUniqueLocalIpv6Address(const char *ipv6addr, int len);
    bool IsValidIpv6Address(const char *ipv6addr);
    uint32_t ConvertNetworkToHostLong(uint32_t value);
    // Callback function mutex
    std::mutex ipv6CallbackMutex_;
    std::function<void(const std::string ifname, DhcpIpv6Info &info)> onIpv6AddressChanged_ { nullptr };
    // Callback for RA flags (M/O) change
    std::function<void(const std::string ifname, bool managed, bool other)> onRaFlagsChanged_ { nullptr };
    // Callback for kernel DAD result (address, tentative flag state)
    std::function<void(const std::string ifname, const std::string addr,
        bool isTentative)> onIpv6DadResult_ { nullptr };
    // Callback for address removal notification (to clear DHCPv6 cache on IPv6 self-healing)
    std::function<void(const std::string ifname, const std::string addr)> onAddrRemoved_ { nullptr };
    // Direct reference to DhcpV6Client for address type checking
#if DHCPV6_ENABLE
    DhcpV6Client* pDhcpV6Client_ { nullptr };
#endif
    // global variables
    std::mutex mutex_;
    std::string interfaceName;
    struct DhcpIpv6Info dhcpIpv6Info;
    int32_t ipv6SocketFd = -1;
    std::atomic<bool> runFlag_ { false };
    bool layer3_{false};
    // IPv6 thread
    std::unique_ptr<std::thread> ipv6Thread_ = nullptr;
    // DNS repository
    std::unique_ptr<DnsServerRepository> dhcpIpv6DnsRepository_ = nullptr;
    // Flag to track if RA flags have been queried after first global address
    std::atomic<bool> raFlagsQueried_ { false };
    // RA flags stored for reporting (M/O bits)
    std::atomic<uint8_t> raFlags_ { 0 };
    // Flag to track if valid RA has been received from current network (via RTM_NEWNDUSEROPT)
    std::atomic<bool> raReceived_ { false };
};
}  // namespace DHCP
}  // namespace OHOS

#endif
