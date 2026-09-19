/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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
#ifndef OHOS_DHCP_CLIENT_SERVICE_IMPL_H
#define OHOS_DHCP_CLIENT_SERVICE_IMPL_H

#include <map>
#include <mutex>
#include "i_dhcp_client_callback.h"
#include "dhcp_client_def.h"
#include "dhcp_client_state_machine.h"
#ifdef OHOS_ARCH_LITE
#include "dhcp_client_stub_lite.h"
#else
#include "system_ability.h"
#include "iremote_object.h"
#include "dhcp_client_stub.h"
#endif
#if DHCPV6_ENABLE
#include "dhcp_v6_callback.h"
#include "dhcp_v6_result.h"
#endif

namespace OHOS {
namespace DHCP {
enum ClientServiceRunningState { STATE_NOT_START, STATE_RUNNING };
#ifdef OHOS_ARCH_LITE
class DhcpClientServiceImpl : public DhcpClientStub {
#else
class DhcpClientServiceImpl : public SystemAbility, public DhcpClientStub {
#endif

#ifndef OHOS_ARCH_LITE
    DECLARE_SYSTEM_ABILITY(DhcpClientServiceImpl);
#endif
    
public:
    DhcpClientServiceImpl();
    virtual ~DhcpClientServiceImpl();
#ifdef OHOS_ARCH_LITE
    static std::shared_ptr<DhcpClientServiceImpl> GetInstance();
    void OnStart();
    void OnStop();
#else
    static sptr<DhcpClientServiceImpl> GetInstance();
    void OnStart() override;
    void OnStop() override;
#endif

#ifdef OHOS_ARCH_LITE
    ErrCode RegisterDhcpClientCallBack(const std::string& ifname, const std::shared_ptr<IDhcpClientCallBack> &clientCallback) override;
#else
    ErrCode RegisterDhcpClientCallBack(const std::string& ifname, const sptr<IDhcpClientCallBack> &clientCallback) override;
#endif
    ErrCode StartDhcpClient(const RouterConfig &config) override;
    ErrCode DealWifiDhcpCache(int32_t cmd, const IpCacheInfo &ipCacheInfo) override;
    ErrCode StopDhcpIpv4Client(const std::string& ifname);
    ErrCode StopDhcpIpv6Client(const std::string& ifname);
    ErrCode StopDhcpClient(const std::string& ifname, bool bIpv6, bool bIpv4 = true) override;
    ErrCode StopClientSa(void) override;
    bool IsRemoteDied(void) override;
    ErrCode StartNewIpv4Client(const RouterConfig &config, DhcpClient &dhcpClient);
    ErrCode StartNewIpv6Client(const RouterConfig &config, DhcpClient &dhcpClient);
    ErrCode StartSlaacClient(const std::string &ifname, bool bIpv6, DhcpClient &client, bool layer3 = false);
    ErrCode StartOldClient(const RouterConfig &config, DhcpClient &dhcpClient);
    ErrCode StartNewClient(const RouterConfig &config);
#if DHCPV6_ENABLE
    ErrCode StartDhcpV6ClientByRaFlags(const std::string &ifname, bool managed, bool other, DhcpClient &client);
    void OnRaFlagsChanged(const std::string &ifname, bool managed, bool other);
#endif

    int DhcpIpv4ResultSuccess(struct DhcpIpResult &ipResult);
#ifndef OHOS_ARCH_LITE
    int DhcpOfferResultSuccess(struct DhcpIpResult &ipResult);
#endif
    int DhcpIpv4ResultFail(struct DhcpIpResult &ipResult);
    int DhcpIpv4ResultTimeOut(const std::string &ifname);
    int DhcpIpv4ResultExpired(const std::string &ifname);
    int DhcpIpv6ResultTimeOut(const std::string &ifname);
    int DhcpFreeIpv6(const std::string ifname);
    void DhcpIpv6ResulCallback(const std::string ifname, DhcpIpv6Info &info);
    void FillDhcpResultFromIpv6Info(DhcpResult& result, const DhcpIpv6Info& info);
    void RemoveIpv6Results(const std::string& ifname);
#if DHCPV6_ENABLE
    void DhcpV6ResultCallback(const std::string &ifname, const DhcpV6Result &result, bool stateless);
    void DhcpV6FailCallback(const std::string &ifname, int errorCode, bool stateless);
    void DhcpV6ExpiredCallback(const std::string &ifname, bool stateless);
    void DhcpV6KernelDadCallback(const std::string &ifname, const std::string &addr, bool dadFailed);
    // Callback for address removal notification (to clear DHCPv6 cache on IPv6 self-healing)
    void OnDhcpV6AddressRemoved(const std::string &ifname, const std::string &addr);

private:
    void ReportDhcpV6FailureCallback(const std::string &ifname, int status, const char *reason);
#endif
    void GetRaFlagsFromClient(const std::string &ifname, uint8_t &raFlags);
    void PushDhcpResult(const std::string &ifname, OHOS::DHCP::DhcpResult &result);
    bool CheckDhcpResultExist(const std::string &ifname, OHOS::DHCP::DhcpResult &result);
public:
    std::mutex m_clientServiceMutex;
    std::map<std::string, DhcpClient> m_mapClientService;

    // ip result info
    std::mutex m_dhcpResultMutex;
    std::map<std::string, std::vector<DhcpResult>> m_mapDhcpResult;

    // client call back
    std::mutex m_clientCallBackMutex;
#ifdef OHOS_ARCH_LITE
    using ClientCallBackType = std::shared_ptr<IDhcpClientCallBack>;
#else
    using ClientCallBackType = sptr<IDhcpClientCallBack>;
#endif
    std::map<std::string, ClientCallBackType> m_mapClientCallBack;
private:
    bool Init();
    bool IsGlobalIPv6Address(std::string ipAddress);
#if DHCPV6_ENABLE
    void AppendDhcpV6Info(const std::string &ifname, OHOS::DHCP::DhcpResult &result);
#endif
    std::atomic<bool> mPublishFlag_;
    static std::mutex g_instanceLock;
    ClientServiceRunningState mState;
#ifdef OHOS_ARCH_LITE
    static std::shared_ptr<DhcpClientServiceImpl> g_instance;
#else
    static sptr<DhcpClientServiceImpl> g_instance;
#endif
    std::string m_bssid;

    std::mutex m_ipv6MergeMutex;
    std::map<std::string, DhcpIpv6Info> m_lastIpv6Info;
#if DHCPV6_ENABLE
    std::map<std::string, DhcpV6Result> m_lastDhcpV6;

    std::map<std::string, std::unique_ptr<IDhcpV6Callback>> m_dhcpv6Callbacks;

    // Cleanup DhcpV6Client (stop, delete, erase callbacks)
    DhcpV6Client* CleanupDhcpV6Client(const std::string &ifname, DhcpClient &client);
    // Stop DhcpV6Client (stop only, no delete)
    ErrCode StopDhcpV6Client(const std::string &ifname, DhcpClient &client);
#endif
};
}  // namespace DHCP
}  // namespace OHOS
#endif
