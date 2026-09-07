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

#include "dhcp_client_service_impl.h"
#include "dhcp_common_utils.h"
#ifndef OHOS_ARCH_LITE
#include "dhcp_client_death_recipient.h"
#endif
#include "dhcp_function.h"
#include "dhcp_define.h"
#include "dhcp_errcode.h"
#include "dhcp_logger.h"
#include "dhcp_result_store_manager.h"
#include "dhcp_permission_utils.h"
#include "parameters.h"
#if DHCPV6_ENABLE
#include "dhcp_v6_client.h"
#include "dhcp_v6_constants.h"
#include "dhcp_v6_callback_impl.h"
#endif
#ifndef OHOS_ARCH_LITE
#include "ipc_skeleton.h"
#include "netsys_controller.h"
#ifndef OHOS_EUPDATER
#include "dhcp_sa_manager.h"
#endif
#endif

DEFINE_DHCPLOG_DHCP_LABEL("DhcpClientServiceImpl");

namespace OHOS {
namespace DHCP {
namespace {
constexpr uint32_t MAX_REGISTER_CLIENT_NUM = 1000;
static bool IsDhcpV6Enabled()
{
    bool enabled = OHOS::system::GetBoolParameter("const.wifi.dhcpv6_feature_enable", false);
    DHCP_LOGI("IsDhcpV6Enabled: const.wifi.dhcpv6_feature_enable=%{public}d", enabled);
    return enabled;
}
}
std::mutex DhcpClientServiceImpl::g_instanceLock;

#ifdef OHOS_ARCH_LITE
std::shared_ptr<DhcpClientServiceImpl> DhcpClientServiceImpl::g_instance = nullptr;
std::shared_ptr<DhcpClientServiceImpl> DhcpClientServiceImpl::GetInstance()
{
    if (g_instance == nullptr) {
        std::lock_guard<std::mutex> autoLock(g_instanceLock);
        if (g_instance == nullptr) {
            std::shared_ptr<DhcpClientServiceImpl> service = std::make_shared<DhcpClientServiceImpl>();
            g_instance = service;
        }
    }
    return g_instance;
}
#else
sptr<DhcpClientServiceImpl> DhcpClientServiceImpl::g_instance = nullptr;
const bool REGISTER_RESULT = SystemAbility::MakeAndRegisterAbility(DhcpClientServiceImpl::GetInstance().GetRefPtr());
sptr<DhcpClientServiceImpl> DhcpClientServiceImpl::GetInstance()
{
    if (g_instance == nullptr) {
        std::lock_guard<std::mutex> autoLock(g_instanceLock);
        if (g_instance == nullptr) {
            DHCP_LOGI("new DhcpClientServiceImpl GetInstance()");
            sptr<DhcpClientServiceImpl> service = sptr<DhcpClientServiceImpl>::MakeSptr();
            g_instance = service;
        }
    }
    return g_instance;
}
#endif

DhcpClientServiceImpl::DhcpClientServiceImpl()
#ifndef OHOS_ARCH_LITE
    : SystemAbility(DHCP_CLIENT_ABILITY_ID, true), mPublishFlag_(false),
    mState(ClientServiceRunningState::STATE_NOT_START)
#endif
{
    DHCP_LOGI("enter DhcpClientServiceImpl()");
    {
        std::lock_guard<std::mutex> autoLock(m_clientServiceMutex);
        m_mapClientService.clear();
    }

    {
        std::lock_guard<std::mutex> autoLock(m_dhcpResultMutex);
        m_mapDhcpResult.clear();
    }

    {
        std::lock_guard<std::mutex> autoLock(m_clientCallBackMutex);
        m_mapClientCallBack.clear();
    }
    CreateDirs(DHCP_WORK_DIR.c_str(), DIR_DEFAULT_MODE);
}

DhcpClientServiceImpl::~DhcpClientServiceImpl()
{
    DHCP_LOGI("enter ~DhcpClientServiceImpl()");
    std::vector<DhcpIpv6Client*> ipv6ClientsToDelete;
#if DHCPV6_ENABLE
    std::vector<DhcpV6Client*> dhcpV6ClientsToDelete;
#endif
    {
        std::lock_guard<std::mutex> autoLock(m_clientServiceMutex);
        auto iter = m_mapClientService.begin();
        while(iter != m_mapClientService.end()) {
            if ((iter->second).pipv6Client != nullptr) {
                ipv6ClientsToDelete.push_back((iter->second).pipv6Client);
                (iter->second).pipv6Client = nullptr;
            }
            if ((iter->second).pStaStateMachine != nullptr) {
                delete (iter->second).pStaStateMachine;
                (iter->second).pStaStateMachine = nullptr;
            }
#if DHCPV6_ENABLE
            if ((iter->second).pDhcpV6Client != nullptr) {
                dhcpV6ClientsToDelete.push_back((iter->second).pDhcpV6Client);
                (iter->second).pDhcpV6Client = nullptr;
            }
#endif
            iter++;
        }
        m_mapClientService.clear();
#if DHCPV6_ENABLE
        m_dhcpv6Callbacks.clear();
#endif
    }
    
    for (auto* client : ipv6ClientsToDelete) {
        delete client;  // 析构函数会自动调用 DhcpIPV6Stop
        client = nullptr;
    }
#if DHCPV6_ENABLE
    for (auto* client : dhcpV6ClientsToDelete) {
        delete client;  // 析构函数会自动调用 DhcpV6Stop
        client = nullptr;
    }
#endif

#if DHCPV6_ENABLE
    {
        std::lock_guard<std::mutex> lock(m_ipv6MergeMutex);
        m_lastDhcpV6.clear();
        m_lastIpv6Info.clear();
    }
#endif
}

void DhcpClientServiceImpl::OnStart()
{
    DHCP_LOGI("enter Client OnStart");
    if (mState == ClientServiceRunningState::STATE_RUNNING) {
        DHCP_LOGW("Service has already started.");
        return;
    }
    if (!Init()) {
        DHCP_LOGE("Failed to init dhcp client service");
        OnStop();
        return;
    }
    mState = ClientServiceRunningState::STATE_RUNNING;
    DHCP_LOGI("Client Service has started.");
}

void DhcpClientServiceImpl::OnStop()
{
    mPublishFlag_ = false;
    DHCP_LOGI("OnStop dhcp client service!");
}

bool DhcpClientServiceImpl::Init()
{
    DHCP_LOGI("enter client Init");
    if (!mPublishFlag_.load()) {
#ifdef OHOS_ARCH_LITE
        bool ret = true;
#else
        bool ret = Publish(DhcpClientServiceImpl::GetInstance());
#endif
        if (!ret) {
            DHCP_LOGE("Failed to publish dhcp client service!");
            return false;
        }
        mPublishFlag_ = true;
    }
    return true;
}

#ifdef OHOS_ARCH_LITE
ErrCode DhcpClientServiceImpl::RegisterDhcpClientCallBack(const std::string& ifname,
    const std::shared_ptr<IDhcpClientCallBack> &clientCallback)
#else
ErrCode DhcpClientServiceImpl::RegisterDhcpClientCallBack(const std::string& ifname,
    const sptr<IDhcpClientCallBack> &clientCallback)
#endif
{
    DHCP_LOGI("[DHCP][ClientService] register callback begin, ifname:%{public}s", ifname.c_str());
    if (!DhcpPermissionUtils::VerifyIsNativeProcess()) {
        DHCP_LOGE("[DHCP][ClientService] register callback failed at native-process check, ifname:%{public}s",
            ifname.c_str());
        return DHCP_E_PERMISSION_DENIED;
    }
    if (!DhcpPermissionUtils::VerifyDhcpNetworkPermission("ohos.permission.NETWORK_DHCP")) {
        DHCP_LOGE("[DHCP][ClientService] register callback failed at NETWORK_DHCP check, ifname:%{public}s",
            ifname.c_str());
        return DHCP_E_PERMISSION_DENIED;
    }
    std::lock_guard<std::mutex> autoLock(m_clientCallBackMutex);
    auto iter = m_mapClientCallBack.find(ifname);
    if (iter != m_mapClientCallBack.end()) {
        (iter->second) = clientCallback;
        DHCP_LOGI("RegisterDhcpClientCallBack find ifname update clientCallback, ifname:%{public}s", ifname.c_str());
    } else {
        uint32_t registerNum = m_mapClientCallBack.size();
        if (registerNum > MAX_REGISTER_CLIENT_NUM) {
            DHCP_LOGE("[DHCP][ClientService] register callback failed: limit reached, ifname:%{public}s "
                "count:%{public}u", ifname.c_str(), registerNum);
            return DHCP_E_FAILED;
        }
#ifdef OHOS_ARCH_LITE
        std::shared_ptr<IDhcpClientCallBack> mclientCallback = clientCallback;
#else
        sptr<IDhcpClientCallBack> mclientCallback = clientCallback;
#endif
        m_mapClientCallBack.emplace(std::make_pair(ifname, mclientCallback));
        DHCP_LOGI("RegisterDhcpClientCallBack add ifname and mclientCallback, ifname:%{public}s", ifname.c_str());
    }
    DHCP_LOGI("[DHCP][ClientService] register callback succeeded, ifname:%{public}s", ifname.c_str());
    return DHCP_E_SUCCESS;
}

ErrCode DhcpClientServiceImpl::StartDhcpClient(const RouterConfig &config)
{
    DHCP_LOGI("[DHCP][ClientService] start begin, ifname:%{public}s ipv4:%{public}d ipv6:%{public}d "
        "static:%{public}d mode:%{public}u", config.ifname.c_str(), config.bIpv4, config.bIpv6,
        config.isStaticIpv4, static_cast<uint8_t>(config.linkMode));
    if (!DhcpPermissionUtils::VerifyIsNativeProcess()) {
        DHCP_LOGE("[DHCP][ClientService] start failed at native-process check, ifname:%{public}s",
            config.ifname.c_str());
        return DHCP_E_PERMISSION_DENIED;
    }
    if (!DhcpPermissionUtils::VerifyDhcpNetworkPermission("ohos.permission.NETWORK_DHCP")) {
        DHCP_LOGE("[DHCP][ClientService] start failed at NETWORK_DHCP check, ifname:%{public}s",
            config.ifname.c_str());
        return DHCP_E_PERMISSION_DENIED;
    }
    if (config.ifname.empty()) {
        DHCP_LOGE("[DHCP][ClientService] start failed: ifname is empty");
        return DHCP_E_FAILED;
    }
    RouterConfig innerCfg;
    innerCfg.ifname = config.ifname;
    innerCfg.bssid = config.bssid;
    innerCfg.prohibitUseCacheIp = config.prohibitUseCacheIp;
    innerCfg.bIpv6 = config.bIpv6;
    innerCfg.bSpecificNetwork = config.bSpecificNetwork;
    innerCfg.isStaticIpv4 = config.isStaticIpv4;
    innerCfg.bIpv4 = config.bIpv4;
    innerCfg.linkMode = config.linkMode;
    innerCfg.clientKey = config.clientKey;
    {
        std::lock_guard<std::mutex> autoLock(m_clientServiceMutex);
        auto iter = m_mapClientService.find(innerCfg.ifname);
        if (iter != m_mapClientService.end()) {
            ErrCode ret = StartOldClient(innerCfg, iter->second);
            DHCP_LOGI("[DHCP][ClientService] existing client start complete, ifname:%{public}s ret:%{public}d",
                innerCfg.ifname.c_str(), static_cast<int32_t>(ret));
            return ret;
        }
    }
    ErrCode ret = StartNewClient(innerCfg);
    DHCP_LOGI("[DHCP][ClientService] new client start complete, ifname:%{public}s ret:%{public}d",
        innerCfg.ifname.c_str(), static_cast<int32_t>(ret));
    return ret;
}

ErrCode DhcpClientServiceImpl::DealWifiDhcpCache(int32_t cmd, const IpCacheInfo &ipCacheInfo)
{
    DHCP_LOGI("DealWifiDhcpCache enter");
    if (!DhcpPermissionUtils::VerifyIsNativeProcess()) {
        DHCP_LOGE("DealWifiDhcpCache:NOT NATIVE PROCESS, PERMISSION_DENIED!");
        return DHCP_E_PERMISSION_DENIED;
    }
    if (!DhcpPermissionUtils::VerifyDhcpNetworkPermission("ohos.permission.SET_WIFI_CONFIG")) {
        DHCP_LOGE("DealWifiDhcpCache:VerifyDhcpNetworkPermission PERMISSION_DENIED!");
        return DHCP_E_PERMISSION_DENIED;
    }
    IpInfoCached cacheInfo;
    cacheInfo.ssid = ipCacheInfo.ssid;
    cacheInfo.bssid = ipCacheInfo.bssid;
#ifndef OHOS_ARCH_LITE
    std::function<void()> func;
    if (cmd == WIFI_DHCP_CACHE_ADD) {
        func = [cacheInfo]() { DhcpResultStoreManager::GetInstance().AddCachedIp(cacheInfo); };
    } else if (cmd == WIFI_DHCP_CACHE_REMOVE) {
        func = [cacheInfo]() { DhcpResultStoreManager::GetInstance().RemoveCachedIp(cacheInfo); };
    } else {
        return DHCP_E_FAILED;
    }
    uint32_t taskId = 0;
    DhcpTimer::GetInstance()->Register(func, taskId, 0);
    return (taskId > 0) ? DHCP_E_SUCCESS : DHCP_E_FAILED;
#else
    if (cmd == WIFI_DHCP_CACHE_ADD) {
        DhcpResultStoreManager::GetInstance().AddCachedIp(cacheInfo);
    } else if (cmd == WIFI_DHCP_CACHE_REMOVE) {
        DhcpResultStoreManager::GetInstance().RemoveCachedIp(cacheInfo);
    }
    return DHCP_E_SUCCESS;
#endif
}

ErrCode DhcpClientServiceImpl::StartOldClient(const RouterConfig &config, DhcpClient &dhcpClient)
{
    DHCP_LOGI("StartOldClient ifname:%{public}s bIpv6:%{public}d", config.ifname.c_str(), config.bIpv6);
    ErrCode ret = DHCP_E_SUCCESS;
    const std::string ifname = config.ifname;
    if (config.bIpv6) {
        if (dhcpClient.pipv6Client == nullptr) {
            ret = StartNewIpv6Client(config, dhcpClient);
        } else {
#ifndef OHOS_ARCH_LITE
            NetManagerStandard::NetsysController::GetInstance().SetIpv6PrivacyExtensions(ifname, DHCP_IPV6_ENABLE);
            NetManagerStandard::NetsysController::GetInstance().SetEnableIpv6(ifname, DHCP_IPV6_ENABLE);
#endif
            ret = StartSlaacClient(ifname, config.bIpv6, dhcpClient);
        }
    }
    if (ret != DHCP_E_SUCCESS) {
        return ret;
    }
    if (config.bIpv4) {
        if (dhcpClient.pStaStateMachine == nullptr) {
            ret = StartNewIpv4Client(config, dhcpClient);
        } else {
            dhcpClient.pStaStateMachine->SetConfiguration(config);
            if (!config.isStaticIpv4) {
                int startRet = dhcpClient.pStaStateMachine->StartIpv4Type(ifname, config.bIpv6, ACTION_START_OLD);
                if (startRet != DHCP_OPT_SUCCESS) {
                    DHCP_LOGE("[DHCP][ClientService] existing IPv4 state machine start failed, ifname:%{public}s "
                        "ret:%{public}d", ifname.c_str(), startRet);
                    return DHCP_E_FAILED;
                }
            }
        }
    }
    if (ret != DHCP_E_SUCCESS) {
        return ret;
    }
    return DHCP_E_SUCCESS;
}

ErrCode DhcpClientServiceImpl::StartNewIpv4Client(const RouterConfig &config, DhcpClient &client)
{
    DHCP_LOGI("StartNewIpv4Client ifname:%{public}s", config.ifname.c_str());
    const std::string ifname = config.ifname;
    DhcpClientStateMachine *pStaState = new (std::nothrow)DhcpClientStateMachine(ifname);
    if (pStaState == nullptr) {
    DHCP_LOGI("StartNewIpv4Client ifname:%{public}s", config.ifname.c_str());
        DHCP_LOGE("StartNewIpv4Client new DhcpClientStateMachine failed!, ifname:%{public}s", ifname.c_str());
        return DHCP_E_FAILED;
    }
    client.pStaStateMachine = pStaState;
    pStaState->SetConfiguration(config);
    if (!config.isStaticIpv4) {
        int startRet = pStaState->StartIpv4Type(ifname, config.bIpv6, ACTION_START_NEW);
        if (startRet != DHCP_OPT_SUCCESS) {
            DHCP_LOGE("[DHCP][ClientService] new IPv4 state machine start failed, ifname:%{public}s ret:%{public}d",
                ifname.c_str(), startRet);
            delete pStaState;
            client.pStaStateMachine = nullptr;
            return DHCP_E_FAILED;
        }
    }
    DHCP_LOGI("[DHCP][ClientService] IPv4 state machine started, ifname:%{public}s mode:%{public}u", ifname.c_str(),
        static_cast<uint8_t>(config.linkMode));
    return DHCP_E_SUCCESS;
}

// Note: In this file, "ipv6" prefix refers to SLAAC (Stateless Address Autoconfiguration),
// while "dhcpv6" prefix refers to DHCPv6 (Stateful DHCPv6).
ErrCode DhcpClientServiceImpl::StartSlaacClient(const std::string &ifname, bool bIpv6, DhcpClient &client)
{
    if (client.pipv6Client == nullptr) {
        client.pipv6Client = new (std::nothrow)DhcpIpv6Client(ifname);
        if (client.pipv6Client == nullptr) {
            DHCP_LOGE("StartSlaacClient: new DhcpIpv6Client failed!, ifname:%{public}s", ifname.c_str());
            return DHCP_E_FAILED;
        }
        DHCP_LOGI("StartSlaacClient: new SLAAC client, ifname:%{public}s", ifname.c_str());
    } else {
        DHCP_LOGI("StartSlaacClient: stop and restart SLAAC client, ifname:%{public}s", ifname.c_str());
#if DHCPV6_ENABLE
        client.pipv6Client->UnRegisterDhcpV6Callbacks();
#endif
        client.pipv6Client->DhcpIPV6Stop();
        client.pipv6Client->Reset();
    }

    client.pipv6Client->SetCallback(
        [this](const std::string ifname, DhcpIpv6Info &info) { this->DhcpIpv6ResulCallback(ifname, info); });
#if DHCPV6_ENABLE
    // Set callback for RA flags change to dynamically manage DHCPv6 client
    client.pipv6Client->SetRaFlagsCallback(
        [this](const std::string ifname, bool managed, bool other) {
            this->OnRaFlagsChanged(ifname, managed, other);
        });
    // Set callback for kernel DAD result notification
    client.pipv6Client->SetDadResultCallback(
        [this](const std::string ifname, const std::string addr, bool isTentative) {
            // isTentative=true means DAD failure (tentative address deleted during DAD detection)
            this->DhcpV6KernelDadCallback(ifname, addr, isTentative);
        });
    // Set callback for address removal notification (to clear DHCPv6 cache on IPv6 self-healing)
    client.pipv6Client->SetAddrRemovedCallback(
        [this](const std::string ifname, const std::string addr) {
            this->OnDhcpV6AddressRemoved(ifname, addr);
        });
    // Set direct reference to DHCPv6 client for address type checking
    // This allows SLAAC to recognize DHCPv6 addresses and classify them as GLOBAL
    client.pipv6Client->SetDhcpV6Client(client.pDhcpV6Client);
#endif
    client.pipv6Client->StartIpv6Thread(ifname, bIpv6);
    return DHCP_E_SUCCESS;
}

#if DHCPV6_ENABLE
// Start DHCPv6 client based on RA flags (M/O bits)
// M=1: Use DHCPv6 (stateful)
// M=0, O=1: Use DHCPv6 for information only (stateless)
// M=0, O=0: Use SLAAC only, stop DHCPv6
ErrCode DhcpClientServiceImpl::StartDhcpV6ClientByRaFlags(const std::string &ifname,
    bool managed, bool other, DhcpClient &client)
{
    if (!managed && !other) {
        DHCP_LOGI("StartDhcpV6ClientByRaFlags: M=0 O=0, stop DHCPv6, ifname:%{public}s", ifname.c_str());
        return StopDhcpV6Client(ifname, client);
    }

    bool stateless = (!managed) && other;
    DHCP_LOGI("StartDhcpV6ClientByRaFlags: starting DHCPv6, ifname:%{public}s stateless:%{public}d",
        ifname.c_str(), stateless);

    DhcpV6Client* existingClient = nullptr;
    {
        std::lock_guard<std::mutex> lock(m_clientServiceMutex);
        existingClient = client.pDhcpV6Client;
        if (existingClient != nullptr) {
            client.pDhcpV6Client = nullptr;
            m_dhcpv6Callbacks.erase(ifname);
        }
    }
    if (existingClient != nullptr) {
        existingClient->DhcpV6Stop();
        delete existingClient;
    }

    DhcpV6Client* newV6Client = new (std::nothrow)DhcpV6Client(ifname);
    if (newV6Client == nullptr) {
        DHCP_LOGE("StartDhcpV6ClientByRaFlags: new DhcpV6Client failed!, ifname:%{public}s", ifname.c_str());
        return DHCP_E_FAILED;
    }

    auto cb = std::make_unique<DhcpV6CallbackImpl>(this, ifname, stateless);
    newV6Client->DhcpV6RegisterCallback(cb.get());

    {
        std::lock_guard<std::mutex> lock(m_clientServiceMutex);
        client.pDhcpV6Client = newV6Client;
        if (client.pipv6Client != nullptr) {
            client.pipv6Client->SetDhcpV6Client(newV6Client);
        }
        m_dhcpv6Callbacks[ifname] = std::move(cb);
    }

    newV6Client->DhcpV6ConfigureStateless(stateless);
    newV6Client->DhcpV6Start();
    return DHCP_E_SUCCESS;
}

ErrCode DhcpClientServiceImpl::StopDhcpV6Client(const std::string &ifname, DhcpClient &client)
{
    DhcpV6Client* toStop = nullptr;
    {
        std::lock_guard<std::mutex> lock(m_clientServiceMutex);
        toStop = CleanupDhcpV6Client(ifname, client);
        if (client.pipv6Client != nullptr) {
            client.pipv6Client->SetDhcpV6Client(nullptr);
        }
    }
    if (toStop != nullptr) {
        toStop->DhcpV6Stop();
        delete toStop;
    }
    {
        std::lock_guard<std::mutex> lock(m_ipv6MergeMutex);
        m_lastDhcpV6.erase(ifname);
    }
    return DHCP_E_SUCCESS;
}

void DhcpClientServiceImpl::OnRaFlagsChanged(const std::string &ifname, bool managed, bool other)
{
    DHCP_LOGI("OnRaFlagsChanged: ifname=%{public}s M=%{public}d O=%{public}d", ifname.c_str(), managed, other);

    DhcpClient* pClient = nullptr;
    uint8_t prevFlags = 0;
    {
        std::lock_guard<std::mutex> autoLock(m_clientServiceMutex);
        auto iter = m_mapClientService.find(ifname);
        if (iter == m_mapClientService.end()) {
            DHCP_LOGW("OnRaFlagsChanged: client not found, ifname=%{public}s", ifname.c_str());
            return;
        }
        DhcpClient &client = iter->second;
        pClient = &client;
        if (client.pipv6Client != nullptr) {
            client.pipv6Client->GetRaFlags(prevFlags);
        }
    }

    uint8_t currentFlags = (managed ? RA_FLAG_MANAGED_MASK : 0) | (other ? RA_FLAG_OTHER_MASK : 0);
    if (currentFlags == prevFlags) {
        DHCP_LOGI("OnRaFlagsChanged: RA flags unchanged (0x%{public}x), skip restart", currentFlags);
        return;
    }
    if (IsDhcpV6Enabled()) {
        if (managed || other) {
            DHCP_LOGI("OnRaFlagsChanged: M=%{public}d O=%{public}d, starting DHCPv6, ifname=%{public}s",
                managed, other, ifname.c_str());
        } else {
            DHCP_LOGI("OnRaFlagsChanged: M=0 O=0, SLAAC only, stopping DHCPv6, ifname=%{public}s", ifname.c_str());
        }
        StartDhcpV6ClientByRaFlags(ifname, managed, other, *pClient);
    }
}
#endif // DHCPV6_ENABLE

ErrCode DhcpClientServiceImpl::StartNewIpv6Client(const RouterConfig &config, DhcpClient &client)
{
    DHCP_LOGI("StartNewIpv6Client ifname=%{public}s", config.ifname.c_str());
    const std::string ifname = config.ifname;

#ifndef OHOS_ARCH_LITE
    // Enable IPv6
    NetManagerStandard::NetsysController::GetInstance().SetIpv6PrivacyExtensions(ifname, DHCP_IPV6_ENABLE);
    NetManagerStandard::NetsysController::GetInstance().SetEnableIpv6(ifname, DHCP_IPV6_ENABLE);

    // Start SLAAC client - M/O will be retrieved via RTM_GETLINK/RTM_NEWLINK
    // DHCPv6 client will be started/stopped dynamically based on M/O changes
    return StartSlaacClient(ifname, config.bIpv6, client);
#else
    // OHOS_ARCH_LITE version - always use SLAAC (no RA-based decision)
    DhcpIpv6Client *pipv6Client = new (std::nothrow)DhcpIpv6Client(ifname);
    if (pipv6Client == nullptr) {
        DHCP_LOGE("StartNewIpv6Client new DhcpIpv6Client failed!, ifname:%{public}s", ifname.c_str());
        return DHCP_E_FAILED;
    }
    client.pipv6Client = pipv6Client;
    DHCP_LOGI("StartNewIpv6Client new DhcpIpv6Client, ifname:%{public}s, bIpv6:%{public}d", ifname.c_str(),
        config.bIpv6);
    pipv6Client->Reset();
    pipv6Client->SetCallback(
        [this](const std::string ifname, DhcpIpv6Info &info) { this->DhcpIpv6ResulCallback(ifname, info); });
    pipv6Client->StartIpv6Thread(ifname, config.bIpv6);
    return DHCP_E_SUCCESS;
#endif
}


ErrCode DhcpClientServiceImpl::StartNewClient(const RouterConfig &config)
{
    DHCP_LOGI("StartNewClient ifname:%{public}s, bIpv6:%{public}d", config.ifname.c_str(), config.bIpv6);
    DhcpClient client;
    ErrCode ret = DHCP_E_SUCCESS;
    const std::string ifname = config.ifname;
    if (config.bIpv6) {
        client.isIpv6 = config.bIpv6;
        ret = StartNewIpv6Client(config, client);
    }
    if (ret != DHCP_E_SUCCESS) {
        return ret;
    }
    if (config.bIpv4) {
        ret = StartNewIpv4Client(config, client);
    }
    if (ret != DHCP_E_SUCCESS) {
        return ret;
    }
    client.ifName = ifname;
    {
        std::lock_guard<std::mutex> autoLock(m_clientServiceMutex);
        m_mapClientService.emplace(std::make_pair(ifname, client));
    }
    return DHCP_E_SUCCESS;
}


ErrCode DhcpClientServiceImpl::StopDhcpIpv4Client(const std::string& ifname)
{
    {
        std::lock_guard<std::mutex> autoLock(m_clientServiceMutex);
        auto iter2 = m_mapClientService.find(ifname);
        if (iter2 != m_mapClientService.end()) {
            if ((iter2->second).pStaStateMachine != nullptr) {
                DHCP_LOGI("StopDhcpClient pStaStateMachine StopIpv4Type, ifname:%{public}s", ifname.c_str());
                (iter2->second).pStaStateMachine->StopIpv4Type();
            }
        }
    }
    {
        std::lock_guard<std::mutex> autoLock(m_dhcpResultMutex);
        auto iter = m_mapDhcpResult.find(ifname);
        if (iter != m_mapDhcpResult.end()) {
            DHCP_LOGI("m_mapDhcpResult erase ifName:%{public}s", ifname.c_str());
            for (auto result = iter->second.begin(); result != iter->second.end();) {
                if (result->iptype == 0) {
                    result = iter->second.erase(result);
                } else {
                    result ++;
                }
            }
            if (iter->second.empty()) {
                m_mapDhcpResult.erase(iter);
            }
        }
    }
    return DHCP_E_SUCCESS;
}

void DhcpClientServiceImpl::RemoveIpv6Results(const std::string& ifname)
{
    std::lock_guard<std::mutex> autoLock(m_dhcpResultMutex);
    auto iter = m_mapDhcpResult.find(ifname);
    if (iter == m_mapDhcpResult.end()) {
        return;
    }
    for (auto result = iter->second.begin(); result != iter->second.end();) {
        if (result->iptype == 1) {
            result = iter->second.erase(result);
        } else {
            ++result;
        }
    }
    if (iter->second.empty()) {
        m_mapDhcpResult.erase(iter);
    }
}

ErrCode DhcpClientServiceImpl::StopDhcpIpv6Client(const std::string& ifname)
{
    {
        std::lock_guard<std::mutex> autoLock(m_clientCallBackMutex);
        auto iter = m_mapClientCallBack.find(ifname);
        if (iter != m_mapClientCallBack.end()) {
            m_mapClientCallBack.erase(iter);
        }
    }

#if DHCPV6_ENABLE
    DhcpIpv6Client* pipv6ClientToStop = nullptr;
    DhcpV6Client* pDhcpV6ClientToStop = nullptr;
    {
        std::lock_guard<std::mutex> autoLock(m_clientServiceMutex);
        auto iter = m_mapClientService.find(ifname);
        if (iter != m_mapClientService.end()) {
            if (iter->second.pipv6Client != nullptr) {
                pipv6ClientToStop = iter->second.pipv6Client;
#ifndef OHOS_ARCH_LITE
                NetManagerStandard::NetsysController::GetInstance().SetEnableIpv6(ifname, DHCP_IPV6_DISENABLE);
#endif
            }
            pDhcpV6ClientToStop = CleanupDhcpV6Client(ifname, iter->second);
            if (iter->second.pipv6Client != nullptr) {
                iter->second.pipv6Client->ResetRaFlags();
            }
        }
    }

    if (pipv6ClientToStop != nullptr) {
        DHCP_LOGI("StopDhcpClient pipv6Client DhcpIPV6Stop, ifname:%{public}s", ifname.c_str());
        pipv6ClientToStop->DhcpIPV6Stop();
    }
    if (pDhcpV6ClientToStop != nullptr) {
        pDhcpV6ClientToStop->DhcpV6Stop();
        delete pDhcpV6ClientToStop;
        pDhcpV6ClientToStop = nullptr;
    }

    {
        std::lock_guard<std::mutex> lock(m_ipv6MergeMutex);
        m_lastDhcpV6.erase(ifname);
    }
#endif

#ifndef OHOS_ARCH_LITE
    {
        std::lock_guard<std::mutex> lock(m_ipv6MergeMutex);
        m_lastIpv6Info.erase(ifname);
    }
#endif

    RemoveIpv6Results(ifname);
    return DHCP_E_SUCCESS;
}

ErrCode DhcpClientServiceImpl::StopDhcpClient(const std::string& ifname, bool bIpv6, bool bIpv4)
{
    DHCP_LOGI("StopDhcpClient ifName:%{public}s, bIpv6:%{public}d, bIpv4:%{public}d", ifname.c_str(), bIpv6, bIpv4);
    if (!DhcpPermissionUtils::VerifyIsNativeProcess()) {
        DHCP_LOGE("StopDhcpClient:NOT NATIVE PROCESS, PERMISSION_DENIED!");
        return DHCP_E_PERMISSION_DENIED;
    }
    if (!DhcpPermissionUtils::VerifyDhcpNetworkPermission("ohos.permission.NETWORK_DHCP")) {
        DHCP_LOGE("StopDhcpClient:VerifyDhcpNetworkPermission PERMISSION_DENIED!");
        return DHCP_E_PERMISSION_DENIED;
    }
    if (ifname.empty()) {
        DHCP_LOGE("StopDhcpClient ifname is empty!");
        return DHCP_E_FAILED;
    }
    if (bIpv6) {
        StopDhcpIpv6Client(ifname);
    }
    if (bIpv4) {
        StopDhcpIpv4Client(ifname);
    }

    return DHCP_E_SUCCESS;
}

ErrCode DhcpClientServiceImpl::StopClientSa(void)
{
    if (!DhcpPermissionUtils::VerifyIsNativeProcess()) {
        DHCP_LOGE("StopDhcpClient:NOT NATIVE PROCESS, PERMISSION_DENIED!");
        return DHCP_E_PERMISSION_DENIED;
    }
    if (!DhcpPermissionUtils::VerifyDhcpNetworkPermission("ohos.permission.NETWORK_DHCP")) {
        DHCP_LOGE("StopClientSa:VerifyDhcpNetworkPermission PERMISSION_DENIED!");
        return DHCP_E_PERMISSION_DENIED;
    }
#ifdef OHOS_ARCH_LITE
    return DHCP_E_SUCCESS;
#else
#ifndef OHOS_EUPDATER
    return DhcpSaLoadManager::GetInstance().UnloadWifiSa(DHCP_CLIENT_ABILITY_ID);
#else
    return DHCP_E_SUCCESS;
#endif
#endif
}

int DhcpClientServiceImpl::DhcpIpv4ResultSuccess(struct DhcpIpResult &ipResult)
{
    std::string ifname = ipResult.ifname;
    DHCP_LOGI("[DHCP][ClientService] IPv4 success result received, ifname:%{public}s", ifname.c_str());
    OHOS::DHCP::DhcpResult result;
    result.iptype = 0;
    result.isOptSuc = true;
    result.uGetTime = (uint32_t)time(NULL);
    result.uAddTime = ipResult.uAddTime;
    result.uLeaseTime = ipResult.uOptLeasetime;
    result.strYourCli = ipResult.strYiaddr;
    result.strServer = ipResult.strOptServerId;
    result.strSubnet = ipResult.strOptSubnet;
    result.strDns1 = ipResult.strOptDns1;
    result.strDns2 = ipResult.strOptDns2;
    result.strRouter1 = ipResult.strOptRouter1;
    result.strRouter2 = ipResult.strOptRouter2;
    result.strVendor = ipResult.strOptVendor;
    for (std::vector<std::string>::iterator it = ipResult.dnsAddr.begin(); it != ipResult.dnsAddr.end(); it++) {
        result.vectorDnsAddr.push_back(*it);
    }
    DHCP_LOGI("DhcpIpv4ResultSuccess %{public}s, %{public}d, opt:%{public}d, cli:%{private}s, server:%{private}s, "
        "Subnet:%{private}s, Dns1:%{private}s, Dns2:%{private}s, Router1:%{private}s, Router2:%{private}s, "
        "strVendor:%{public}s, uLeaseTime:%{public}u, uAddTime:%{public}u, uGetTime:%{public}u.",
        ifname.c_str(), result.iptype, result.isOptSuc, result.strYourCli.c_str(), result.strServer.c_str(),
        result.strSubnet.c_str(), result.strDns1.c_str(), result.strDns2.c_str(), result.strRouter1.c_str(),
        result.strRouter2.c_str(), result.strVendor.c_str(), result.uLeaseTime, result.uAddTime, result.uGetTime);
    
    std::lock_guard<std::mutex> autoLock(m_clientCallBackMutex);
    auto iter = m_mapClientCallBack.find(ifname);
    if (iter == m_mapClientCallBack.end()) {
        DHCP_LOGE("[DHCP][ClientService] success result exit: callback not found, ifname:%{public}s", ifname.c_str());
        return DHCP_OPT_FAILED;
    }
    if ((iter->second) == nullptr) {
        DHCP_LOGE("[DHCP][ClientService] success result exit: callback is null, ifname:%{public}s", ifname.c_str());
        return DHCP_OPT_FAILED;
    }
    if (CheckDhcpResultExist(ifname, result)) {
        DHCP_LOGI("DhcpIpv4ResultSuccess DhcpResult %{public}s equal new addtime %{public}u, no need update.",
            ifname.c_str(), result.uAddTime);
        return DHCP_OPT_SUCCESS;
    }
    PushDhcpResult(ifname, result);
    (iter->second)->OnIpSuccessChanged(DHCP_OPT_SUCCESS, ifname, result);
    DHCP_LOGI("[DHCP][ClientService] IPv4 success callback dispatched, ifname:%{public}s", ifname.c_str());
    return DHCP_OPT_SUCCESS;
}
#ifndef OHOS_ARCH_LITE
int DhcpClientServiceImpl::DhcpOfferResultSuccess(struct DhcpIpResult &ipResult)
{
    std::string ifname = ipResult.ifname;
    OHOS::DHCP::DhcpResult result;
    result.iptype = 0;
    result.isOptSuc = true;
    result.uGetTime = static_cast<uint32_t>(time(NULL));
    result.uAddTime = ipResult.uAddTime;
    result.uLeaseTime = ipResult.uOptLeasetime;
    result.strYourCli = ipResult.strYiaddr;
    result.strServer = ipResult.strOptServerId;
    result.strSubnet = ipResult.strOptSubnet;
    result.strDns1 = ipResult.strOptDns1;
    result.strDns2 = ipResult.strOptDns2;
    result.strRouter1 = ipResult.strOptRouter1;
    result.strRouter2 = ipResult.strOptRouter2;
    result.strVendor = ipResult.strOptVendor;
    for (std::vector<std::string>::iterator it = ipResult.dnsAddr.begin(); it != ipResult.dnsAddr.end(); it++) {
        result.vectorDnsAddr.push_back(*it);
    }

    std::lock_guard<std::mutex> autoLock(m_clientCallBackMutex);
    auto iter = m_mapClientCallBack.find(ifname);
    if (iter == m_mapClientCallBack.end()) {
        DHCP_LOGE("OnDhcpOfferReport m_mapClientCallBack not find callback!");
        return DHCP_OPT_FAILED;
    }
    if ((iter->second) == nullptr) {
        DHCP_LOGE("OnDhcpOfferReport mclientCallback is nullptr!");
        return DHCP_OPT_FAILED;
    }
    (iter->second)->OnDhcpOfferReport(0, ifname, result);
    return DHCP_OPT_SUCCESS;
}
#endif
int DhcpClientServiceImpl::DhcpIpv4ResultFail(struct DhcpIpResult &ipResult)
{
    std::string ifname = ipResult.ifname;
    OHOS::DHCP::DhcpResult result;
    result.iptype = 0;
    result.isOptSuc = false;
    result.uGetTime = (uint32_t)time(NULL);
    result.uAddTime = ipResult.uAddTime;

    DHCP_LOGE("[DHCP][ClientService] IPv4 failure result received, ifname:%{public}s", ifname.c_str());
    ActionMode action = ACTION_INVALID;
    {
        std::lock_guard<std::mutex> autoLock(m_clientServiceMutex);
        auto iterlient = m_mapClientService.find(ifname);
        if (iterlient != m_mapClientService.end() && ((iterlient->second).pStaStateMachine != nullptr)) {
            action = (iterlient->second).pStaStateMachine->GetAction();
        }
    }
    std::lock_guard<std::mutex> autoLock(m_clientCallBackMutex);
    auto iter = m_mapClientCallBack.find(ifname);
    if (iter == m_mapClientCallBack.end()) {
        DHCP_LOGE("[DHCP][ClientService] failure result exit: callback not found, ifname:%{public}s", ifname.c_str());
        return DHCP_OPT_FAILED;
    }
    if ((iter->second) == nullptr) {
        DHCP_LOGE("[DHCP][ClientService] failure result exit: callback is null, ifname:%{public}s", ifname.c_str());
        return DHCP_OPT_FAILED;
    }
    PushDhcpResult(ifname, result);
    if ((action == ACTION_RENEW_T1) || (action == ACTION_RENEW_T2) || (action == ACTION_RENEW_T3)) {
        (iter->second)->OnIpFailChanged(DHCP_OPT_RENEW_FAILED, ifname.c_str(), "get dhcp renew result failed!");
    } else {
        (iter->second)->OnIpFailChanged(DHCP_OPT_FAILED, ifname.c_str(), "get dhcp ip result failed!");
    }
    DHCP_LOGI("[DHCP][ClientService] IPv4 failure callback dispatched, ifname:%{public}s action:%{public}d",
        ifname.c_str(), action);
    return DHCP_OPT_SUCCESS;
}

int DhcpClientServiceImpl::DhcpIpv4ResultTimeOut(const std::string &ifname)
{
    DHCP_LOGE("[DHCP][ClientService] IPv4 acquisition timed out, ifname:%{public}s", ifname.c_str());
    ActionMode action = ACTION_INVALID;
    {
        std::lock_guard<std::mutex> autoLock(m_clientServiceMutex);
        auto iterlient = m_mapClientService.find(ifname);
        if (iterlient != m_mapClientService.end() && ((iterlient->second).pStaStateMachine != nullptr)) {
            action = (iterlient->second).pStaStateMachine->GetAction();
        }
    }
    std::lock_guard<std::mutex> autoLock(m_clientCallBackMutex);
    auto iter = m_mapClientCallBack.find(ifname);
    if (iter == m_mapClientCallBack.end()) {
        DHCP_LOGE("DhcpIpv4ResultTimeOut m_mapClientCallBack not find callback!");
        return DHCP_OPT_FAILED;
    }
    if ((iter->second) == nullptr) {
        DHCP_LOGE("DhcpIpv4ResultTimeOut mclientCallback == nullptr!");
        return DHCP_OPT_FAILED;
    }
    if ((action == ACTION_RENEW_T1) || (action == ACTION_RENEW_T2) || (action == ACTION_RENEW_T3)) {
        (iter->second)->OnIpFailChanged(DHCP_OPT_RENEW_TIMEOUT, ifname.c_str(), "get dhcp renew result timeout!");
    } else {
        (iter->second)->OnIpFailChanged(DHCP_OPT_TIMEOUT, ifname.c_str(), "get dhcp result timeout!");
    }
    DHCP_LOGI("DhcpIpv4ResultTimeOut OnIpFailChanged Timeout!, action:%{public}d", action);
    return DHCP_OPT_SUCCESS;
}

int DhcpClientServiceImpl::DhcpIpv4ResultExpired(const std::string &ifname)
{
    DHCP_LOGI("DhcpIpv4ResultExpired ifname:%{public}s", ifname.c_str());
    std::lock_guard<std::mutex> autoLock(m_clientCallBackMutex);
    auto iter = m_mapClientCallBack.find(ifname);
    if (iter == m_mapClientCallBack.end()) {
        DHCP_LOGE("DhcpIpv4ResultExpired not find ifname callback!");
        return DHCP_OPT_FAILED;
    }
    if ((iter->second) == nullptr) {
        DHCP_LOGE("DhcpIpv4ResultExpired callback is nullptr!");
        return DHCP_OPT_FAILED;
    }
    (iter->second)->OnIpFailChanged(DHCP_OPT_LEASE_EXPIRED, ifname.c_str(), "ifname ip lease expired!");
    DHCP_LOGI("DhcpIpv4ResultExpired OnIpFailChanged Lease Expired!");
    return DHCP_OPT_SUCCESS;
}

void DhcpClientServiceImpl::FillDhcpResultFromIpv6Info(DhcpResult& result, const DhcpIpv6Info& info)
{
    result.uAddTime = (uint32_t)time(NULL);
    result.iptype = 1;
    result.isOptSuc = true;
    result.uGetTime = (uint32_t)time(NULL);
    result.strYourCli = info.globalIpv6Addr;
    result.strSubnet = info.ipv6SubnetAddr;
    result.strRouter1 = info.routeAddr;
    result.strDns1 = info.dnsAddr;
    result.strDns2 = info.dnsAddr2;
    result.strRouter2 = "*";
    result.strLinkIpv6Addr = info.linkIpv6Addr;
    result.strRandIpv6Addr = info.randIpv6Addr;
    result.strLocalAddr1 = info.uniqueLocalAddr1;
    result.strLocalAddr2 = info.uniqueLocalAddr2;
    result.validLifetime = info.validLifetime;
    result.preferredLifetime = info.preferredLifetime;
    result.routeLifetime = info.routeLifetime;
    for (const auto &kv : info.IpAddrMap) {
        result.IpAddrMap[kv.first] = kv.second;
    }
    for (auto dnsAddr : info.vectorDnsAddr) {
        result.vectorDnsAddr.push_back(dnsAddr);
    }
    result.raFlags = info.raFlags;
}

void DhcpClientServiceImpl::DhcpIpv6ResulCallback(const std::string ifname, DhcpIpv6Info& info)
{
    OHOS::DHCP::DhcpResult result;
    // Get RA flags
    {
        std::lock_guard<std::mutex> autoLock(m_clientServiceMutex);
        auto iter = m_mapClientService.find(ifname);
        if (iter != m_mapClientService.end() && iter->second.pipv6Client != nullptr) {
            iter->second.pipv6Client->GetRaFlags(info.raFlags);
        }
    }
    {
        std::lock_guard<std::mutex> lock(m_ipv6MergeMutex);
        m_lastIpv6Info[ifname] = info;
    }
    FillDhcpResultFromIpv6Info(result, info);
#if DHCPV6_ENABLE
    AppendDhcpV6Info(ifname, result);
#endif
    DHCP_LOGI("DhcpIpv6ResulCallback %{public}s, %{public}d, opt:%{public}d, cli:%{public}s, server:%{public}s, "
        "Subnet:%{public}s, Dns1:%{public}s, Dns2:%{public}s, Router1:%{public}s, Router2:%{public}s, "
        "strVendor:%{public}s, strLinkIpv6Addr:%{public}s, strRandIpv6Addr:%{public}s, uLeaseTime:%{public}u, "
        "uAddTime:%{public}u, uGetTime:%{public}u.",
        ifname.c_str(), result.iptype, result.isOptSuc, Ipv6Anonymize(result.strYourCli).c_str(),
        Ipv6Anonymize(result.strServer).c_str(), Ipv6Anonymize(result.strSubnet).c_str(),
        Ipv6Anonymize(result.strDns1).c_str(), Ipv6Anonymize(result.strDns2).c_str(),
        Ipv6Anonymize(result.strRouter1).c_str(), Ipv6Anonymize(result.strRouter2).c_str(),
        Ipv6Anonymize(result.strVendor).c_str(), Ipv6Anonymize(result.strLinkIpv6Addr).c_str(),
        Ipv6Anonymize(result.strRandIpv6Addr).c_str(), result.uLeaseTime, result.uAddTime, result.uGetTime);
    ClientCallBackType callbackCopy;
    {
        std::lock_guard<std::mutex> autoLock(m_clientCallBackMutex);
        auto iter = m_mapClientCallBack.find(ifname);
        if (iter == m_mapClientCallBack.end()) {
            DHCP_LOGE("DhcpIpv6ResulCallback m_mapClientCallBack not find callback!");
            return;
        }
        if (iter->second == nullptr) {
            DHCP_LOGE("DhcpIpv6ResulCallback mclientCallback == nullptr!");
            return;
        }
        callbackCopy = iter->second;
        PushDhcpResult(ifname, result);
    }
    callbackCopy->OnIpSuccessChanged(PUBLISH_CODE_SUCCESS, ifname, result);
}

#if DHCPV6_ENABLE
void DhcpClientServiceImpl::AppendDhcpV6Info(const std::string &ifname, OHOS::DHCP::DhcpResult &result)
{
    std::lock_guard<std::mutex> lock(m_ipv6MergeMutex);
    auto iter = m_lastDhcpV6.find(ifname);
    if (iter == m_lastDhcpV6.end() || !iter->second.ready) {
        return;
    }
    const auto &v6 = iter->second;

    // Add DHCPv6 addresses with GLOBAL type for consistent handling with SLAAC
    for (const auto &addr : v6.ipv6Addresses) {
        if (!addr.empty() && result.IpAddrMap.find(addr) == result.IpAddrMap.end()) {
            result.IpAddrMap[addr] = static_cast<int>(AddrType::GLOBAL);
            if (result.strYourCli.empty()) {
                result.strYourCli = addr;
            }
        }
    }
    // Add DHCPv6 DNS servers
    for (const auto &dns : v6.dnsServers) {
        if (!dns.empty() &&
            std::find(result.vectorDnsAddr.begin(), result.vectorDnsAddr.end(), dns) ==
            result.vectorDnsAddr.end()) {
            result.vectorDnsAddr.push_back(dns);
        }
    }
    // Use SLAAC lifetimes first; fallback to DHCPv6 only when SLAAC has no lifetimes
    if (result.validLifetime == 0 && v6.validLifetime != 0) {
        result.validLifetime = v6.validLifetime;
    }
    if (result.preferredLifetime == 0 && v6.preferredLifetime != 0) {
        result.preferredLifetime = v6.preferredLifetime;
    }
}

DhcpV6Client* DhcpClientServiceImpl::CleanupDhcpV6Client(const std::string &ifname, DhcpClient &client)
{
    DhcpV6Client* toStop = client.pDhcpV6Client;
    client.pDhcpV6Client = nullptr;
    m_dhcpv6Callbacks.erase(ifname);
    return toStop;
}
#endif // DHCPV6_ENABLE

int DhcpClientServiceImpl::DhcpIpv6ResultTimeOut(const std::string &ifname)
{
    DHCP_LOGI("DhcpIpv6ResultTimeOut ifname:%{public}s", ifname.c_str());
    DhcpFreeIpv6(ifname);
    return DHCP_OPT_SUCCESS;
}

int DhcpClientServiceImpl::DhcpFreeIpv6(const std::string ifname)
{
    DHCP_LOGI("DhcpFreeIpv6 ifname:%{public}s", ifname.c_str());
    DhcpIpv6Client* pipv6ClientToStop = nullptr;
#if DHCPV6_ENABLE
    DhcpV6Client* pDhcpV6ClientToStop = nullptr;
#endif
    {
        std::lock_guard<std::mutex> autoLockServer(m_clientServiceMutex);
        auto iter = m_mapClientService.find(ifname);
        if (iter != m_mapClientService.end()) {
            if ((iter->second).pipv6Client != nullptr) {
                pipv6ClientToStop = (iter->second).pipv6Client;
            }
#if DHCPV6_ENABLE
            pDhcpV6ClientToStop = CleanupDhcpV6Client(ifname, iter->second);
#endif
        }
    }
    
    if (pipv6ClientToStop != nullptr) {
        pipv6ClientToStop->DhcpIPV6Stop();
    }
#if DHCPV6_ENABLE
    if (pDhcpV6ClientToStop != nullptr) {
        pDhcpV6ClientToStop->DhcpV6Stop();
        delete pDhcpV6ClientToStop;
        pDhcpV6ClientToStop = nullptr;
    }
#endif
    
    {
        std::lock_guard<std::mutex> lock(m_ipv6MergeMutex);
#if DHCPV6_ENABLE
        m_lastDhcpV6.erase(ifname);
#endif
        m_lastIpv6Info.erase(ifname);
    }
    return DHCP_OPT_SUCCESS;
}

void DhcpClientServiceImpl::PushDhcpResult(const std::string &ifname, OHOS::DHCP::DhcpResult &result)
{
    std::lock_guard<std::mutex> autoLock(m_dhcpResultMutex);
    auto iterResult = m_mapDhcpResult.find(ifname);
    if (iterResult != m_mapDhcpResult.end()) {
        for (size_t i = 0; i < iterResult->second.size(); i++) {
            if (iterResult->second[i].iptype != result.iptype) {
                continue;
            }
            if (iterResult->second[i].iptype == 0) { // 0-ipv4 
                if (iterResult->second[i].uAddTime != result.uAddTime) {
                    iterResult->second[i] = result;
                    DHCP_LOGI("PushDhcpResult update ipv4 result, ifname:%{public}s", ifname.c_str());
                }
            } else { // 1-ipv6
                DHCP_LOGI("PushDhcpResult update ipv6 result, ifname:%{public}s", ifname.c_str());
                iterResult->second[i] = result;
            }
            return;
        }
        DHCP_LOGI("PushDhcpResult ifname add new result, ifname:%{public}s", ifname.c_str());
        iterResult->second.push_back(result);
    } else {
        std::vector<OHOS::DHCP::DhcpResult> results;
        results.push_back(result);
        m_mapDhcpResult.emplace(std::make_pair(ifname, results));
        DHCP_LOGI("PushDhcpResult add new ifname result, ifname:%{public}s", ifname.c_str());
    }
}

bool DhcpClientServiceImpl::CheckDhcpResultExist(const std::string &ifname, OHOS::DHCP::DhcpResult &result)
{
    bool exist = false;
    std::lock_guard<std::mutex> autoLock(m_dhcpResultMutex);
    auto iterResult = m_mapDhcpResult.find(ifname);
    if (iterResult != m_mapDhcpResult.end()) {
        for (size_t i = 0; i < iterResult->second.size(); i++) {
            if (iterResult->second[i].iptype != result.iptype) {
                continue;
            }
            if (iterResult->second[i].uAddTime == result.uAddTime) {
                exist = true;
                break;
            }
        }
    }
    return exist;
}

bool DhcpClientServiceImpl::IsRemoteDied(void)
{
    DHCP_LOGD("IsRemoteDied");
    return true;
}

bool DhcpClientServiceImpl::IsGlobalIPv6Address(std::string ipAddress)
{
    const char* ipAddr = ipAddress.c_str();
    int first = ipAddr[0]-'0';
    DHCP_LOGI("first = %{public}d", first);
    if (first == NUMBER_TWO || first == NUMBER_THREE) {
        return true;
    }
    return false;
}

#if DHCPV6_ENABLE
void DhcpClientServiceImpl::DhcpV6ResultCallback(const std::string &ifname, const DhcpV6Result &result, bool stateless)
{
    {
        std::lock_guard<std::mutex> lock(m_ipv6MergeMutex);
        auto &cache = m_lastDhcpV6[ifname];
        cache.ipv6Addresses = result.ipv6Addresses;
        cache.dnsServers = result.dnsServers;
        cache.preferredLifetime = result.preferredLifetime;
        cache.validLifetime = result.validLifetime;
        cache.t1 = result.t1;
        cache.t2 = result.t2;
        cache.ready = true;
    }
    DhcpIpv6Info info;
    {
        std::lock_guard<std::mutex> autoLock(m_clientServiceMutex);
        auto iter = m_mapClientService.find(ifname);
        if (iter != m_mapClientService.end() && iter->second.pipv6Client != nullptr) {
            iter->second.pipv6Client->GetIpv6InfoSnapshot(info);
        }
    }
    DhcpIpv6ResulCallback(ifname, info);
}

void DhcpClientServiceImpl::ReportDhcpV6FailureCallback(
    const std::string &ifname, int status, const char *reason)
{
    ClientCallBackType callbackCopy;
    {
        std::lock_guard<std::mutex> autoLock(m_clientCallBackMutex);
        auto iter = m_mapClientCallBack.find(ifname);
        if (iter == m_mapClientCallBack.end()) {
            DHCP_LOGE("ReportDhcpV6FailureCallback m_mapClientCallBack not find ifname:%{public}s",
                ifname.c_str());
            return;
        }
        if (iter->second == nullptr) {
            DHCP_LOGE("ReportDhcpV6FailureCallback callback is nullptr ifname:%{public}s",
                ifname.c_str());
            return;
        }
        callbackCopy = iter->second;
    }
    callbackCopy->OnIpFailChanged(status, ifname.c_str(), reason);
    DHCP_LOGI("ReportDhcpV6FailureCallback OnIpFailChanged ifname:%{public}s status:%{public}d",
        ifname.c_str(), status);
}

void DhcpClientServiceImpl::OnDhcpV6AddressRemoved(const std::string &ifname, const std::string &addr)
{
    if (!IsDhcpV6Enabled()) {
        DHCP_LOGD("OnDhcpV6AddressRemoved DHCPv6 feature disabled, skip");
        return;
    }
    std::lock_guard<std::mutex> lock(m_ipv6MergeMutex);
    auto iter = m_lastDhcpV6.find(ifname);
    if (iter == m_lastDhcpV6.end()) {
        return;
    }
    auto &cache = iter->second;
    auto &ipv6Addresses = cache.ipv6Addresses;
    DHCP_LOGI("OnDhcpV6AddressRemoved current DHCPv6 addr count:%{public}zu", ipv6Addresses.size());
    auto it = std::find(ipv6Addresses.begin(), ipv6Addresses.end(), addr);
    if (it != ipv6Addresses.end()) {
        ipv6Addresses.erase(it);
        if (ipv6Addresses.empty()) {
            cache.dnsServers.clear();
            cache.preferredLifetime = 0;
            cache.validLifetime = 0;
            cache.t1 = 0;
            cache.t2 = 0;
            cache.ready = false;
            DHCP_LOGI("OnDhcpV6AddressRemoved all DHCPv6 addr cleared for ifname:%{public}s", ifname.c_str());
        }
    }
}

void DhcpClientServiceImpl::DhcpV6FailCallback(const std::string &ifname, int errorCode, bool stateless)
{
    {
        std::lock_guard<std::mutex> lock(m_ipv6MergeMutex);
        auto &cache = m_lastDhcpV6[ifname];
        cache.ipv6Addresses.clear();
        cache.dnsServers.clear();
        cache.preferredLifetime = 0;
        cache.validLifetime = 0;
        cache.t1 = 0;
        cache.t2 = 0;
        cache.ready = false;
    }

    // Stateless failure (M=0,O=1): do not break SLAAC result publishing.
    if (stateless) {
        DHCP_LOGI("DhcpV6FailCallback stateless failed ifname:%{public}s err:%{public}d",
            ifname.c_str(), errorCode);
        return;
    }

    // Stateful failure (M=1): check if SLAAC already has address before reporting failure
    bool hasSlaacAddress = false;
    {
        std::lock_guard<std::mutex> lock(m_ipv6MergeMutex);
        auto iter = m_lastIpv6Info.find(ifname);
        if (iter != m_lastIpv6Info.end() && strlen(iter->second.globalIpv6Addr) > 0) {
            hasSlaacAddress = true;
        }
    }
    if (hasSlaacAddress) {
        DHCP_LOGI("DhcpV6FailCallback SLAAC already has address, skip ifname:%{public}s",
            ifname.c_str());
        return;
    }

    // Report IPv6 failure to upper layer
    int status = DHCP_OPT_FAILED;
    const char *reason = "dhcpv6 failed";
    if (errorCode == ERR_RETRY_EXCEEDED) {
        status = DHCP_OPT_TIMEOUT;
        reason = "dhcpv6 timeout";
    } else if (errorCode == ERR_DAD_FAILED) {
        status = DHCP_OPT_FAILED;
        reason = "dhcpv6 dad failed";
    } else if (errorCode == ERR_LEASE_EXPIRED) {
        status = DHCP_OPT_FAILED;
        reason = "dhcpv6 lease expired";
    }
    ReportDhcpV6FailureCallback(ifname, status, reason);
}

void DhcpClientServiceImpl::DhcpV6ExpiredCallback(const std::string &ifname, bool stateless)
{
    // Treat expired as lease expired.
    DhcpV6FailCallback(ifname, ERR_LEASE_EXPIRED, stateless);
}

void DhcpClientServiceImpl::DhcpV6KernelDadCallback(const std::string &ifname,
    const std::string &addr, bool dadFailed)
{
    if (!IsDhcpV6Enabled()) {
        DHCP_LOGI("DhcpV6KernelDadCallback: DHCPv6 feature disabled, skip");
        return;
    }
    DHCP_LOGI("DhcpV6KernelDadCallback ifname:%{public}s addr:%{public}s dadFailed:%{public}d",
        ifname.c_str(), Ipv6Anonymize(addr).c_str(), dadFailed);

#if DHCPV6_ENABLE
    DhcpV6Client* v6Client = nullptr;
    {
        std::lock_guard<std::mutex> lock(m_clientServiceMutex);
        auto iter = m_mapClientService.find(ifname);
        if (iter == m_mapClientService.end()) {
            DHCP_LOGI("DhcpV6KernelDadCallback: no client for %{public}s", ifname.c_str());
            return;
        }
        v6Client = iter->second.pDhcpV6Client;
    }
    if (v6Client == nullptr) {
        DHCP_LOGI("DhcpV6KernelDadCallback: no DhcpV6Client for %{public}s", ifname.c_str());
        return;
    }
    // Only handle DAD failure for DHCPv6-assigned addresses (not SLAAC addresses)
    // SLAAC uses EUI-64 which rarely has DAD conflicts, while DHCPv6 may encounter conflicts
    if (dadFailed) {
        std::lock_guard<std::mutex> lock(m_ipv6MergeMutex);
        auto itCache = m_lastDhcpV6.find(ifname);
        bool isDhcpV6Addr = (itCache != m_lastDhcpV6.end() &&
            std::find(itCache->second.ipv6Addresses.begin(), itCache->second.ipv6Addresses.end(), addr) !=
            itCache->second.ipv6Addresses.end());
        if (!isDhcpV6Addr) {
            DHCP_LOGI("DhcpV6KernelDadCallback: address not from DHCPv6, skipping");
            return;
        }
        DHCP_LOGW("DhcpV6KernelDadCallback: DAD conflict for %{public}s",
            Ipv6Anonymize(addr).c_str());
        v6Client->OnKernelDadConflict(addr);
    }
#endif
}
#endif
} // namespace DHCP
} // namespace OHOS
