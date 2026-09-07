/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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
#include "kits/c/dhcp_c_api.h"
#include "inner_api/dhcp_client.h"
#include "inner_api/dhcp_server.h"
#include "dhcp_sdk_define.h"
#include "dhcp_c_utils.h"
#include "dhcp_event.h"
#include "dhcp_logger.h"
#ifndef OHOS_ARCH_LITE
#include <string_ex.h>
#endif
DEFINE_DHCPLOG_DHCP_LABEL("DhcpCService");
namespace {
    std::shared_ptr<OHOS::DHCP::DhcpClient> dhcpClientPtr = nullptr;
    std::shared_ptr<OHOS::DHCP::DhcpServer> dhcpServerPtr = nullptr;
}

#ifdef OHOS_ARCH_LITE
    static std::shared_ptr<DhcpClientCallBack> dhcpClientCallBack = nullptr;
    static std::shared_ptr<DhcpServerCallBack> dhcpServerCallBack = nullptr;
#else
    static OHOS::sptr<DhcpClientCallBack> dhcpClientCallBack = nullptr;
    static OHOS::sptr<DhcpServerCallBack> dhcpServerCallBack = nullptr;
#endif

NO_SANITIZE("cfi")  DhcpErrorCode RegisterDhcpClientCallBack(const char *ifname, const ClientCallBack *event)
{
    if (ifname == nullptr || event == nullptr) {
        DHCP_LOGE("[DHCP][CAdapter] register callback failed: invalid parameter");
        return DHCP_INVALID_PARAM;
    }
    DHCP_LOGI("[DHCP][CAdapter] register callback begin, ifname:%{public}s", ifname);
    if (dhcpClientPtr == nullptr) {
        dhcpClientPtr = OHOS::DHCP::DhcpClient::GetInstance(DHCP_CLIENT_ABILITY_ID);
    }
    if (dhcpClientPtr == nullptr) {
        DHCP_LOGE("[DHCP][CAdapter] register callback failed: client instance unavailable");
        return DHCP_INVALID_PARAM;
    }
#ifdef OHOS_ARCH_LITE
    if (dhcpClientCallBack == nullptr) {
        dhcpClientCallBack = std::shared_ptr<DhcpClientCallBack>(new (std::nothrow)DhcpClientCallBack());
    }
#else
    if (dhcpClientCallBack == nullptr) {
        dhcpClientCallBack = OHOS::sptr<DhcpClientCallBack>(new (std::nothrow)DhcpClientCallBack());
    }
#endif
    if (dhcpClientCallBack == nullptr) {
        DHCP_LOGE("[DHCP][CAdapter] register callback failed: callback allocation");
        return DHCP_INVALID_PARAM;
    }
    dhcpClientCallBack->RegisterCallBack(ifname, event);
    DhcpErrorCode ret = GetCErrorCode(dhcpClientPtr->RegisterDhcpClientCallBack(ifname, dhcpClientCallBack));
    DHCP_LOGI("[DHCP][CAdapter] register callback complete, ifname:%{public}s ret:%{public}d", ifname, ret);
    return ret;
}

DhcpErrorCode RegisterDhcpClientReportCallBack(const char *ifname, const DhcpClientReport *event)
{
    CHECK_PTR_RETURN(ifname, DHCP_INVALID_PARAM);
    CHECK_PTR_RETURN(event, DHCP_INVALID_PARAM);
#ifdef OHOS_ARCH_LITE
    if (dhcpClientCallBack == nullptr) {
        dhcpClientCallBack = std::make_shared<DhcpClientCallBack>();
    }
#else
    if (dhcpClientCallBack == nullptr) {
        dhcpClientCallBack = OHOS::sptr<DhcpClientCallBack>(new (std::nothrow)DhcpClientCallBack());
    }
#endif
    CHECK_PTR_RETURN(dhcpClientCallBack, DHCP_INVALID_PARAM);
    dhcpClientCallBack->RegisterDhcpClientReportCallBack(ifname, event);
    return DHCP_SUCCESS;
}

NO_SANITIZE("cfi") DhcpErrorCode StartDhcpClient(const RouterConfig &config)
{
    if (dhcpClientPtr == nullptr) {
        DHCP_LOGE("[DHCP][CAdapter] start failed: callback must be registered first");
        return DHCP_INVALID_PARAM;
    }
    DHCP_LOGI("[DHCP][CAdapter] start begin, ifname:%{public}s mode:%{public}u", config.ifname, config.linkMode);
    OHOS::DHCP::RouterConfig routerConfig;
    routerConfig.ifname = config.ifname;
    routerConfig.bssid = config.bssid;
    routerConfig.prohibitUseCacheIp = config.prohibitUseCacheIp;
    routerConfig.bIpv6 = config.bIpv6;
    routerConfig.bSpecificNetwork = config.bSpecificNetwork;
    routerConfig.isStaticIpv4 = config.isStaticIpv4;
    routerConfig.bIpv4 = config.bIpv4;
    routerConfig.linkMode = static_cast<OHOS::DHCP::DhcpLinkMode>(config.linkMode);
    routerConfig.clientKey = { config.clientKey[0], config.clientKey[1], config.clientKey[2],
        config.clientKey[3], config.clientKey[4], config.clientKey[5] };
    DhcpErrorCode ret = GetCErrorCode(dhcpClientPtr->StartDhcpClient(routerConfig));
    if (ret != DHCP_SUCCESS) {
        DHCP_LOGE("[DHCP][CAdapter] start failed, ifname:%{public}s ret:%{public}d", config.ifname, ret);
    } else {
        DHCP_LOGI("[DHCP][CAdapter] start accepted, ifname:%{public}s", config.ifname);
    }
    return ret;
}

DhcpErrorCode DealWifiDhcpCache(int32_t cmd, const IpCacheInfo &ipCacheInfo)
{
    CHECK_PTR_RETURN(ipCacheInfo.ssid, DHCP_INVALID_PARAM);
    CHECK_PTR_RETURN(ipCacheInfo.bssid, DHCP_INVALID_PARAM);
    CHECK_PTR_RETURN(dhcpClientPtr, DHCP_INVALID_PARAM);
    OHOS::DHCP::IpCacheInfo cacheInfo;
    cacheInfo.ssid = ipCacheInfo.ssid;
    cacheInfo.bssid = ipCacheInfo.bssid;
    return GetCErrorCode(dhcpClientPtr->DealWifiDhcpCache(cmd, cacheInfo));
}

NO_SANITIZE("cfi") DhcpErrorCode StopDhcpClient(const char *ifname, bool bIpv6, bool bIpv4)
{
    CHECK_PTR_RETURN(ifname, DHCP_INVALID_PARAM);
    if (dhcpClientPtr == nullptr) {
        dhcpClientPtr = OHOS::DHCP::DhcpClient::GetInstance(DHCP_CLIENT_ABILITY_ID);
    }
    CHECK_PTR_RETURN(dhcpClientPtr, DHCP_INVALID_PARAM);
    if (bIpv4 && dhcpClientCallBack != nullptr) {
        dhcpClientCallBack->UnRegisterCallBack(ifname);
    }
    return  GetCErrorCode(dhcpClientPtr->StopDhcpClient(ifname, bIpv6, bIpv4));
}

NO_SANITIZE("cfi") DhcpErrorCode RegisterDhcpServerCallBack(const char *ifname, const ServerCallBack *event)
{
    CHECK_PTR_RETURN(ifname, DHCP_INVALID_PARAM);
    CHECK_PTR_RETURN(event, DHCP_INVALID_PARAM);
    if (dhcpServerPtr == nullptr) {
        dhcpServerPtr = OHOS::DHCP::DhcpServer::GetInstance(DHCP_SERVER_ABILITY_ID);
    }
    CHECK_PTR_RETURN(dhcpServerPtr, DHCP_INVALID_PARAM);
#ifdef OHOS_ARCH_LITE
    if (dhcpServerCallBack == nullptr) {
        dhcpServerCallBack = std::shared_ptr<DhcpServerCallBack>(new (std::nothrow)DhcpServerCallBack());
    }
#else
    if (dhcpServerCallBack == nullptr) {
        dhcpServerCallBack = OHOS::sptr<DhcpServerCallBack>(new (std::nothrow)DhcpServerCallBack());
    }
#endif
    CHECK_PTR_RETURN(dhcpServerCallBack, DHCP_INVALID_PARAM);
    dhcpServerCallBack->RegisterCallBack(ifname, event);
    return GetCErrorCode(dhcpServerPtr->RegisterDhcpServerCallBack(ifname, dhcpServerCallBack));
}

NO_SANITIZE("cfi") DhcpErrorCode StartDhcpServer(const char *ifname)
{
    if (dhcpServerPtr == nullptr) {
        dhcpServerPtr = OHOS::DHCP::DhcpServer::GetInstance(DHCP_SERVER_ABILITY_ID);
    }
    CHECK_PTR_RETURN(ifname, DHCP_INVALID_PARAM);
    CHECK_PTR_RETURN(dhcpServerPtr, DHCP_INVALID_PARAM);
    return GetCErrorCode(dhcpServerPtr->StartDhcpServer(ifname));
}

NO_SANITIZE("cfi") DhcpErrorCode StopDhcpServer(const char *ifname)
{
    if (dhcpServerPtr == nullptr) {
        dhcpServerPtr = OHOS::DHCP::DhcpServer::GetInstance(DHCP_SERVER_ABILITY_ID);
    }
    CHECK_PTR_RETURN(ifname, DHCP_INVALID_PARAM);
    CHECK_PTR_RETURN(dhcpServerPtr, DHCP_INVALID_PARAM);
#ifdef OHOS_ARCH_LITE
    if (dhcpServerCallBack == nullptr) {
        dhcpServerCallBack = std::make_shared<DhcpServerCallBack>();
    }
#else
    if (dhcpServerCallBack == nullptr) {
        dhcpServerCallBack = OHOS::sptr<DhcpServerCallBack>(new (std::nothrow)DhcpServerCallBack());
    }
#endif
    CHECK_PTR_RETURN(dhcpServerCallBack, DHCP_INVALID_PARAM);
    dhcpServerCallBack->UnRegisterCallBack(ifname);
    return GetCErrorCode(dhcpServerPtr->StopDhcpServer(ifname));
}

NO_SANITIZE("cfi") DhcpErrorCode SetDhcpRange(const char *ifname, const DhcpRange *range)
{
    if (dhcpServerPtr == nullptr) {
        dhcpServerPtr = OHOS::DHCP::DhcpServer::GetInstance(DHCP_SERVER_ABILITY_ID);
    }
    CHECK_PTR_RETURN(ifname, DHCP_INVALID_PARAM);
    CHECK_PTR_RETURN(range, DHCP_INVALID_PARAM);
    CHECK_PTR_RETURN(dhcpServerPtr, DHCP_INVALID_PARAM);
    OHOS::DHCP::DhcpRange rangeNew;
    rangeNew.iptype = range->iptype;
    rangeNew.strStartip = range->strStartip;
    rangeNew.strEndip = range->strEndip;
    rangeNew.strSubnet = range->strSubnet;
    rangeNew.strTagName = range->strTagName;
    return GetCErrorCode(dhcpServerPtr->SetDhcpRange(ifname, rangeNew));
}

NO_SANITIZE("cfi") DhcpErrorCode SetDhcpName(const char *ifname, const char *tagName)
{
    if (dhcpServerPtr == nullptr) {
        dhcpServerPtr = OHOS::DHCP::DhcpServer::GetInstance(DHCP_SERVER_ABILITY_ID);
    }
    CHECK_PTR_RETURN(ifname, DHCP_INVALID_PARAM);
    CHECK_PTR_RETURN(tagName, DHCP_INVALID_PARAM);
    CHECK_PTR_RETURN(dhcpServerPtr, DHCP_INVALID_PARAM);
    return GetCErrorCode(dhcpServerPtr->SetDhcpName(ifname, tagName));
}

NO_SANITIZE("cfi") DhcpErrorCode PutDhcpRange(const char *tagName, const DhcpRange *range)
{
    if (dhcpServerPtr == nullptr) {
        dhcpServerPtr = OHOS::DHCP::DhcpServer::GetInstance(DHCP_SERVER_ABILITY_ID);
    }
    CHECK_PTR_RETURN(tagName, DHCP_INVALID_PARAM);
    CHECK_PTR_RETURN(range, DHCP_INVALID_PARAM);
    CHECK_PTR_RETURN(dhcpServerPtr, DHCP_INVALID_PARAM);
    OHOS::DHCP::DhcpRange rangeNew;
    rangeNew.iptype = range->iptype;
    rangeNew.strStartip = range->strStartip;
    rangeNew.strEndip = range->strEndip;
    rangeNew.strSubnet = range->strSubnet;
    rangeNew.strTagName = range->strTagName;
    return GetCErrorCode(dhcpServerPtr->PutDhcpRange(tagName, rangeNew));
}

NO_SANITIZE("cfi") DhcpErrorCode RemoveAllDhcpRange(const char *tagName)
{
    if (dhcpServerPtr == nullptr) {
        dhcpServerPtr = OHOS::DHCP::DhcpServer::GetInstance(DHCP_SERVER_ABILITY_ID);
    }
    CHECK_PTR_RETURN(tagName, DHCP_INVALID_PARAM);
    CHECK_PTR_RETURN(dhcpServerPtr, DHCP_INVALID_PARAM);
    return GetCErrorCode(dhcpServerPtr->RemoveAllDhcpRange(tagName));
}

DhcpErrorCode RemoveDhcpRange(const char *tagName, const void *range)
{
    if (dhcpServerPtr == nullptr) {
        dhcpServerPtr = OHOS::DHCP::DhcpServer::GetInstance(DHCP_SERVER_ABILITY_ID);
    }
    CHECK_PTR_RETURN(tagName, DHCP_INVALID_PARAM);
    CHECK_PTR_RETURN(range, DHCP_INVALID_PARAM);
    CHECK_PTR_RETURN(dhcpServerPtr, DHCP_INVALID_PARAM);
    return GetCErrorCode(dhcpServerPtr->RemoveDhcpRange(tagName, *(OHOS::DHCP::DhcpRange *)range));
}

DhcpErrorCode ParseClientInfos(int staNumber, DhcpStationInfo *staInfo, int *staSize, std::vector<std::string> &vecInfo)
{
    int size = static_cast<int>(vecInfo.size());
    DHCP_LOGI("ParseClientInfos staNumber:%{public}d size:%{public}d", staNumber, size);
    int i = 0;
    for (i = 0; i < size; i++) {
        std::vector<std::string> tmp;
        std::string str = vecInfo[i];
        OHOS::SplitStr(str, " ", tmp);
        if (tmp.empty()) {
            continue;
        }
        if (tmp[DHCP_LEASE_MAC_ADDR_POS] == "duid") {
            break;
        }
        if (tmp.size() < DHCP_LEASE_FORMAT_SIZE) {
            continue;
        }
        std::string mac = tmp[DHCP_LEASE_MAC_ADDR_POS];
        std::string ipAddr = tmp[DHCP_LEASE_IP_ADDR_POS];
        std::string deviceName = "";
        if (tmp.size() >= DHCP_LEASE_FORMAT_MAX_SIZE) {
            deviceName = tmp[DHCP_LEASE_HOSTNAME_POS];
        }
        if (i >= staNumber) {
            break;
        }
        if (strcpy_s(staInfo[i].macAddr, MAC_ADDR_MAX_LEN, mac.c_str()) != EOK) {
            DHCP_LOGE("get dhcp client info, cpy mac failed! srclen=%{public}zu", strlen(mac.c_str()));
            return DHCP_FAILED;
        }
        if (strcpy_s(staInfo[i].ipAddr, INET_ADDRSTRLEN, ipAddr.c_str()) != EOK) {
            DHCP_LOGE("get dhcp client info, cpy ip failed!");
            return DHCP_FAILED;
        }
        if (strcpy_s(staInfo[i].deviceName, DHCP_LEASE_DATA_MAX_LEN, deviceName.c_str()) != EOK) {
            DHCP_LOGE("get dhcp client info, cpy name failed!");
            return DHCP_FAILED;
        }
    }
    *staSize = i;
    DHCP_LOGI("GetDhcpClientInfos staNumber:%{public}d staSize:%{public}d", staNumber, *staSize);
    return DHCP_SUCCESS;
}

DhcpErrorCode GetDhcpClientInfos(const char *ifname, int staNumber, DhcpStationInfo *staInfo, int *staSize)
{
    if (dhcpServerPtr == nullptr) {
        dhcpServerPtr = OHOS::DHCP::DhcpServer::GetInstance(DHCP_SERVER_ABILITY_ID);
    }
    CHECK_PTR_RETURN(ifname, DHCP_INVALID_PARAM);
    CHECK_PTR_RETURN(staInfo, DHCP_INVALID_PARAM);
    CHECK_PTR_RETURN(staSize, DHCP_INVALID_PARAM);
    CHECK_PTR_RETURN(dhcpServerPtr, DHCP_INVALID_PARAM);
    std::vector<std::string> vecInfo;
    DhcpErrorCode ret = GetCErrorCode(dhcpServerPtr->GetDhcpClientInfos(ifname, vecInfo));
    if (ret != DHCP_SUCCESS) {
        DHCP_LOGE("GetDhcpClientInfos failed!");
        return DHCP_FAILED;
    }
    return ParseClientInfos(staNumber, staInfo, staSize, vecInfo);
}

NO_SANITIZE("cfi") DhcpErrorCode UpdateLeasesTime(const char *leaseTime)
{
    if (dhcpServerPtr == nullptr) {
        dhcpServerPtr = OHOS::DHCP::DhcpServer::GetInstance(DHCP_SERVER_ABILITY_ID);
    }
    CHECK_PTR_RETURN(leaseTime, DHCP_INVALID_PARAM);
    CHECK_PTR_RETURN(dhcpServerPtr, DHCP_INVALID_PARAM);
    return GetCErrorCode(dhcpServerPtr->UpdateLeasesTime(leaseTime));
}

DhcpErrorCode StopDhcpdClientSa(void)
{
    CHECK_PTR_RETURN(dhcpClientPtr, DHCP_INVALID_PARAM);
    return GetCErrorCode(dhcpClientPtr->StopClientSa());
}

DhcpErrorCode StopDhcpdServerSa(void)
{
    CHECK_PTR_RETURN(dhcpServerPtr, DHCP_INVALID_PARAM);
    return GetCErrorCode(dhcpServerPtr->StopServerSa());
}
