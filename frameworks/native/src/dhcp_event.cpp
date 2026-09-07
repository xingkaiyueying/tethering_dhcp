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
#include "dhcp_event.h"
#include "dhcp_logger.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpSAEvent");

DhcpClientCallBack::DhcpClientCallBack()
{
    DHCP_LOGI("DhcpClientCallBack");
}

DhcpClientCallBack::~DhcpClientCallBack()
{
    DHCP_LOGI("~DhcpClientCallBack");
}

void DhcpClientCallBack::ResultInfoCopy(DhcpResult &dhcpResult, OHOS::DHCP::DhcpResult& result)
{
    if (strcpy_s(dhcpResult.strOptClientId, DHCP_MAX_FILE_BYTES, result.strYourCli.c_str()) != EOK) {
        DHCP_LOGE("ResultInfoCopy strOptClientId strcpy_s failed!");
    }
    if (strcpy_s(dhcpResult.strOptServerId, DHCP_MAX_FILE_BYTES, result.strServer.c_str()) != EOK) {
        DHCP_LOGE("ResultInfoCopy strOptServerId strcpy_s failed!");
    }
    if (strcpy_s(dhcpResult.strOptSubnet, DHCP_MAX_FILE_BYTES, result.strSubnet.c_str()) != EOK) {
        DHCP_LOGE("ResultInfoCopy strOptSubnet strcpy_s failed!");
    }
    if (strcpy_s(dhcpResult.strOptDns1, DHCP_MAX_FILE_BYTES, result.strDns1.c_str()) != EOK) {
        DHCP_LOGE("ResultInfoCopy strOptDns1 strcpy_s failed!");
    }
    if (strcpy_s(dhcpResult.strOptDns2, DHCP_MAX_FILE_BYTES, result.strDns2.c_str()) != EOK) {
        DHCP_LOGE("ResultInfoCopy strOptDns2 strcpy_s failed!");
    }
    if (strcpy_s(dhcpResult.strOptRouter1, DHCP_MAX_FILE_BYTES, result.strRouter1.c_str()) != EOK) {
        DHCP_LOGE("ResultInfoCopy strOptRouter1 strcpy_s failed!");
    }
    if (strcpy_s(dhcpResult.strOptRouter2, DHCP_MAX_FILE_BYTES, result.strRouter2.c_str()) != EOK) {
        DHCP_LOGE("ResultInfoCopy strOptRouter2 strcpy_s failed!");
    }
    if (strcpy_s(dhcpResult.strOptVendor, DHCP_MAX_FILE_BYTES, result.strVendor.c_str()) != EOK) {
        DHCP_LOGE("ResultInfoCopy strOptVendor strcpy_s failed!");
    }
    if (strcpy_s(dhcpResult.strOptLinkIpv6Addr, DHCP_MAX_FILE_BYTES, result.strLinkIpv6Addr.c_str()) != EOK) {
        DHCP_LOGE("ResultInfoCopy strOptLinkIpv6Addr strcpy_s failed!");
    }
    if (strcpy_s(dhcpResult.strOptRandIpv6Addr, DHCP_MAX_FILE_BYTES, result.strRandIpv6Addr.c_str()) != EOK) {
        DHCP_LOGE("ResultInfoCopy strOptRandIpv6Addr strcpy_s failed!");
    }
    if (strcpy_s(dhcpResult.strOptLocalAddr1, DHCP_MAX_FILE_BYTES, result.strLocalAddr1.c_str()) != EOK) {
        DHCP_LOGE("ResultInfoCopy strOptLocalAddr1 strcpy_s failed!");
    }
    if (strcpy_s(dhcpResult.strOptLocalAddr2, DHCP_MAX_FILE_BYTES, result.strLocalAddr2.c_str()) != EOK) {
        DHCP_LOGE("ResultInfoCopy strOptLocalAddr2 strcpy_s failed!");
    }
    ResultInfoCopyExt(dhcpResult, result);
}

void DhcpClientCallBack::ResultInfoCopyExt(DhcpResult &dhcpResult, OHOS::DHCP::DhcpResult& result)
{
    for (size_t i = 0; i < result.vectorDnsAddr.size(); i++) {
        if (i >= DHCP_DNS_MAX_NUMBER) {
            DHCP_LOGE("ResultInfoCopy break, i:%{public}zu, dns max number:%{public}d", i, DHCP_DNS_MAX_NUMBER);
            break;
        }
        if (strncpy_s(dhcpResult.dnsList.dnsAddr[i], DHCP_DNS_DATA_MAX_LEN, result.vectorDnsAddr[i].c_str(),
            result.vectorDnsAddr[i].length()) != EOK) {
            DHCP_LOGE("ResultInfoCopy, strncpy_s failed, i:%{public}zu", i);
        } else {
            dhcpResult.dnsList.dnsNumber++;
        }
    }
    for (const auto &addrItem : result.IpAddrMap) {
        if (dhcpResult.addrList.addrNumber >= DHCP_ADDR_MAX_NUMBER) {
            DHCP_LOGE("ResultInfoCopy break, addr max number:%{public}d", DHCP_ADDR_MAX_NUMBER);
            break;
        }
        const std::string &addr = addrItem.first;
        if (strncpy_s(dhcpResult.addrList.addr[dhcpResult.addrList.addrNumber], DHCP_ADDR_DATA_MAX_LEN, addr.c_str(),
            addr.length()) != EOK) {
            DHCP_LOGE("ResultInfoCopy, strncpy_s failed, addrSize:%{public}u", dhcpResult.addrList.addrNumber);
        } else {
            dhcpResult.addrList.addrType[dhcpResult.addrList.addrNumber] = addrItem.second;
            dhcpResult.addrList.addrNumber++;
        }
    }
}
void DhcpClientCallBack::OnIpSuccessChanged(int status, const std::string& ifname, OHOS::DHCP::DhcpResult& result)
    __attribute__((no_sanitize("cfi")))
{
    DHCP_LOGI("[DHCP][CAdapter] success callback received, ifname:%{public}s status:%{public}d",
        ifname.c_str(), status);
    DhcpResult dhcpResult;
    dhcpResult.iptype = result.iptype;
    dhcpResult.isOptSuc = result.isOptSuc;
    dhcpResult.uOptLeasetime = result.uLeaseTime;
    dhcpResult.uAddTime = result.uAddTime;
    dhcpResult.uGetTime = result.uGetTime;
    dhcpResult.ipv6LifeTime.validLifeTime = result.validLifetime;
    dhcpResult.ipv6LifeTime.prefLifeTime = result.preferredLifetime;
    dhcpResult.ipv6LifeTime.routerLifeTime = result.routeLifetime;
    dhcpResult.raFlags = result.raFlags;
    ResultInfoCopy(dhcpResult, result);
    DHCP_LOGI("ResultInfoCopy dstDnsNumber:%{public}u srcDnsNumber:%{public}zu", dhcpResult.dnsList.dnsNumber,
        result.vectorDnsAddr.size());

    std::lock_guard<std::mutex> autoLock(callBackMutex);
    auto iter = mapClientCallBack.find(ifname);
    if ((iter != mapClientCallBack.end()) && (iter->second != nullptr) &&
        (iter->second->OnIpSuccessChanged != nullptr)) {
        DHCP_LOGI("[DHCP][CAdapter] dispatch success callback, ifname:%{public}s status:%{public}d",
            ifname.c_str(), status);
        iter->second->OnIpSuccessChanged(status, ifname.c_str(), &dhcpResult);
    } else {
        DHCP_LOGE("[DHCP][CAdapter] success callback dispatch failed: handler not found, ifname:%{public}s",
            ifname.c_str());
    }
}

void DhcpClientCallBack::OnIpFailChanged(int status, const std::string& ifname, const std::string& reason)
    __attribute__((no_sanitize("cfi")))
{
    DHCP_LOGI("[DHCP][CAdapter] failure callback received, ifname:%{public}s status:%{public}d reason:%{public}s",
        ifname.c_str(), status, reason.c_str());
    std::lock_guard<std::mutex> autoLock(callBackMutex);
    auto iter = mapClientCallBack.find(ifname);
    if ((iter != mapClientCallBack.end()) && (iter->second != nullptr) && (iter->second->OnIpFailChanged != nullptr)) {
        DHCP_LOGI("[DHCP][CAdapter] dispatch failure callback, ifname:%{public}s status:%{public}d",
            ifname.c_str(), status);
        iter->second->OnIpFailChanged(status, ifname.c_str(), reason.c_str());
    } else {
        DHCP_LOGE("[DHCP][CAdapter] failure callback dispatch failed: handler not found, ifname:%{public}s",
            ifname.c_str());
    }
}
#ifndef OHOS_ARCH_LITE
void DhcpClientCallBack::OnDhcpOfferReport(int status, const std::string& ifname, OHOS::DHCP::DhcpResult& result)
{
    DHCP_LOGI("OnDhcpOfferReport status:%{public}d,ifname:%{public}s", status, ifname.c_str());
    DhcpResult dhcpResult;
    dhcpResult.iptype = result.iptype;
    dhcpResult.isOptSuc = result.isOptSuc;
    dhcpResult.uOptLeasetime = result.uLeaseTime;
    dhcpResult.uAddTime = result.uAddTime;
    dhcpResult.uGetTime = result.uGetTime;
    ResultInfoCopy(dhcpResult, result);
    std::lock_guard<std::mutex> autoLock(mapReportMutex_);
    auto iter = mapDhcpClientReport_.find(ifname);
    if ((iter != mapDhcpClientReport_.end()) && (iter->second != nullptr) &&
        (iter->second->OnDhcpClientReport != nullptr)) {
        iter->second->OnDhcpClientReport(status, ifname.c_str(), &dhcpResult);
    } else {
        DHCP_LOGE("OnDhcpOfferReport callbackEvent failed!");
    }
}

OHOS::sptr<OHOS::IRemoteObject> DhcpClientCallBack::AsObject() 
{
    DHCP_LOGI("DhcpClientCallBack AsObject!");
    return nullptr;
}
#endif
void DhcpClientCallBack::RegisterCallBack(const std::string& ifname, const ClientCallBack *event)
{
    if (event == nullptr) {
        DHCP_LOGE("DhcpClientCallBack event is nullptr!");
        return;
    }
    std::lock_guard<std::mutex> autoLock(callBackMutex);
    auto iter = mapClientCallBack.find(ifname);
    if (iter != mapClientCallBack.end()) {
        iter->second = event;
        DHCP_LOGI("Client RegisterCallBack update event, ifname:%{public}s", ifname.c_str());
    } else {
        mapClientCallBack.emplace(std::make_pair(ifname, event));
        DHCP_LOGI("Client RegisterCallBack add event, ifname:%{public}s", ifname.c_str());
    }
}

static bool MatchSubStr(const std::string &key, const std::string &pattern)
{
    return key.find(pattern) != std::string::npos;
}

void DhcpClientCallBack::UnRegisterCallBack(const std::string& ifname)
{
    if (ifname.empty()) {
        DHCP_LOGE("Client UnRegisterCallBack ifname is empty!");
        return;
    }
    std::lock_guard<std::mutex> autoLock(callBackMutex);
    auto iter = mapClientCallBack.find(ifname);
    if (iter != mapClientCallBack.end()) {
        mapClientCallBack.erase(iter);
        DHCP_LOGI("Client UnRegisterCallBack erase ifname:%{public}s", ifname.c_str());
    } else {
        auto it = std::find_if(mapClientCallBack.begin(), mapClientCallBack.end(),
            [&](const auto &kv) { return MatchSubStr(kv.first, ifname); });
        if (it != mapClientCallBack.end()) {
            DHCP_LOGI("Client UnRegisterCallBack find match ifname:%{public}s key:%{public}s",
                ifname.c_str(), it->first.c_str());
            mapClientCallBack.erase(it);
        } else {
            DHCP_LOGI("Client UnRegisterCallBack no match ifname:%{public}s", ifname.c_str());
        }
    }
}

void DhcpClientCallBack::RegisterDhcpClientReportCallBack(const std::string& ifname, const DhcpClientReport *event)
{
    if (event == nullptr) {
        DHCP_LOGE("RegisterDhcpClientReportCallBack event is nullptr!");
        return;
    }
    std::lock_guard<std::mutex> autoLock(mapReportMutex_);
    auto iter = mapDhcpClientReport_.find(ifname);
    if (iter != mapDhcpClientReport_.end()) {
        iter->second = event;
        DHCP_LOGI("RegisterDhcpClientReportCallBack update event, ifname:%{public}s", ifname.c_str());
    } else {
        mapDhcpClientReport_.emplace(std::make_pair(ifname, event));
        DHCP_LOGI("RegisterDhcpClientReportCallBack add event, ifname:%{public}s", ifname.c_str());
    }
}

DhcpServerCallBack::DhcpServerCallBack()
{
    DHCP_LOGI("DhcpServerCallBack");
}

DhcpServerCallBack::~DhcpServerCallBack()
{
    DHCP_LOGI("~DhcpServerCallBack");
}

void DhcpServerCallBack::OnServerStatusChanged(int status)
{
    DHCP_LOGI("DhcpServerCallBack OnServerStatusChanged status:%{public}d", status);
}

void DhcpServerCallBack::OnServerLeasesChanged(const std::string& ifname, std::vector<std::string>& leases) 
{
    DHCP_LOGI("DhcpServerCallBack OnServerLeasesChanged ifname:%{public}s", ifname.c_str());
}

void DhcpServerCallBack::OnServerSerExitChanged(const std::string& ifname)
{
    DHCP_LOGI("DhcpServerCallBack OnServerSerExitChanged ifname:%{public}s", ifname.c_str());
}

void DhcpServerCallBack::OnServerSuccess(const std::string& ifname, std::vector<DhcpStationInfo>& stationInfos)
{
    size_t size = stationInfos.size();
    DHCP_LOGI("DhcpServerCallBack OnServerSuccess ifname:%{public}s size:%{public}zu", ifname.c_str(), size);
    std::lock_guard<std::mutex> autoLock(callBackServerMutex);
    auto iter = mapServerCallBack.find(ifname);
    if ((iter != mapServerCallBack.end()) && (iter->second != nullptr) && (iter->second->OnServerSuccess != nullptr) &&
        (size > 0)) {
        DhcpStationInfo *infos = (struct DhcpStationInfo*)malloc(size * sizeof(DhcpStationInfo));
        if (infos == nullptr) {
            DHCP_LOGE("malloc failed");
            return;
        }
        for (size_t i = 0; i < size; i++) {
            if (strcpy_s(infos[i].ipAddr, sizeof(infos[i].ipAddr), stationInfos[i].ipAddr) != EOK) {
                DHCP_LOGE("OnServerSuccess strcpy_s ipAddr failed!");
                free(infos);
                infos = nullptr;
                return;
            }
            if (strcpy_s(infos[i].macAddr, sizeof(infos[i].macAddr), stationInfos[i].macAddr) != EOK) {
                DHCP_LOGE("OnServerSuccess strcpy_s macAddr failed!");
                free(infos);
                infos = nullptr;
                return;
            }
            if (strcpy_s(infos[i].deviceName, sizeof(infos[i].deviceName), stationInfos[i].deviceName) != EOK) {
                DHCP_LOGE("OnServerSuccess strcpy_s deviceName failed!");
                free(infos);
                infos = nullptr;
                return;
            }
        }
        iter->second->OnServerSuccess(ifname.c_str(), infos, size);
        free(infos);
        infos = nullptr;
        DHCP_LOGI("OnServerSuccess callbackEvent ok!");
    } else {
        DHCP_LOGE("OnServerSuccess not find callback!");
    }
}

#ifndef OHOS_ARCH_LITE
OHOS::sptr<OHOS::IRemoteObject> DhcpServerCallBack::AsObject() 
{
    DHCP_LOGI("DhcpServerCallBack AsObject!");
    return nullptr;
}
#endif
void DhcpServerCallBack::RegisterCallBack(const std::string& ifname, const ServerCallBack *event)
{
    if (event == nullptr) {
        DHCP_LOGE("DhcpServerCallBack event is nullptr!");
        return;
    }
    std::lock_guard<std::mutex> autoLock(callBackServerMutex);
    auto iter = mapServerCallBack.find(ifname);
    if (iter != mapServerCallBack.end()) {
        iter->second = event;
        DHCP_LOGI("Server RegisterCallBack update event, ifname:%{public}s", ifname.c_str());
    } else {
        mapServerCallBack.emplace(std::make_pair(ifname, event));
        DHCP_LOGI("Server RegisterCallBack add event, ifname:%{public}s", ifname.c_str());
    }
}

void DhcpServerCallBack::UnRegisterCallBack(const std::string& ifname)
{
    if (ifname.empty()) {
        DHCP_LOGE("Server UnRegisterCallBack ifname is empty!");
        return;
    }
    std::lock_guard<std::mutex> autoLock(callBackServerMutex);
    auto iter = mapServerCallBack.find(ifname);
    if (iter != mapServerCallBack.end()) {
        mapServerCallBack.erase(iter);
        DHCP_LOGI("Server UnRegisterCallBack erase ifname:%{public}s", ifname.c_str());
    } else {
        DHCP_LOGI("Server UnRegisterCallBack not find, ifname:%{public}s", ifname.c_str());
    }
}
