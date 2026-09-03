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
#include <mutex>
#include "dhcp_permission_utils.h"
#include "dhcp_logger.h"
#ifndef OHOS_ARCH_LITE
#include <cinttypes>
#include "ipc_skeleton.h"
#include "tokenid_kit.h"
#include "accesstoken_kit.h"
#endif
 
DEFINE_DHCPLOG_DHCP_LABEL("DhcpPermissionUtils");
namespace OHOS {
namespace DHCP {
DhcpPermissionUtils &DhcpPermissionUtils::GetInstance()
{
    static DhcpPermissionUtils gDhcpPermissionUtils;
    return gDhcpPermissionUtils;
}

bool DhcpPermissionUtils::VerifyIsNativeProcess()
{
#ifdef DTFUZZ_TEST
    DHCP_LOGI("VerifyIsNativeProcess DTFUZZ_TEST permission granted!");
    return true;
#endif
#ifndef OHOS_ARCH_LITE
    uint32_t tokenId = IPCSkeleton::GetCallingTokenID();
    Security::AccessToken::ATokenTypeEnum callingType =
        Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    if (callingType == Security::AccessToken::TOKEN_NATIVE) {
        return true;
    }
    DHCP_LOGE("VerifyIsNativeProcess false, callingType:%{public}d is not a native process.", callingType);
    return false;
#else
    DHCP_LOGI("VerifyIsNativeProcess OHOS_ARCH_LITE permission granted!");
    return true;
#endif
}
 
bool DhcpPermissionUtils::VerifyDhcpNetworkPermission(const std::string &permissionName)
{
#ifdef DTFUZZ_TEST
    DHCP_LOGI("VerifyDhcpNetworkPermission DTFUZZ_TEST permission granted!");
    return true;
#endif
#ifndef OHOS_ARCH_LITE
    if (!(DhcpPermissionUtils::GetInstance().VerifyPermission(permissionName, IPCSkeleton::GetCallingRealPid(),
        IPCSkeleton::GetCallingUid(), 0))) {
        DHCP_LOGE("VerifyDhcpNetworkPermission VerifyPermission denied!");
        return false;
    }
    return true;
#else
    DHCP_LOGI("VerifyDhcpNetworkPermission OHOS_ARCH_LITE permission granted!");
    return true;
#endif
}
 
bool DhcpPermissionUtils::VerifyPermission(const std::string &permissionName, const int &pid,
    const int &uid, const int &tokenId)
{
#ifdef OHOS_ARCH_LITE
    DHCP_LOGI("VerifyPermission OHOS_ARCH_LITE permission granted!");
    return true;
#else
    if (uid == static_cast<int>(getuid()) && pid == static_cast<int>(getpid())) {
        DHCP_LOGI("VerifyPermission uid pid has permission!");
        return true;
    }
    Security::AccessToken::AccessTokenID callerToken = 0;
    if (tokenId == 0) {
        callerToken = IPCSkeleton::GetCallingTokenID();
    } else {
        callerToken = (Security::AccessToken::AccessTokenID)tokenId;
    }
    DHCP_LOGI("VerifyPermission callerToken:%{public}d", callerToken);
    int result = Security::AccessToken::AccessTokenKit::VerifyAccessToken(callerToken, permissionName);
    if (result == Security::AccessToken::PermissionState::PERMISSION_GRANTED) {
        return true;
    }
    DHCP_LOGE("VerifyPermission has no permission_name=%{public}s, pid=%{public}d, uid=%{public}d, result=%{public}d",
        permissionName.c_str(), pid, uid, result);
    return false;
#endif
}
} // namespace DHCP
} // namespace OHOS