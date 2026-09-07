/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
#include <cstdint>

#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

extern "C" int SetDhcpProbeToken(void)
{
    const char *permissions[] = { "ohos.permission.NETWORK_DHCP" };
    NativeTokenInfoParams tokenInfo = {
        .dcapsNum = 0,
        .permsNum = 1,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = permissions,
        .acls = nullptr,
        .processName = "sleip_dhcp_stage2",
        .aplStr = "system_core",
    };
    uint64_t tokenId = GetAccessTokenId(&tokenInfo);
    if (tokenId == 0) {
        return -1;
    }
    int32_t ret = SetSelfTokenID(tokenId);
    if (ret != 0) {
        return ret;
    }
    return OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}
