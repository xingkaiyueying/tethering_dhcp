/* Copyright (C) 2026 Huawei Device Co., Ltd. Licensed under the Apache License, Version 2.0. */
#ifndef DHCP_L3_IPV6_H
#define DHCP_L3_IPV6_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
// Demo L3 sidecar. The existing public DhcpResult and ClientCallBack layouts stay unchanged.
#define DHCP_L3_IPV6_MAX_ADDRESSES 8
typedef struct {
    char address[46];
    uint32_t ifindex;
    uint32_t prefixLength;
    uint32_t flags; // Linux IFA_F_*; tentative/duplicate are never usable.
    uint32_t preferredLifetime;
    uint32_t validLifetime;
} DhcpL3Ipv6Address;
typedef struct {
    uint32_t addressCount;
    DhcpL3Ipv6Address addresses[DHCP_L3_IPV6_MAX_ADDRESSES];
} DhcpL3Ipv6Snapshot;
#ifdef __cplusplus
}
#endif
#endif
