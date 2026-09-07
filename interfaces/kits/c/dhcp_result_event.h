/*
 * Copyright (c) 2020-2023 Huawei Device Co., Ltd.
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
#ifndef OHOS_DHCP_RESULT_EVENT_H
#define OHOS_DHCP_RESULT_EVENT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <sys/stat.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DHCP_MAX_FILE_BYTES 128
#define MAC_ADDR_MAX_LEN 18
#define DHCP_LEASE_FORMAT_SIZE 8
#define DHCP_LEASE_FORMAT_MAX_SIZE 9
#define DHCP_LEASE_MAC_ADDR_POS 0
#define DHCP_LEASE_IP_ADDR_POS 1
#define DHCP_LEASE_HOSTNAME_POS 8
#define DHCP_LEASE_DATA_MAX_LEN 128
#define DHCP_DNS_MAX_NUMBER 10
#define DHCP_DNS_DATA_MAX_LEN 128
#define DHCP_ADDR_MAX_NUMBER 16
#define DHCP_CLIENT_KEY_LEN 6

typedef enum DhcpLinkMode {
    DHCP_LINK_MODE_L2_PACKET = 0,
    DHCP_LINK_MODE_L3_TUN = 1,
} DhcpLinkMode;
#define DHCP_ADDR_DATA_MAX_LEN 128
#define INTERFACE_MAX_LEN 32
#define SSID_MAX_LEN 32
#define WIFI_DHCP_CACHE_ADD 1
#define WIFI_DHCP_CACHE_REMOVE 2

typedef struct{
    uint32_t dnsNumber;
    char dnsAddr[DHCP_DNS_MAX_NUMBER][DHCP_DNS_DATA_MAX_LEN];
}DnsList;

typedef struct{
    uint32_t addrNumber;
    char addr[DHCP_ADDR_MAX_NUMBER][DHCP_ADDR_DATA_MAX_LEN];
    int addrType[DHCP_ADDR_MAX_NUMBER];
}AddrList;

typedef struct{
    uint32_t validLifeTime;
    uint32_t prefLifeTime;
    uint32_t routerLifeTime;
}Ipv6LifeTime;

typedef struct{
    int iptype;                                /* 0-ipv4,1-ipv6 */
    bool isOptSuc;                              /* get result */
    char strOptClientId[DHCP_MAX_FILE_BYTES];   /* your (client) IP */
    char strOptServerId[DHCP_MAX_FILE_BYTES];   /* dhcp server IP */
    char strOptSubnet[DHCP_MAX_FILE_BYTES];     /* your (client) subnet mask */
    char strOptDns1[DHCP_MAX_FILE_BYTES];       /* your (client) DNS server1 */
    char strOptDns2[DHCP_MAX_FILE_BYTES];       /* your (client) DNS server2 */
    char strOptRouter1[DHCP_MAX_FILE_BYTES];    /* your (client) router1 */
    char strOptRouter2[DHCP_MAX_FILE_BYTES];    /* your (client) router2 */
    char strOptVendor[DHCP_MAX_FILE_BYTES];     /* your (client) vendor */
    char strOptLinkIpv6Addr[DHCP_MAX_FILE_BYTES];  /* your (client) link ipv6 addr */
    char strOptRandIpv6Addr[DHCP_MAX_FILE_BYTES];  /* your (client) rand ipv6 addr */
    char strOptLocalAddr1[DHCP_MAX_FILE_BYTES];    /* your (client) unique local ipv6 addr */
    char strOptLocalAddr2[DHCP_MAX_FILE_BYTES];    /* your (client) unique local ipv6 addr */
    uint32_t uOptLeasetime;                     /* your (client) IP lease time (s) */
    uint32_t uAddTime;                          /* dhcp result add time */
    uint32_t uGetTime;                          /* dhcp result get time */
    DnsList dnsList;                            /* dhcp dns list */
    AddrList addrList;                          /* dhcp addr list */
    Ipv6LifeTime ipv6LifeTime;                  /* dhcp ipv6 life time */
    uint8_t raFlags;                            /* RA flags: bit0=M flag, bit1=O flag */
} DhcpResult;

typedef struct DhcpRange{
    int iptype;                           /* 0-ipv4,1-ipv6 */
    int leaseHours;                       /* lease hours */
    char strTagName[DHCP_MAX_FILE_BYTES]; /* dhcp-range tag name */
    char strStartip[INET_ADDRSTRLEN];     /* dhcp-range start ip */
    char strEndip[INET_ADDRSTRLEN];       /* dhcp-range end ip */
    char strSubnet[INET_ADDRSTRLEN];      /* dhcp-range subnet */
}DhcpRange;

typedef struct DhcpStationInfo{
    char ipAddr[INET_ADDRSTRLEN];
    char macAddr[MAC_ADDR_MAX_LEN];
    char deviceName[DHCP_LEASE_DATA_MAX_LEN];
}DhcpStationInfo;

typedef struct {
    void (*OnIpSuccessChanged)(int status, const char *ifname, DhcpResult *result);
    void (*OnIpFailChanged)(int status, const char *ifname, const char *reason);
}ClientCallBack;

typedef struct {
    void (*OnDhcpClientReport)(int status, const char *ifname, DhcpResult *result);
}DhcpClientReport;

typedef struct {
    void (*OnServerStatusChanged)(int status);
    void (*OnServerLeasesChanged)(const char *ifname, const char *leases);
    void (*OnSerExitChanged)(const char *ifname);
    void (*OnServerSuccess)(const char *ifname, DhcpStationInfo *stationInfos, size_t size);
}ServerCallBack;

typedef struct RouterConfig {
    char ifname[INTERFACE_MAX_LEN];
    char bssid[MAC_ADDR_MAX_LEN];
#ifdef __cplusplus
    bool prohibitUseCacheIp { false };
    bool bIpv6 { true };
    bool bSpecificNetwork { false };
    bool isStaticIpv4 { false };
    bool bIpv4 { true };
    uint8_t linkMode { DHCP_LINK_MODE_L2_PACKET };
    uint8_t clientKey[DHCP_CLIENT_KEY_LEN] { 0 };
#else
    bool prohibitUseCacheIp;
    bool bIpv6;
    bool bSpecificNetwork;
    bool isStaticIpv4;
    bool bIpv4;
    uint8_t linkMode;
    uint8_t clientKey[DHCP_CLIENT_KEY_LEN];
#endif
}RouterConfig;

typedef struct IpCacheInfo {
    char ssid[SSID_MAX_LEN];
    char bssid[MAC_ADDR_MAX_LEN];
}IpCacheInfo;
#ifdef __cplusplus
}
#endif
#endif
