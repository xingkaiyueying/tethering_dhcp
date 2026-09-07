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

#ifndef OHOS_DHCP_DEFINE_H
#define OHOS_DHCP_DEFINE_H

#include <array>
#include <string>
#include <map>
#include <cstdint>
#include <netinet/ip.h>
#include <sys/stat.h>

const int ETH_MAC_ADDR_INDEX_0  = 0;
const int ETH_MAC_ADDR_INDEX_1  = 1;
const int ETH_MAC_ADDR_INDEX_2  = 2;
const int ETH_MAC_ADDR_INDEX_3  = 3;
const int ETH_MAC_ADDR_INDEX_4  = 4;
const int ETH_MAC_ADDR_INDEX_5  = 5;
const int ETH_MAC_ADDR_LEN      = 6;
const int ETH_MAC_ADDR_CHAR_NUM = 3;
const int IP_SIZE               = 18;
const int LEASETIME_DEFAULT_SERVER     = 6;
const int ONE_HOURS_SEC         = 3600;
const int RECEIVER_TIMEOUT      = 6;
const int EVENT_DATA_NUM        = 11;
const int IPV6_EVENT_DATA_NUM   = 9;
const int DHCP_NUM_ZERO         = 0;
const int DHCP_NUM_ONE          = 1;
const int DHCP_NUM_TWO          = 2;
const int DHCP_NUM_THREE        = 3;
const int DHCP_NUM_FOUR         = 4;
const int DHCP_NUM_FIVE         = 5;
const int DHCP_NUM_SIX          = 6;
const int DHCP_NUM_SEVEN        = 7;
const int DHCP_NUM_EIGHT        = 8;
const int DHCP_NUM_NINE         = 9;
const int DHCP_NUM_TEN          = 10;
const int DHCP_FILE_MAX_BYTES   = 128;
const int FILE_LINE_MAX_SIZE    = 1024;
const int DHCP_SER_ARGSNUM      = 6;
const int DHCP_CLI_ARGSNUM      = 5;
const int SLEEP_TIME_200_MS     = 200 * 1000;
const int SLEEP_TIME_500_MS     = 500 * 1000;
const int PID_MAX_LEN           = 16;
const int PARAM_MAX_SIZE        = 40;
const int DEFAULT_UMASK         = 027;
const int DIR_MAX_LEN           = 256;

// RA flags bit masks (M/O bits)
constexpr uint8_t RA_FLAG_MANAGED_MASK = 0x01;  // M flag - DHCPv6 should be used
constexpr uint8_t RA_FLAG_OTHER_MASK = 0x02;    // O flag - Other config via DHCPv6
const int DIR_DEFAULT_MODE      = S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH;
const int DHCP_IPV4_GETTED  = 1;
const int DHCP_IPV6_GETTED  = 2;
const int DHCP_IPALL_GETED  = DHCP_IPV4_GETTED | DHCP_IPV6_GETTED;
inline const std::string IP4_SEPARATOR(".");
inline const std::string IP6_SEPARATOR(":");
inline const std::string INVALID_STRING("*");
inline const std::string EVENT_DATA_DELIMITER(",");
inline const std::string EVENT_DATA_IPV4("ipv4");
inline const std::string EVENT_DATA_IPV6("ipv6");

#define DHCP_CLIENT_ABILITY_ID  1126
#define DHCP_SERVER_ABILITY_ID  1127

#ifdef OHOS_EUPDATER
inline const std::string DHCP_WORK_DIR("/tmp/service/el1/public/dhcp/");
#else
inline const std::string DHCP_WORK_DIR("/data/service/el1/public/dhcp/");
#endif // OHOS_EUPDATER

inline const std::string DHCP_CLIENT_PID_FILETYPE(".pid");
inline const std::string DHCP_RESULT_FILETYPE(".result");
#ifdef OHOS_ARCH_LITE
inline const std::string DHCP_CLIENT_FILE("/bin/dhcp_client_service");
inline const std::string DHCP_SERVER_FILE("/bin/dhcp_server");
#else
inline const std::string DHCP_CLIENT_FILE("/system/bin/dhcp_client_service");
inline const std::string DHCP_SERVER_FILE("/system/bin/dhcp_server");
#endif
inline const std::string DHCP_SERVER_CONFIG_FILE(DHCP_WORK_DIR + "etc/dhcpd.conf");
inline const std::string DHCP_SERVER_CONFIG_DIR(DHCP_WORK_DIR + "etc/");
inline const std::string DHCP_SERVER_LEASES_FILE(DHCP_WORK_DIR + "dhcpd_lease.lease");
inline const std::string DHCP_SERVER_CFG_IPV4("#ipv4");
inline const std::string DHCP_SERVER_CFG_IPV6("#ipv6");
inline const std::string COMMON_EVENT_DHCP_GET_IPV4 = "usual.event.wifi.dhcp.GET_IPV4";

// See: RFC 2132        DHCP Options and BOOTP Vendor Extensions      March 1997
enum DhcpOptions {
    /*
     * 3. RFC 1497 Vendor Extensions
     * This section lists the vendor extensions as defined in RFC 1497.
     * They are defined here for completeness.
     */
    PAD_OPTION = 0,
    END_OPTION = 255,

    SUBNET_MASK_OPTION = 1,
    TIME_OFFSET_OPTION = 2,
    ROUTER_OPTION = 3,
    TIME_SERVER_OPTION = 4,
    NAME_SERVER_OPTION = 5,
    DOMAIN_NAME_SERVER_OPTION = 6,
    LOG_SERVER_OPTION = 7,
    COOKIE_SERVER_OPTION = 8,
    LPR_SERVER_OPTION = 9,
    IMPRESS_SERVER_OPTION = 10,
    RESOURCE_LOCATION_SERVER_OPTION = 11,
    HOST_NAME_OPTION = 12,
    BOOT_FILE_SIZE_OPTION = 13,
    MERIT_DUMP_FILE_OPTION = 14,
    DOMAIN_NAME_OPTION = 15,
    SWAP_SERVER_OPTION = 16,
    ROOT_PATH_OPTION = 17,
    EXTENSIONS_PATH_OPTION = 18,

    /*
     * IP Layer Parameters per Host
     * This section details the options that affect the operation of the IP layer on a per-host basis.
     */
    IP_FORWARDING_OPTION = 19,
    NON_LOCAL_SOURCE_ROUTING_OPTION = 20,
    POLICY_FILTER_OPTION = 21,
    MAXIMUM_DATAGRAM_REASSEMBLY_SIZE_OPTION = 22,
    DEFAULT_IP_TIME_TO_LIVE_OPTION = 23,
    PATH_MTU_AGING_TIMEOUT_OPTION = 24,
    PATH_MTU_PLATEAU_TABLE_OPTION = 25,

    /*
     * 5. IP Layer Parameters per Interface
     * This section details the options that affect the operation of the IP layer on a per-interface basis.  It is
     * expected that a client can issue multiple requests, one per interface, in order to configure interfaces with
     * their specific parameters.
     */
    INTERFACE_MTU_OPTION = 26,
    ALL_SUBNETS_ARE_LOCAL_OPTION = 27,
    BROADCAST_ADDRESS_OPTION = 28,
    PERFORM_MASK_DISCOVERY_OPTION = 29,
    MASK_SUPPLIER_OPTION = 30,
    PERFORM_ROUTER_DISCOVERY_OPTION = 31,
    ROUTER_SOLICITATION_ADDRESS_OPTION = 32,
    STATIC_ROUTE_OPTION = 33,

    /*
     * 6. Link Layer Parameters per Interface
     * This section lists the options that affect the operation of the data link layer on a per-interface basis.
     */
    TRAILER_ENCAPSULATION_OPTION = 34,   // 6.1. Trailer Encapsulation Option
    ARP_CACHE_TIMEOUT_OPTION = 35,       // 6.2. ARP Cache Timeout Option
    ETHERNET_ENCAPSULATION_OPTION = 36,  // 6.3. Ethernet Encapsulation Option

    /*
     * 7. TCP Parameters
     * This section lists the options that affect the operation of the TCP layer on a per-interface basis.
     */
    TCP_DEFAULT_TTL_OPTION = 37,         // 7.1. TCP Default TTL Option
    TCP_KEEPALIVE_INTERVAL_OPTION = 38,  // 7.2. TCP Keepalive Interval Option
    TCP_KEEPALIVE_GARBAGE_OPTION = 39,   // 7.3. TCP Keepalive Garbage Option

    /*
     * 8. Application and Service Parameters
     * This section details some miscellaneous options used to configure miscellaneous applications and services.
     */
    NETWORK_INFO_SERVICE_DOMAIN_OPTION = 40,           // 8.1. Network Information Service Domain Option
    NETWORK_INFO_SERVERS_OPTION = 41,                  // 8.2. Network Information Servers Option
    NETWORK_TIME_PROTOCOL_SERVERS_OPTION = 42,         // 8.3. Network Time Protocol Servers Option
    VENDOR_SPECIFIC_INFO_OPTION = 43,                  // 8.4. Vendor Specific Information
    NETBIOS_OVER_IP_NAME_SERVER_OPTION = 44,           // 8.5. NetBIOS over TCP/IP Name Server Option
    NETBIOS_OVER_IP_DATAGRAM_DIST_SERVER_OPTION = 45,  // 8.6. NetBIOS over TCP/IP Datagram Distribution Server Option
    NETBIOS_OVER_IP_NODE_TYPE_OPTION = 46,             // 8.7. NetBIOS over TCP/IP Node Type Option
    NETBIOS_OVER_IP_SCOPE_OPTION = 47,                 // 8.8. NetBIOS over TCP/IP Scope Option
    X_WINDOW_SYSTEM_FONT_SERVER_OPTION = 48,           // 8.9. X Window System Font Server Option
    X_WINDOW_SYSTEM_DISPLAY_MANAGER_OPTION = 49,       // 8.10. X Window System Display Manager Option
    NETWORK_INFO_SERVICE_PLUS_DOMAIN_OPTION = 64,      // 8.11. Network Information Service+ Domain Option
    NETWORK_INFO_SERVICE_PLUS_SERVERS_OPTION = 65,     // 8.12. Network Information Service+ Servers Option
    MOBILE_IP_HOME_AGENT_OPTION = 68,                  // 8.13. Mobile IP Home Agent option
    SMTP_SERVER_OPTION = 69,                           // 8.14. Simple Mail Transport Protocol (SMTP) Server Option
    POP3_SERVER_OPTION = 70,                           // 8.15. Post Office Protocol (POP3) Server Option
    NNTP_SERVER_OPTION = 71,                           // 8.16. Network News Transport Protocol (NNTP) Server Option
    DEFAULT_WEB_SERVER_OPTION = 72,                    // 8.17. Default World Wide Web (WWW) Server Option
    DEFAULT_FINGER_SERVER_OPTION = 73,                 // 8.18. Default Finger Server Option
    DEFAULT_IRC_SERVER_OPTION = 74,                    // 8.19. Default Internet Relay Chat (IRC) Server Option
    STREETTALK_SERVER_OPTION = 75,                     // 8.20. StreetTalk Server Option
    STDA_SERVER_OPTION = 76,                           // 8.21. StreetTalk Directory Assistance (STDA) Server Option
    /*
     * 9. DHCP Extensions
     * This section details the options that are specific to DHCP.
     */
    REQUESTED_IP_ADDRESS_OPTION = 50,
    IP_ADDRESS_LEASE_TIME_OPTION = 51,
    OPTION_OVERLOAD_OPTION = 52,
    TFTP_SERVER_NAME_OPTION = 66,
    BOOTFILE_NAME_OPTION = 67,
    DHCP_MESSAGE_TYPE_OPTION = 53,
    SERVER_IDENTIFIER_OPTION = 54,
    PARAMETER_REQUEST_LIST_OPTION = 55,
    MESSAGE_OPTION = 56,
    MAXIMUM_DHCP_MESSAGE_SIZE_OPTION = 57,
    RENEWAL_TIME_VALUE_OPTION = 58,
    REBINDING_TIME_VALUE_OPTION = 59,
    VENDOR_CLASS_IDENTIFIER_OPTION = 60,
    CLIENT_IDENTIFIER_OPTION = 61,
    USER_CLASS_OPTION = 77,
    RAPID_COMMIT_OPTION = 80,
    IPV6_ONLY_PREFERRED_OPTION = 108,
    CAPTIVE_PORTAL_OPTION = 114,
    /* RFC 6704 */
    FORCERENEW_NONCE_OPTION = 145, /* Forcerenew Nonce Authentication */
};
typedef enum EnumErrCode {
    /* success */
    DHCP_OPT_SUCCESS = 0,
    /* failed */
    DHCP_OPT_FAILED,
    /* null pointer */
    DHCP_OPT_NULL,
    /* get ip timeout */
    DHCP_OPT_TIMEOUT,
    /* renew failed */
    DHCP_OPT_RENEW_FAILED,
    /* renew timeout */
    DHCP_OPT_RENEW_TIMEOUT,
    /* lease expired */
    DHCP_OPT_LEASE_EXPIRED,
    /* dhcp offer */
    DHCP_OPT_OFFER_REPORT,
    /* error */
    DHCP_OPT_ERROR,
    /* not support */
    DHCP_OPT_NOT_SUPPORTED,
} DhcpErrCode;

enum DhcpServerStatus {
    DHCP_SERVER_OFF = 0,
    DHCP_SERVER_ON,
};
namespace OHOS {
namespace DHCP {
inline const std::string IP_V4_MASK("255.255.255.0");
inline const std::string IP_V4_DEFAULT("192.168.62.1");
inline const uint32_t LIFETIME_INFINITY = 0xFFFFFFFF; // infinite lifetime
struct DhcpResult {
    bool isOptSuc;          /* get result */
    int iptype;             /* 0-ipv4,1-ipv6 */
    std::string strYourCli; /* your (client) IP */
    std::string strServer;  /* dhcp server IP */
    std::string strSubnet;  /* your (client) subnet mask */
    std::string strDns1;    /* your (client) DNS server1 */
    std::string strDns2;    /* your (client) DNS server2 */
    std::string strRouter1; /* your (client) router1 */
    std::string strRouter2; /* your (client) router2 */
    std::string strVendor;  /* your (client) vendor */
    std::string strLinkIpv6Addr;  /* your (client) link ipv6 addr */
    std::string strRandIpv6Addr;  /* your (client) rand ipv6 addr */
    std::string strLocalAddr1;  /* your (client) unique local ipv6 addr */
    std::string strLocalAddr2;  /* your (client) unique local ipv6 addr */
    uint32_t uLeaseTime;    /* your (client) IP lease time (s) */
    uint32_t uAddTime;      /* dhcp result add time */
    uint32_t uGetTime;      /* dhcp result get time */
    std::vector<std::string> vectorDnsAddr; /* your (client) multi dns server */
    std::map<std::string, int> IpAddrMap; // key: addr, value: type
    uint32_t validLifetime {LIFETIME_INFINITY};
    uint32_t preferredLifetime {LIFETIME_INFINITY};
    uint32_t routeLifetime {LIFETIME_INFINITY};
    uint8_t raFlags { 0 };
    DhcpResult()
    {
        iptype      = -1;
        isOptSuc    = false;
        strYourCli  = "";
        strServer   = "";
        strSubnet   = "";
        strDns1     = "";
        strDns2     = "";
        strRouter1  = "";
        strRouter2  = "";
        strVendor   = "";
        strLinkIpv6Addr = "";
        strRandIpv6Addr = "";
        strLocalAddr1   = "";
        strLocalAddr2   = "";
        uLeaseTime  = 0;
        uAddTime    = 0;
        uGetTime    = 0;
        vectorDnsAddr.clear();
        IpAddrMap.clear();
        validLifetime = LIFETIME_INFINITY;
        preferredLifetime = LIFETIME_INFINITY;
        routeLifetime = LIFETIME_INFINITY;
        raFlags = 0;
    }
};

struct DhcpPacketResult {
    char strYiaddr[INET_ADDRSTRLEN];        /* your (client) IP */
    char strOptServerId[INET_ADDRSTRLEN];   /* dhcp option DHO_SERVERID */
    char strOptSubnet[INET_ADDRSTRLEN];     /* dhcp option DHO_SUBNETMASK */
    char strOptDns1[INET_ADDRSTRLEN];       /* dhcp option DHO_DNSSERVER */
    char strOptDns2[INET_ADDRSTRLEN];       /* dhcp option DHO_DNSSERVER */
    char strOptRouter1[INET_ADDRSTRLEN];    /* dhcp option DHO_ROUTER */
    char strOptRouter2[INET_ADDRSTRLEN];    /* dhcp option DHO_ROUTER */
    char strOptVendor[DHCP_FILE_MAX_BYTES]; /* dhcp option DHO_VENDOR */
    uint32_t uOptLeasetime;                 /* dhcp option DHO_LEASETIME */
    uint32_t uAddTime;                      /* dhcp result add time */
};

struct DhcpServiceInfo {
    bool enableIPv6;        /* true:ipv4 and ipv6,false:ipv4 */
    int clientRunStatus;    /* dhcp client service status */
    pid_t clientProPid;     /* dhcp client process pid */
    std::string serverIp;   /* dhcp server IP */

    DhcpServiceInfo()
    {
        enableIPv6 = true;
        clientRunStatus = -1;
        clientProPid = 0;
        serverIp = "";
    }
};

struct DhcpServerInfo {
    pid_t proPid;           /* dhcp server process id */
    bool normalExit;        /* dhcp server process normal exit */
    bool exitSig;           /* dhcp server process exit signal */

    DhcpServerInfo()
    {
        proPid = 0;
        normalExit = false;
        exitSig = false;
    }
};

struct DhcpRange {
    int iptype;             /* 0-ipv4,1-ipv6 */
    int leaseHours;         /* lease hours */
    std::string strTagName; /* dhcp-range tag name */
    std::string strStartip; /* dhcp-range start ip */
    std::string strEndip;   /* dhcp-range end ip */
    std::string strSubnet;  /* dhcp-range subnet */

    DhcpRange()
    {
        iptype = -1;
        leaseHours = LEASETIME_DEFAULT_SERVER;
        strTagName = "";
        strStartip = "";
        strEndip = "";
        strSubnet = "";
    }
};

enum class DhcpLinkMode : uint8_t {
    L2_PACKET = 0,
    L3_TUN = 1,
};

struct RouterConfig {
    std::string ifname;
    std::string bssid;
    bool prohibitUseCacheIp { false };
    bool bIpv6 { true };
    bool bSpecificNetwork { false };
    bool isStaticIpv4 { false };
    bool bIpv4 { true };
    DhcpLinkMode linkMode { DhcpLinkMode::L2_PACKET };
    std::array<uint8_t, ETH_MAC_ADDR_LEN> clientKey {};
};

struct IpCacheInfo {
    std::string ssid;
    std::string bssid;
};
}  // namespace DHCP
}  // namespace OHOS
#endif /* OHOS_DHCP_DEFINE_H */
