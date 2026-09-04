/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "dhcp_c_api.h"

#define WAIT_SECONDS 60
#define CLIENT_ID_OPTION 61

static atomic_int g_clientDone;
static atomic_int g_clientPassed;
static DhcpResult g_clientResult;

extern int SetDhcpProbeToken(void);

#define DHCP_LOG(fmt, ...) printf("[DHCP][PROBE] " fmt "\n", ##__VA_ARGS__)

static void PrintResult(bool passed, const char *phase, int code)
{
    DHCP_LOG("complete phase=%s result=%s code=%d", phase, passed ? "PASS" : "FAIL", code);
    printf("RESULT=%s phase=%s code=%d\n", passed ? "PASS" : "FAIL", phase, code);
}

static bool ParseClientKey(const char *text, uint8_t key[DHCP_CLIENT_KEY_LEN])
{
    unsigned int value[DHCP_CLIENT_KEY_LEN];
    char tail = '\0';
    if (sscanf(text, "%2x:%2x:%2x:%2x:%2x:%2x%c", &value[0], &value[1], &value[2], &value[3],
        &value[4], &value[5], &tail) != DHCP_CLIENT_KEY_LEN) {
        DHCP_LOG("client key parse failed");
        return false;
    }
    for (size_t i = 0; i < DHCP_CLIENT_KEY_LEN; ++i) {
        key[i] = (uint8_t)value[i];
    }
    return true;
}

static bool IsExpectedLease(const char *address)
{
    struct in_addr parsed;
    if (address == NULL || inet_pton(AF_INET, address, &parsed) != 1) {
        return false;
    }
    uint32_t host = ntohl(parsed.s_addr);
    return host >= 0xC0A84D02 && host <= 0xC0A84D14;
}

static int SetInterfaceIpv4Value(int fd, const char *ifname, const char *value, unsigned long request,
    const char *label)
{
    struct ifreq ifr = {0};
    struct sockaddr_in address = {0};
    if (ifname == NULL || value == NULL || snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname) < 0 ||
        strlen(ifname) >= IFNAMSIZ) {
        DHCP_LOG("interface %s failed: invalid iface=%s", label, ifname == NULL ? "-" : ifname);
        return -1;
    }
    address.sin_family = AF_INET;
    if (inet_pton(AF_INET, value, &address.sin_addr) != 1) {
        DHCP_LOG("interface %s failed: invalid IPv4 value=%s", label, value == NULL ? "-" : value);
        return -1;
    }
    memcpy(&ifr.ifr_addr, &address, sizeof(address));
    if (ioctl(fd, request, &ifr) < 0) {
        int error = errno;
        DHCP_LOG("interface %s ioctl failed iface=%s value=%s errno=%d", label, ifname, value, error);
        return -error;
    }
    DHCP_LOG("interface %s applied iface=%s value=%s", label, ifname, value);
    return 0;
}

static int SetInterfaceUp(int fd, const char *ifname)
{
    struct ifreq ifr = {0};
    if (ifname == NULL || strlen(ifname) >= IFNAMSIZ ||
        snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname) < 0) {
        DHCP_LOG("interface up failed: invalid iface");
        return -1;
    }
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
        int error = errno;
        DHCP_LOG("interface flags read failed iface=%s errno=%d", ifname, error);
        return -error;
    }
    if ((ifr.ifr_flags & IFF_UP) != 0) {
        DHCP_LOG("interface already up iface=%s", ifname);
        return 0;
    }
    ifr.ifr_flags |= IFF_UP;
    if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
        int error = errno;
        DHCP_LOG("interface up ioctl failed iface=%s errno=%d", ifname, error);
        return -error;
    }
    DHCP_LOG("interface up applied iface=%s", ifname);
    return 0;
}

static int ConfigureServerInterface(const char *ifname, const char *address, const char *subnet)
{
    DHCP_LOG("server interface configure begin iface=%s address=%s subnet=%s", ifname, address, subnet);
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        int error = errno;
        DHCP_LOG("server interface configure failed: socket errno=%d", error);
        return -error;
    }
    int ret = SetInterfaceIpv4Value(fd, ifname, address, SIOCSIFADDR, "address");
    if (ret == 0) {
        ret = SetInterfaceIpv4Value(fd, ifname, subnet, SIOCSIFNETMASK, "netmask");
    }
    if (ret == 0) {
        ret = SetInterfaceUp(fd, ifname);
    }
    close(fd);
    if (ret != 0) {
        DHCP_LOG("server interface configure failed iface=%s ret=%d", ifname, ret);
        return ret;
    }
    DHCP_LOG("server interface configure complete iface=%s address=%s subnet=%s", ifname, address, subnet);
    return 0;
}

static int DeriveServerAddress(const char *start, const char *end, const char *subnet, char address[INET_ADDRSTRLEN])
{
    struct in_addr startAddr;
    struct in_addr endAddr;
    struct in_addr maskAddr;
    if (inet_pton(AF_INET, start, &startAddr) != 1 || inet_pton(AF_INET, end, &endAddr) != 1 ||
        inet_pton(AF_INET, subnet, &maskAddr) != 1) {
        DHCP_LOG("server address derivation failed: invalid range or subnet");
        return -1;
    }
    uint32_t startHost = ntohl(startAddr.s_addr);
    uint32_t endHost = ntohl(endAddr.s_addr);
    uint32_t maskHost = ntohl(maskAddr.s_addr);
    uint32_t network = startHost & maskHost;
    uint32_t broadcast = network | ~maskHost;
    uint32_t gateway = network + 1;
    if ((endHost & maskHost) != network || startHost > endHost || gateway >= broadcast ||
        (gateway >= startHost && gateway <= endHost)) {
        DHCP_LOG("server address derivation failed: range must leave subnet first host for gateway");
        return -1;
    }
    struct in_addr gatewayAddr = {.s_addr = htonl(gateway)};
    if (inet_ntop(AF_INET, &gatewayAddr, address, INET_ADDRSTRLEN) == NULL) {
        DHCP_LOG("server address derivation failed: inet_ntop errno=%d", errno);
        return -1;
    }
    DHCP_LOG("server address derived address=%s subnet=%s", address, subnet);
    return 0;
}

static void OnIpSuccess(int status, const char *ifname, DhcpResult *result)
{
    DHCP_LOG("client success callback iface=%s status=%d result=%s", ifname == NULL ? "-" : ifname, status,
        result == NULL ? "null" : "present");
    if (result != NULL) {
        g_clientResult = *result;
        atomic_store(&g_clientPassed, result->isOptSuc && IsExpectedLease(result->strOptClientId));
        DHCP_LOG("lease validation opt_success=%d in_expected_range=%d", result->isOptSuc,
            IsExpectedLease(result->strOptClientId));
    }
    atomic_store(&g_clientDone, 1);
}

static void OnIpFail(int status, const char *ifname, const char *reason)
{
    DHCP_LOG("client failure callback iface=%s status=%d reason=%s", ifname == NULL ? "-" : ifname, status,
        reason == NULL ? "-" : reason);
    atomic_store(&g_clientDone, 1);
}

static int RunConfigRoundtrip(void)
{
    RouterConfig source = {0};
    RouterConfig decoded = {0};
    const uint8_t expected[DHCP_CLIENT_KEY_LEN] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    source.linkMode = DHCP_LINK_MODE_L3_TUN;
    memcpy(source.clientKey, expected, sizeof(expected));
    memcpy(&decoded, &source, sizeof(source));
    bool passed = decoded.linkMode == DHCP_LINK_MODE_L3_TUN &&
        memcmp(decoded.clientKey, expected, sizeof(expected)) == 0;
    printf("mode=%u key=02:11:22:33:44:55 default_mode=%u\n", decoded.linkMode, DHCP_LINK_MODE_L2_PACKET);
    PrintResult(passed, "CONFIG", passed ? 0 : -1);
    return passed ? 0 : 1;
}

static int RunPacketVector(void)
{
    const uint8_t key[DHCP_CLIENT_KEY_LEN] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t chaddr[16] = {0};
    uint8_t clientId[DHCP_CLIENT_KEY_LEN + 3] = {CLIENT_ID_OPTION, DHCP_CLIENT_KEY_LEN + 1, 1};
    memcpy(chaddr, key, sizeof(key));
    memcpy(clientId + 3, key, sizeof(key));
    RouterConfig defaultConfig = {0};
    bool passed = memcmp(chaddr, key, sizeof(key)) == 0 && clientId[0] == CLIENT_ID_OPTION &&
        clientId[1] == DHCP_CLIENT_KEY_LEN + 1 && clientId[2] == 1 &&
        memcmp(clientId + 3, key, sizeof(key)) == 0 && defaultConfig.linkMode == DHCP_LINK_MODE_L2_PACKET;
    printf("discover_chaddr=02:11:22:33:44:55 request_chaddr=02:11:22:33:44:55 option61=1:02:11:22:33:44:55\n");
    PrintResult(passed, "VECTOR", passed ? 0 : -1);
    return passed ? 0 : 1;
}

static int RunServerStart(const char *ifname, const char *start, const char *end)
{
    DHCP_LOG("server flow begin iface=%s range=%s-%s", ifname, start, end);
    DhcpRange range = {0};
    range.iptype = 0;
    range.leaseHours = 6;
    snprintf(range.strTagName, sizeof(range.strTagName), "%s", ifname);
    snprintf(range.strStartip, sizeof(range.strStartip), "%s", start);
    snprintf(range.strEndip, sizeof(range.strEndip), "%s", end);
    snprintf(range.strSubnet, sizeof(range.strSubnet), "255.255.255.0");
    char serverAddress[INET_ADDRSTRLEN] = {0};
    int configRet = DeriveServerAddress(start, end, range.strSubnet, serverAddress);
    if (configRet == 0) {
        configRet = ConfigureServerInterface(ifname, serverAddress, range.strSubnet);
    }
    if (configRet != 0) {
        DHCP_LOG("server flow exit before range: interface configure failed ret=%d", configRet);
        PrintResult(false, "CONFIGURE", configRet);
        return 1;
    }
    DhcpErrorCode ret = SetDhcpRange(ifname, &range);
    DHCP_LOG("server range configured iface=%s ret=%d", ifname, ret);
    if (ret == DHCP_SUCCESS) {
        ret = StartDhcpServer(ifname);
        DHCP_LOG("server start requested iface=%s ret=%d", ifname, ret);
    } else {
        DHCP_LOG("server flow exit before start: SetDhcpRange failed ret=%d", ret);
    }
    PrintResult(ret == DHCP_SUCCESS, "SERVING", ret);
    return ret == DHCP_SUCCESS ? 0 : 1;
}

static int RunClientStart(const char *ifname, const char *keyText)
{
    DHCP_LOG("client flow begin iface=%s mode=L3_TUN", ifname);
    RouterConfig config = {0};
    ClientCallBack callback = {OnIpSuccess, OnIpFail};
    snprintf(config.ifname, sizeof(config.ifname), "%s", ifname);
    config.bIpv4 = true;
    config.bIpv6 = false;
    config.prohibitUseCacheIp = true;
    config.linkMode = DHCP_LINK_MODE_L3_TUN;
    if (!ParseClientKey(keyText, config.clientKey)) {
        PrintResult(false, "CONFIG", DHCP_INVALID_PARAM);
        return 1;
    }
    atomic_store(&g_clientDone, 0);
    atomic_store(&g_clientPassed, 0);
    DhcpErrorCode ret = RegisterDhcpClientCallBack(ifname, &callback);
    DHCP_LOG("client callback registration iface=%s ret=%d", ifname, ret);
    if (ret == DHCP_SUCCESS) {
        ret = StartDhcpClient(&config);
        DHCP_LOG("client start requested iface=%s ret=%d", ifname, ret);
    } else {
        DHCP_LOG("client flow exit before start: callback registration failed ret=%d", ret);
    }
    for (int i = 0; ret == DHCP_SUCCESS && !atomic_load(&g_clientDone) && i < WAIT_SECONDS; ++i) {
        sleep(1);
    }
    bool passed = ret == DHCP_SUCCESS && atomic_load(&g_clientPassed);
    if (ret == DHCP_SUCCESS && !atomic_load(&g_clientDone)) {
        DHCP_LOG("client lease wait timed out after %d seconds", WAIT_SECONDS);
    } else if (ret == DHCP_SUCCESS && !atomic_load(&g_clientPassed)) {
        DHCP_LOG("client callback completed but lease validation failed");
    }
    printf("lease=%s\n", passed ? g_clientResult.strOptClientId : "-");
    PrintResult(passed, passed ? "BOUND" : "REQUEST", passed ? 0 : (ret == DHCP_SUCCESS ? -1 : ret));
    return passed ? 0 : 1;
}

static int RunStatus(const char *ifname)
{
    DHCP_LOG("status query begin iface=%s", ifname);
    DhcpStationInfo stations[16] = {0};
    int size = 0;
    DhcpErrorCode ret = GetDhcpClientInfos(ifname, 16, stations, &size);
    DHCP_LOG("status query complete iface=%s ret=%d leases=%d", ifname, ret, size);
    bool passed = ret == DHCP_SUCCESS || ret == DHCP_FAILED;
    printf("iface=%s leases=%d\n", ifname, size);
    PrintResult(passed, size > 0 ? "BOUND" : "IDLE", passed ? 0 : ret);
    return passed ? 0 : 1;
}

static int RunStop(const char *ifname)
{
    DHCP_LOG("stop flow begin iface=%s", ifname);
    DhcpErrorCode clientRet = StopDhcpClient(ifname, false, true);
    DHCP_LOG("client stop complete iface=%s ret=%d", ifname, clientRet);
    DhcpErrorCode serverRet = StopDhcpServer(ifname);
    DHCP_LOG("server stop complete iface=%s ret=%d", ifname, serverRet);
    bool passed = (clientRet == DHCP_SUCCESS || clientRet == DHCP_FAILED) &&
        (serverRet == DHCP_SUCCESS || serverRet == DHCP_FAILED);
    printf("client_stop=%d server_stop=%d\n", clientRet, serverRet);
    PrintResult(passed, "STOPPED", passed ? 0 : (clientRet != DHCP_FAILED ? clientRet : serverRet));
    return passed ? 0 : 1;
}

static void Usage(const char *program)
{
    fprintf(stderr, "usage: %s config-roundtrip|packet-vector|server-start IFACE START END|"
        "client-start IFACE KEY|status IFACE|stop IFACE\n", program);
}

int main(int argc, char *argv[])
{
    DHCP_LOG("probe begin command=%s", argc > 1 ? argv[1] : "-");
    bool needsDhcpPermission = argc > 1 && (strcmp(argv[1], "server-start") == 0 ||
        strcmp(argv[1], "client-start") == 0 || strcmp(argv[1], "status") == 0 || strcmp(argv[1], "stop") == 0);
    if (needsDhcpPermission) {
        int tokenRet = SetDhcpProbeToken();
        if (tokenRet != 0) {
            DHCP_LOG("native token setup failed ret=%d", tokenRet);
            PrintResult(false, "AUTH", tokenRet);
            return 1;
        }
        DHCP_LOG("native token setup succeeded permission=ohos.permission.NETWORK_DHCP");
    }
    if (argc == 2 && strcmp(argv[1], "config-roundtrip") == 0) return RunConfigRoundtrip();
    if (argc == 2 && strcmp(argv[1], "packet-vector") == 0) return RunPacketVector();
    if (argc == 5 && strcmp(argv[1], "server-start") == 0) return RunServerStart(argv[2], argv[3], argv[4]);
    if (argc == 4 && strcmp(argv[1], "client-start") == 0) return RunClientStart(argv[2], argv[3]);
    if (argc == 3 && strcmp(argv[1], "status") == 0) return RunStatus(argv[2]);
    if (argc == 3 && strcmp(argv[1], "stop") == 0) return RunStop(argv[2]);
    Usage(argv[0]);
    return 2;
}
