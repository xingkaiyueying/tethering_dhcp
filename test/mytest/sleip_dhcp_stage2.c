/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
#include <arpa/inet.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dhcp_c_api.h"

#define WAIT_SECONDS 60
#define CLIENT_ID_OPTION 61

static atomic_int g_clientDone;
static atomic_int g_clientPassed;
static DhcpResult g_clientResult;

static void PrintResult(bool passed, const char *phase, int code)
{
    printf("RESULT=%s phase=%s code=%d\n", passed ? "PASS" : "FAIL", phase, code);
}

static bool ParseClientKey(const char *text, uint8_t key[DHCP_CLIENT_KEY_LEN])
{
    unsigned int value[DHCP_CLIENT_KEY_LEN];
    char tail = '\0';
    if (sscanf(text, "%2x:%2x:%2x:%2x:%2x:%2x%c", &value[0], &value[1], &value[2], &value[3],
        &value[4], &value[5], &tail) != DHCP_CLIENT_KEY_LEN) {
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

static void OnIpSuccess(int status, const char *ifname, DhcpResult *result)
{
    (void)status;
    (void)ifname;
    if (result != NULL) {
        g_clientResult = *result;
        atomic_store(&g_clientPassed, result->isOptSuc && IsExpectedLease(result->strOptClientId));
    }
    atomic_store(&g_clientDone, 1);
}

static void OnIpFail(int status, const char *ifname, const char *reason)
{
    (void)status;
    (void)ifname;
    (void)reason;
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
    DhcpRange range = {0};
    range.iptype = 0;
    range.leaseHours = 6;
    snprintf(range.strTagName, sizeof(range.strTagName), "%s", ifname);
    snprintf(range.strStartip, sizeof(range.strStartip), "%s", start);
    snprintf(range.strEndip, sizeof(range.strEndip), "%s", end);
    snprintf(range.strSubnet, sizeof(range.strSubnet), "255.255.255.0");
    DhcpErrorCode ret = SetDhcpRange(ifname, &range);
    if (ret == DHCP_SUCCESS) {
        ret = StartDhcpServer(ifname);
    }
    PrintResult(ret == DHCP_SUCCESS, "SERVING", ret);
    return ret == DHCP_SUCCESS ? 0 : 1;
}

static int RunClientStart(const char *ifname, const char *keyText)
{
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
    if (ret == DHCP_SUCCESS) {
        ret = StartDhcpClient(&config);
    }
    for (int i = 0; ret == DHCP_SUCCESS && !atomic_load(&g_clientDone) && i < WAIT_SECONDS; ++i) {
        sleep(1);
    }
    bool passed = ret == DHCP_SUCCESS && atomic_load(&g_clientPassed);
    printf("lease=%s\n", passed ? g_clientResult.strOptClientId : "-");
    PrintResult(passed, passed ? "BOUND" : "REQUEST", passed ? 0 : (ret == DHCP_SUCCESS ? -1 : ret));
    return passed ? 0 : 1;
}

static int RunStatus(const char *ifname)
{
    DhcpStationInfo stations[16] = {0};
    int size = 0;
    DhcpErrorCode ret = GetDhcpClientInfos(ifname, 16, stations, &size);
    bool passed = ret == DHCP_SUCCESS || ret == DHCP_FAILED;
    printf("iface=%s leases=%d\n", ifname, size);
    PrintResult(passed, size > 0 ? "BOUND" : "IDLE", passed ? 0 : ret);
    return passed ? 0 : 1;
}

static int RunStop(const char *ifname)
{
    DhcpErrorCode clientRet = StopDhcpClient(ifname, false, true);
    DhcpErrorCode serverRet = StopDhcpServer(ifname);
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
    if (argc == 2 && strcmp(argv[1], "config-roundtrip") == 0) return RunConfigRoundtrip();
    if (argc == 2 && strcmp(argv[1], "packet-vector") == 0) return RunPacketVector();
    if (argc == 5 && strcmp(argv[1], "server-start") == 0) return RunServerStart(argv[2], argv[3], argv[4]);
    if (argc == 4 && strcmp(argv[1], "client-start") == 0) return RunClientStart(argv[2], argv[3]);
    if (argc == 3 && strcmp(argv[1], "status") == 0) return RunStatus(argv[2]);
    if (argc == 3 && strcmp(argv[1], "stop") == 0) return RunStop(argv[2]);
    Usage(argv[0]);
    return 2;
}
