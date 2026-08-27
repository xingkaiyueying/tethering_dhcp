/*
 * Host-side check for DHCP V2 lease timing. No OpenHarmony runtime required.
 * g++ -std=c++17 -I../../interfaces/inner_api/include dhcp_l3_config_v2_host_test.cpp
 */
#include "dhcp_l3_lease_timing.h"

#include <cstdio>

using OHOS::DHCP::DeriveAndValidateLeaseTiming;

static int Fail(const char *msg)
{
    std::fprintf(stderr, "FAIL %s\n", msg);
    return 1;
}

int main()
{
    uint32_t t1 = 0;
    uint32_t t2 = 0;
    if (DeriveAndValidateLeaseTiming(0, t1, t2)) {
        return Fail("leaseSeconds=0 must be rejected");
    }
    t1 = 0;
    t2 = 0;
    if (!DeriveAndValidateLeaseTiming(86400, t1, t2) || t1 != 43200 || t2 != 75600) {
        return Fail("86400 should derive T1=1/2 T2=7/8");
    }
    t1 = 0;
    t2 = 0;
    if (!DeriveAndValidateLeaseTiming(120, t1, t2) || t1 != 60 || t2 != 105) {
        return Fail("120 should derive T1=60 T2=105");
    }
    t1 = 90;
    t2 = 100;
    if (!DeriveAndValidateLeaseTiming(120, t1, t2) || t1 != 90 || t2 != 100) {
        return Fail("explicit T1=90 T2=100 lease=120 should pass");
    }
    t1 = 80;
    t2 = 40;
    if (DeriveAndValidateLeaseTiming(120, t1, t2)) {
        return Fail("T1 > T2 must be rejected");
    }
    t1 = 0;
    t2 = 120;
    if (DeriveAndValidateLeaseTiming(120, t1, t2)) {
        return Fail("T2 == leaseSeconds must be rejected");
    }
    std::printf("PASS dhcp v2 lease timing\n");
    return 0;
}
