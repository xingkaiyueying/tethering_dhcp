/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>

#include "dhcp_server_service_impl.h"
#include "dhcp_errcode.h"
#include "system_func_mock.h"
#include "dhcp_function.h"
#include "dhcp_logger.h"

DEFINE_DHCPLOG_DHCP_LABEL("DhcpServerServiceTest");

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::DHCP;
namespace OHOS {
namespace DHCP {
constexpr int ZERO = 0;
class DhcpServerServiceTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {
        pServerServiceImpl = std::make_unique<OHOS::DHCP::DhcpServerServiceImpl>();
    }
    virtual void TearDown()
    {
        if (pServerServiceImpl != nullptr) {
            pServerServiceImpl.reset(nullptr);
        }
    }
public:
    std::unique_ptr<OHOS::DHCP::DhcpServerServiceImpl> pServerServiceImpl;
};

HWTEST_F(DhcpServerServiceTest, DhcpServerServiceImplTest, TestSize.Level1)
{
    ASSERT_TRUE(pServerServiceImpl != nullptr);
    DHCP_LOGE("enter IsNativeProcess is fail test.");

    std::string ifname = "wlan0";
    std::string tagName = "sta";
    DhcpRange putRange;
    putRange.iptype = 0;
    DhcpRange setRange;
    setRange.iptype = 0;
    EXPECT_EQ(DHCP_E_SUCCESS, pServerServiceImpl->StopDhcpServer("wlan1"));
    EXPECT_EQ(DHCP_E_FAILED, pServerServiceImpl->StopDhcpServer(""));
    EXPECT_EQ(DHCP_E_FAILED, pServerServiceImpl->PutDhcpRange(tagName, putRange));
    EXPECT_EQ(DHCP_E_FAILED, pServerServiceImpl->PutDhcpRange("", putRange));
    EXPECT_EQ(DHCP_E_SUCCESS, pServerServiceImpl->RemoveDhcpRange(tagName, putRange));
    EXPECT_EQ(DHCP_E_FAILED, pServerServiceImpl->RemoveDhcpRange("", putRange));
    EXPECT_EQ(DHCP_E_SUCCESS, pServerServiceImpl->RemoveAllDhcpRange(tagName));
    EXPECT_EQ(DHCP_E_FAILED, pServerServiceImpl->RemoveAllDhcpRange(""));
    EXPECT_EQ(DHCP_E_FAILED, pServerServiceImpl->SetDhcpRange(ifname, setRange));
    setRange.strStartip = "192.168.2.2";
    setRange.strEndip = "192.168.2.200";
    setRange.strSubnet = "255.255.255.0";
    EXPECT_EQ(DHCP_E_FAILED, pServerServiceImpl->SetDhcpRange(ifname, setRange));
    EXPECT_EQ(DHCP_E_FAILED, pServerServiceImpl->StartDhcpServer(ifname));
    EXPECT_EQ(DHCP_E_FAILED, pServerServiceImpl->StartDhcpServer(""));
    EXPECT_EQ(DHCP_E_FAILED, pServerServiceImpl->SetDhcpName(ifname, tagName));
    EXPECT_EQ(DHCP_E_FAILED, pServerServiceImpl->SetDhcpName("", tagName));
    EXPECT_EQ(DHCP_E_FAILED, pServerServiceImpl->SetDhcpName(ifname, ""));
    EXPECT_EQ(DHCP_E_FAILED, pServerServiceImpl->SetDhcpName("", ""));
    EXPECT_EQ(DHCP_E_FAILED, pServerServiceImpl->SetDhcpNameExt(ifname, tagName));
    EXPECT_EQ(DHCP_E_FAILED, pServerServiceImpl->SetDhcpNameExt("", tagName));
    EXPECT_EQ(DHCP_E_FAILED, pServerServiceImpl->SetDhcpNameExt(ifname, ""));
    EXPECT_EQ(DHCP_E_FAILED, pServerServiceImpl->SetDhcpNameExt("", ""));

    std::vector<std::string> vecLeases;
    EXPECT_EQ(DHCP_E_FAILED, pServerServiceImpl->GetDhcpClientInfos(ifname, vecLeases));
    EXPECT_EQ(DHCP_E_FAILED, pServerServiceImpl->GetDhcpClientInfos("", vecLeases));
    std::string strLeaseTime;
    EXPECT_EQ(DHCP_E_SUCCESS, pServerServiceImpl->UpdateLeasesTime(strLeaseTime));
}

HWTEST_F(DhcpServerServiceTest, DhcpServerService_Test5, TestSize.Level1)
{
    DHCP_LOGE("enter DhcpServerService_Test5.");
    ASSERT_TRUE(pServerServiceImpl != nullptr);

    EXPECT_EQ(DHCP_OPT_ERROR, pServerServiceImpl->CheckAndUpdateConf(""));
    EXPECT_EQ(DHCP_E_SUCCESS, pServerServiceImpl->CheckAndUpdateConf("wlan1"));

    std::string ipRange;
    EXPECT_EQ(DHCP_OPT_ERROR, pServerServiceImpl->GetUsingIpRange("", ipRange));
    EXPECT_EQ(DHCP_E_FAILED, pServerServiceImpl->GetUsingIpRange("ww", ipRange));
    EXPECT_EQ(DHCP_E_FAILED, pServerServiceImpl->GetUsingIpRange("wlan0", ipRange));

    DhcpRange checkRange;
    EXPECT_EQ(false, pServerServiceImpl->CheckIpAddrRange(checkRange));
    checkRange.iptype = 0;
    checkRange.strStartip = "192.168.0";
    checkRange.strEndip = "192.168.1";
    EXPECT_EQ(false, pServerServiceImpl->CheckIpAddrRange(checkRange));
    checkRange.strStartip = "192.168.0.49";
    checkRange.strEndip = "192.168.1";
    EXPECT_EQ(false, pServerServiceImpl->CheckIpAddrRange(checkRange));
    checkRange.strStartip = "192.168.0.2";
    checkRange.strEndip = "192.168.0.2";
    EXPECT_EQ(true, pServerServiceImpl->CheckIpAddrRange(checkRange));
    checkRange.strEndip = "192.168.0.1";
    EXPECT_EQ(false, pServerServiceImpl->CheckIpAddrRange(checkRange));

    checkRange.iptype = 1;
    checkRange.strStartip = "fe80:fac8";
    EXPECT_EQ(false, pServerServiceImpl->CheckIpAddrRange(checkRange));
    checkRange.strStartip = "fe80::fac8";
    checkRange.strEndip = "fe80:fac8";
    EXPECT_EQ(false, pServerServiceImpl->CheckIpAddrRange(checkRange));

    std::string ifname;
    EXPECT_EQ(DHCP_OPT_ERROR, pServerServiceImpl->AddSpecifiedInterface(ifname));
    ifname = "wlan";
    EXPECT_EQ(DHCP_E_SUCCESS, pServerServiceImpl->AddSpecifiedInterface(ifname));
    EXPECT_EQ(DHCP_E_SUCCESS, pServerServiceImpl->AddSpecifiedInterface(ifname));

    ifname.clear();
    EXPECT_EQ(DHCP_OPT_ERROR, pServerServiceImpl->DelSpecifiedInterface(ifname));
    ifname = "wlan";
    EXPECT_EQ(DHCP_E_SUCCESS, pServerServiceImpl->DelSpecifiedInterface(ifname));
    EXPECT_EQ(DHCP_E_SUCCESS, pServerServiceImpl->DelSpecifiedInterface(ifname));

    std::string strFile = DHCP_SERVER_LEASES_FILE + "." + ifname;
    std::string strTestData = "dhcp server leases file test";
    ASSERT_TRUE(DhcpFunction::CreateFile(strFile, strTestData));
    std::vector<std::string> vecLeases;
    EXPECT_EQ(DHCP_E_SUCCESS, pServerServiceImpl->GetDhcpClientInfos(ifname, vecLeases));
    ASSERT_TRUE(DhcpFunction::RemoveFile(strFile));
}

HWTEST_F(DhcpServerServiceTest, CreateDefaultConfigFileTest, TestSize.Level1)
{
    ASSERT_TRUE(pServerServiceImpl != nullptr);
    std::string strFile;

    strFile = "";
    EXPECT_EQ(DHCP_OPT_ERROR, pServerServiceImpl->CreateDefaultConfigFile(strFile));
    strFile = "wlan0";
    EXPECT_EQ(DHCP_OPT_SUCCESS, pServerServiceImpl->CreateDefaultConfigFile(strFile));
}

HWTEST_F(DhcpServerServiceTest, OnStartTest, TestSize.Level1)
{
    DHCP_LOGE("enter OnStartTest");
    pServerServiceImpl->OnStart();
    EXPECT_EQ(DHCP_OPT_SUCCESS, ZERO);
}

HWTEST_F(DhcpServerServiceTest, OnStopTest, TestSize.Level1)
{
    DHCP_LOGE("enter OnStopTest");
    pServerServiceImpl->OnStop();
    EXPECT_EQ(DHCP_OPT_SUCCESS, ZERO);
}

HWTEST_F(DhcpServerServiceTest, IsRemoteDiedTest, TestSize.Level1)
{
    DHCP_LOGE("enter IsRemoteDiedTest");
    ASSERT_TRUE(pServerServiceImpl != nullptr);

    EXPECT_EQ(true, pServerServiceImpl->IsRemoteDied());
}

HWTEST_F(DhcpServerServiceTest, DeleteLeaseFileTest, TestSize.Level1)
{
    DHCP_LOGI("enter DeleteLeaseFileTest");
    ASSERT_TRUE(pServerServiceImpl != nullptr);
    std::string ifname;
    EXPECT_EQ(DHCP_E_FAILED, pServerServiceImpl->DeleteLeaseFile(ifname));
}

HWTEST_F(DhcpServerServiceTest, DeviceInfoCallBackTest, TestSize.Level1)
{
    DHCP_LOGI("enter DealServerSuccessTest");
    ASSERT_TRUE(pServerServiceImpl != nullptr);
    std::string ifname;
    pServerServiceImpl->DeviceInfoCallBack(ifname);
    ifname = "wlan0";
    pServerServiceImpl->DeviceInfoCallBack(ifname);
}

HWTEST_F(DhcpServerServiceTest, ConvertLeasesToStationInfosTest, TestSize.Level1)
{
    DHCP_LOGI("enter ConvertLeasesToStationInfosTest");
    ASSERT_TRUE(pServerServiceImpl != nullptr);
    std::vector<std::string> leases;
    std::vector<DhcpStationInfo> stationInfos;
    pServerServiceImpl->ConvertLeasesToStationInfos(leases, stationInfos);
    std::string leasesInfo = "68:77:24:77:8f:6b 192.168.43.5 21600 1720428443 1720424415 0 1 2 DESKT-OSNYRBJKJ";
    leases.push_back(leasesInfo);
    pServerServiceImpl->ConvertLeasesToStationInfos(leases, stationInfos);
}

HWTEST_F(DhcpServerServiceTest, DeviceConnectCallBackTest, TestSize.Level1)
{
    DHCP_LOGI("enter GDealServerSuccessTest");
    std::string ifname;
    DeviceConnectCallBack(ifname.c_str());
    ifname = "wlan0";
    DeviceConnectCallBack(ifname.c_str());

    DeviceConnectCallBack(nullptr);
    EXPECT_EQ(DHCP_OPT_SUCCESS, ZERO);
}

HWTEST_F(DhcpServerServiceTest, m_mapInfDhcpRange_TEST, TestSize.Level1)
{
    std::string ipRange = "192.168.1.100";
    DhcpRange range;
    range.strTagName = "test_ifname";
    range.strStartip = "192.168.1.1";
    range.strEndip = "192.168.1.100";
    range.strSubnet = "255.255.255.0";
    range.iptype = 0;
    DhcpRange putRange;
    putRange.iptype = 0;
    pServerServiceImpl->m_mapInfDhcpRange["test_ifname"];
    EXPECT_EQ(pServerServiceImpl->GetUsingIpRange("test_ifname", ipRange), DHCP_OPT_FAILED);
    EXPECT_EQ(pServerServiceImpl->SetDhcpRange("test_ifname", range), DHCP_E_FAILED);
    EXPECT_EQ(pServerServiceImpl->StopDhcpServer("test_ifname"), DHCP_E_SUCCESS);
    EXPECT_EQ(pServerServiceImpl->CheckAndUpdateConf("test_ifname"), DHCP_E_SUCCESS);
}

HWTEST_F(DhcpServerServiceTest, PutDhcpRangeTest, TestSize.Level1)
{
    DhcpRange range;
    range.strTagName = "test_tag";
    range.strStartip = "192.168.1.1";
    range.strEndip = "192.168.1.100";
    range.strSubnet = "255.255.255.0";
    range.iptype = 0;
    pServerServiceImpl->m_mapTagDhcpRange["test_tag"];
    EXPECT_EQ(pServerServiceImpl->PutDhcpRange("test_tag", range), DHCP_E_SUCCESS);
    EXPECT_EQ(pServerServiceImpl->SetDhcpNameExt("test_tag", "test_tag"), DHCP_E_FAILED);
}
}
}