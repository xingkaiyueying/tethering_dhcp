/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_DHCP_SERVER_C_H
#define OHOS_DHCP_SERVER_C_H

#include <string>

typedef void(*DeviceConnectFun)(const char *ifname);
int StartDhcpServerMain(const std::string& ifName, const std::string& netMask, const std::string& ipRange,
    const std::string& localIp);
int StopDhcpServerMain();
int StopNearlinkDhcpServerMain(const std::string &ifName);
int RegisterDeviceConnectCallBack(DeviceConnectFun fun);
#endif