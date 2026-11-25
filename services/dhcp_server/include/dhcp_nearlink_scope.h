/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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
#ifndef DHCP_NEARLINK_SCOPE_H
#define DHCP_NEARLINK_SCOPE_H

#include <cctype>
#include <string>

inline bool IsNearlinkDhcpInterface(const std::string &iface)
{
    if (iface.size() < 6 || iface.size() >= 16 || iface.compare(0, 5, "sleip") != 0) {
        return false;
    }
    for (size_t i = 5; i < iface.size(); ++i) {
        if (!std::isdigit(static_cast<unsigned char>(iface[i]))) {
            return false;
        }
    }
    return true;
}
// Select the current interface's binding records for calls through the existing pool callbacks.
std::string SetNearlinkBindingScope(const std::string &iface);
bool HasNearlinkBindingScope();

class DhcpNearlinkBindingScope final {
public:
    explicit DhcpNearlinkBindingScope(const std::string &iface) : previous_(SetNearlinkBindingScope(iface)) {}
    ~DhcpNearlinkBindingScope()
    {
        SetNearlinkBindingScope(previous_);
    }
    DhcpNearlinkBindingScope(const DhcpNearlinkBindingScope &) = delete;
    DhcpNearlinkBindingScope &operator=(const DhcpNearlinkBindingScope &) = delete;

private:
    std::string previous_;
};
#endif
