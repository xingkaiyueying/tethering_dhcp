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

#include <cstring>

// The server worker selects its private binding namespace for one request.
// The worker uses the existing DHCP structures and function-pointer signatures.
extern thread_local bool g_nearlinkBindingScope;
class NearlinkDhcpBindingScope final {
public:
    explicit NearlinkDhcpBindingScope(const char *iface) : previous_(g_nearlinkBindingScope)
    {
        g_nearlinkBindingScope = iface && std::strcmp(iface, "sleip0") == 0;
    }
    ~NearlinkDhcpBindingScope()
    {
        g_nearlinkBindingScope = previous_;
    }
    NearlinkDhcpBindingScope(const NearlinkDhcpBindingScope &) = delete;
    NearlinkDhcpBindingScope &operator=(const NearlinkDhcpBindingScope &) = delete;

private:
    bool previous_;
};
#endif
