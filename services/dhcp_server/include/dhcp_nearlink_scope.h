/* Copyright (c) 2026 Huawei Device Co., Ltd. Licensed under the Apache License, Version 2.0. */
#ifndef DHCP_NEARLINK_SCOPE_H
#define DHCP_NEARLINK_SCOPE_H
#include <string>
#include <cctype>
inline bool IsNearlinkDhcpInterface(const std::string &iface)
{
    if (iface.size() < 6 || iface.size() >= 16 || iface.compare(0, 5, "sleip") != 0)
        return false;
    for (size_t i = 5; i < iface.size(); ++i)
        if (!std::isdigit(static_cast<unsigned char>(iface[i])))
            return false;
    return true;
}
// Scope is internal to the server worker; old pool callback signatures/layout stay intact.
std::string SetNearlinkBindingScope(const std::string &iface);
bool HasNearlinkBindingScope();
class DhcpNearlinkBindingScope final {
  public:
    explicit DhcpNearlinkBindingScope(const std::string &iface) : previous_(SetNearlinkBindingScope(iface)) {}
    ~DhcpNearlinkBindingScope()
    {
        SetNearlinkBindingScope(previous_);
    }

  private:
    std::string previous_;
};
#endif
