"""Call the production legacy config copy with an old object ending at a guard page."""
from pathlib import Path
import subprocess
import tempfile

repo = Path(__file__).resolve().parents[2]
base = '96e26d3aef6dcc17dc0007908a25289b2f8f096e'
relative = 'interfaces/inner_api/include/dhcp_define.h'
old_header = subprocess.run(
    ['git', '-c', f'safe.directory={repo.as_posix()}', '-C', str(repo), 'show', f'{base}:{relative}'],
    capture_output=True, text=True, check=True).stdout
new_header = (repo / relative).read_text(encoding='utf-8')
source = (repo / 'frameworks/native/src/dhcp_client_impl.cpp').read_text(encoding='utf-8')


def router_struct(header):
    start = header.index('struct RouterConfig {')
    return header[start:header.index('\n};', start) + 3]


helper_start = source.index('RouterConfig CopyLegacyRouterConfig(')
helper = source[helper_start:source.index('} // namespace', helper_start)]
assert 'CopyLegacyRouterConfig(config)' in source[source.index('ErrCode DhcpClientImpl::StartDhcpClient('):
                                                  source.index('ErrCode DhcpClientImpl::StartDhcpClientL3(')]

with tempfile.TemporaryDirectory(prefix='p2-dhcp-old-abi-') as directory:
    out = Path(directory)
    test = r'''
#include <windows.h>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>
#include <string>
constexpr int ETH_MAC_ADDR_LEN = 6;
namespace Old { OLD_STRUCT }
namespace OHOS::DHCP {
enum class DhcpLinkMode : uint8_t { L2_PACKET, L3_TUN };
NEW_STRUCT
HELPER
}
int main()
{
    using OldConfig = Old::RouterConfig;
    using NewConfig = OHOS::DHCP::RouterConfig;
    static_assert(offsetof(OldConfig, bIpv4) == offsetof(NewConfig, bIpv4));
    SYSTEM_INFO system{};
    GetSystemInfo(&system);
    auto size = static_cast<size_t>(system.dwPageSize);
    auto *pages = static_cast<char *>(VirtualAlloc(nullptr, size * 2, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    assert(pages != nullptr);
    DWORD previous = 0;
    assert(VirtualProtect(pages + size, size, PAGE_NOACCESS, &previous));
    auto *legacy = new (pages + size - sizeof(OldConfig)) OldConfig{};
    legacy->ifname = "wlan0";
    legacy->bssid = "aa:bb:cc:dd:ee:ff";
    legacy->bIpv4 = true;
    auto *padding = reinterpret_cast<unsigned char *>(&legacy->bIpv4) + sizeof(legacy->bIpv4);
    auto *end = reinterpret_cast<unsigned char *>(legacy) + sizeof(OldConfig);
    std::memset(padding, 0xff, static_cast<size_t>(end - padding));
    const auto &view = *reinterpret_cast<const NewConfig *>(legacy);
    auto safe = OHOS::DHCP::CopyLegacyRouterConfig(view);
    assert(safe.ifname == "wlan0" && safe.bssid == legacy->bssid);
    assert(safe.linkMode == OHOS::DHCP::DhcpLinkMode::L2_PACKET);
    assert(safe.clientKey == NewConfig{}.clientKey);
    legacy->~OldConfig();
    assert(VirtualFree(pages, 0, MEM_RELEASE));
}
'''
    (out / 'test.cpp').write_text(test.replace('OLD_STRUCT', router_struct(old_header))
                                  .replace('NEW_STRUCT', router_struct(new_header))
                                  .replace('HELPER', helper), encoding='utf-8')
    exe = out / 'test.exe'
    subprocess.run(['g++', '-std=c++17', '-fno-strict-aliasing', str(out / 'test.cpp'),
                    '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
    print('Old RouterConfig prefix: guarded legacy copy and L2 default PASS (Windows host ABI)')
