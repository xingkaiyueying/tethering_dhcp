"""Run production C-adapter session dispatch with explicit logging/SDK doubles."""
from pathlib import Path
import subprocess
import tempfile

repo = Path(__file__).resolve().parents[2]
text = (repo / 'frameworks/native/src/dhcp_event.cpp').read_text(encoding='utf-8')
methods = text[text.index('void DhcpClientCallBack::OnIpSuccessChanged('):text.index('#ifndef OHOS_ARCH_LITE\nvoid DhcpClientCallBack::OnDhcpOfferReport')]
# GCC host has no OpenHarmony Clang CFI attribute; only this platform annotation is removed.
methods = methods.replace('__attribute__((no_sanitize("cfi")))', '')
with tempfile.TemporaryDirectory(prefix='p2-s3-session-') as directory:
    out = Path(directory)
    (out / 'netinet').mkdir()
    (out / 'netinet/ip.h').write_text('#include <winsock2.h>\n#include <ws2tcpip.h>\n')
    (out / 'test.cpp').write_text(r'''
#include <vector>
#include <string>
#include <map>
#include <mutex>
#include <cassert>
#include <cstring>
#include <cstdio>
#include "dhcp_result_event.h"
#include "dhcp_l3_ipv6.h"
#define DHCP_LOGI(...) ((void)0)
#define DHCP_LOGE(...) ((void)0)
#define EOK 0
int strcpy_s(char*d,size_t n,const char*s){if(strlen(s)>=n)return -1;strcpy(d,s);return 0;}
namespace OHOS::DHCP {
struct Address {std::string address;uint32_t ifindex=7,prefixLength=64,flags=0,preferredLifetime=60,validLifetime=120;};
struct DhcpResult {int iptype=0;bool isOptSuc=true,l3Ipv6=false;uint32_t uLeaseTime=0,uAddTime=0,uGetTime=0,
validLifetime=0,preferredLifetime=0,routeLifetime=0;uint8_t raFlags=0;
std::vector<std::string> vectorDnsAddr;std::vector<Address> l3Addresses;};
}
class DhcpClientCallBack {public:
uint64_t sessionGeneration=0;
void (*sessionSuccess)(uint64_t,int,const char*,const DhcpResult*,const DhcpL3Ipv6Snapshot*)=nullptr;
void (*sessionFailure)(uint64_t,int,const char*,const char*)=nullptr;
std::mutex callBackMutex;
std::map<std::string,void (*)(const char*,const DhcpL3Ipv6Snapshot*)> l3Callbacks;
std::map<std::string,const ClientCallBack*> mapClientCallBack;
void ResultInfoCopy(DhcpResult&,OHOS::DHCP::DhcpResult&){}
void OnIpSuccessChanged(int,const std::string&,OHOS::DHCP::DhcpResult&);
void OnIpFailChanged(int,const std::string&,const std::string&);
};
''' + methods + r'''
std::vector<uint64_t> sessions;std::vector<int> failures;bool paired=false;
void Success(uint64_t session,int,const char*,const DhcpResult*r,const DhcpL3Ipv6Snapshot*s){
sessions.push_back(session);paired=s && r->iptype==1 && s->addressCount==1 && s->addresses[0].ifindex==7;}
void Failure(uint64_t session,int code,const char*,const char*){sessions.push_back(session);failures.push_back(code);}
int main(){
 DhcpClientCallBack old,current;old.sessionGeneration=11;current.sessionGeneration=22;
 old.sessionSuccess=current.sessionSuccess=Success;old.sessionFailure=current.sessionFailure=Failure;
 OHOS::DHCP::DhcpResult r;r.l3Ipv6=true;r.iptype=1;r.l3Addresses.push_back({"fd77:77:1::2"});
 current.OnIpSuccessChanged(0,"sleip0",r);assert(paired);
 old.OnIpSuccessChanged(0,"sleip0",r);assert(paired&&sessions[0]==22&&sessions[1]==11);
 old.OnIpFailChanged(0x10001,"sleip0","v6");assert(sessions.back()==11&&failures.back()==0x10001);
 r.iptype=0;r.l3Ipv6=false;current.OnIpSuccessChanged(0,"sleip0",r);assert(!paired);
 puts("DHCP session adapter: immutable callback generation, paired address/result snapshot, IPv6 failure source, IPv4 path PASS");
}
''')
    exe = out / 'test.exe'
    subprocess.run(['g++', '-std=c++17', f'-I{out}', f'-I{repo / "interfaces/kits/c"}',
                    str(out / 'test.cpp'), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
# These are wiring checks, not a real Binder test.
proxy = (repo / 'frameworks/native/src/dhcp_client_proxy.cpp').read_text()
assert 'ifname == "sleip0"' in proxy and 'data.WriteRemoteObject(callbackStub->AsObject())' in proxy
assert '"RegisterDhcpClientL3Session";' in (repo / 'frameworks/native/libdhcp_sdk.map').read_text()
print('private session export and distinct Binder target wiring: PASS (static only)')
