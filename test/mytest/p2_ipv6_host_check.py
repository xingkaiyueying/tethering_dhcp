"""Compile the actual L3 address parser and DNS repository with Linux/platform boundary stubs."""
from pathlib import Path
import subprocess
import tempfile

repo = Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix='p2-dhcp-') as directory:
    out = Path(directory)
    def put(name, text):
        (out/name).write_text(text, encoding='utf-8')
    put('securec.h', '''#pragma once
#include <cstring>
#define EOK 0
inline int memcpy_s(void*d,size_t n,const void*s,size_t k){if(k>n)return -1;memcpy(d,s,k);return 0;}
inline int memset_s(void*d,size_t n,int c,size_t k){if(k>n)return -1;memset(d,c,k);return 0;}
inline int strcpy_s(char*d,size_t n,const char*s){if(strlen(s)>=n)return -1;strcpy(d,s);return 0;}
''')
    production = (repo/'services/dhcp_client/src/dhcp_ipv6_event.cpp').read_text(encoding='utf-8')
    parser = production.split('bool DhcpIpv6Client::ParseL3Address(void *msg)', 1)[1].split(
        'void DhcpIpv6Client::NotifyRaFlagsChanged', 1)[0]
    put('parser.cpp', '''#include <algorithm>
#include <vector>
#include <map>
#include <string>
#include <mutex>
#include <cassert>
#include <iostream>
#include <cstdint>
#include <chrono>
#include "securec.h"
constexpr int AF_INET6=10, DHCP_INET6_ADDRSTRLEN=128;
constexpr int IFA_ADDRESS=1, IFA_CACHEINFO=6, IFA_FLAGS=8, IFA_F_TENTATIVE=0x40, IFA_F_DADFAILED=8;
constexpr int RTM_NEWADDR=20, RTM_DELADDR=21;
struct nlmsghdr{uint32_t nlmsg_len; uint16_t nlmsg_type,nlmsg_flags; uint32_t seq,pid;};
struct ifaddrmsg{uint8_t ifa_family,ifa_prefixlen,ifa_flags,scope; uint32_t ifa_index;};
struct rtattr{uint16_t rta_len,rta_type;};
struct ifa_cacheinfo{uint32_t ifa_prefered,ifa_valid,created,updated;};
#define ALIGN(n) (((n)+3)&~3)
#define NLMSG_DATA(p) ((char*)(p)+16)
#define IFA_PAYLOAD(p) ((p)->nlmsg_len-24)
#define IFA_RTA(p) ((rtattr*)((char*)(p)+8))
#define RTA_PAYLOAD(p) ((p)->rta_len-4)
#define RTA_DATA(p) ((char*)(p)+4)
#define RTA_OK(p,n) ((n)>=4 && (p)->rta_len>=4 && (p)->rta_len<=(n))
#define RTA_NEXT(p,n) ((n)-=ALIGN((p)->rta_len),(rtattr*)((char*)(p)+ALIGN((p)->rta_len)))
struct L3Ipv6Address{std::string address;uint64_t observedAt=0;uint32_t ifindex=0,prefixLength=0,flags=0,preferredLifetime=0,validLifetime=0;};
enum class AddrType{GLOBAL};
struct DhcpIpv6Client {
 std::mutex mutex_;
 struct {std::vector<L3Ipv6Address> l3Addresses;std::map<std::string,int> IpAddrMap;bool l3Ipv6=false;} dhcpIpv6Info;
 int GetIpFromS6Address(void*p,int,char*out,int n){return strcpy_s(out,n,("fd77::"+std::to_string(((uint8_t*)p)[15])).c_str());}
 bool ParseL3Address(void*);
};
bool DhcpIpv6Client::ParseL3Address(void *msg)''' + parser + '''
struct Message {
 nlmsghdr header{72,RTM_NEWADDR,0,0,0}; ifaddrmsg info{10,64,0,0,7};
 rtattr cache{20,IFA_CACHEINFO}; ifa_cacheinfo life{30,90,0,0};
 rtattr flagsAttr{8,IFA_FLAGS}; uint32_t flags=IFA_F_TENTATIVE;
 rtattr addressAttr{20,IFA_ADDRESS}; uint8_t address[16]{};
};
int main(){
 static_assert(sizeof(Message)==72);
 DhcpIpv6Client client; Message msg; msg.address[0]=0xfd; msg.address[15]=2;
 assert(client.ParseL3Address(&msg)); auto &s=client.dhcpIpv6Info;
 assert(s.l3Addresses.size()==1 && s.IpAddrMap.empty());
 assert(s.l3Addresses[0].preferredLifetime==30 && s.l3Addresses[0].flags==IFA_F_TENTATIVE);
 msg.flags=0; assert(client.ParseL3Address(&msg) && s.IpAddrMap.size()==1);
 msg.address[15]=3; msg.flags=IFA_F_DADFAILED;
 assert(client.ParseL3Address(&msg) && s.IpAddrMap.size()==1 && s.l3Addresses.size()==2);
 msg.header.nlmsg_type=RTM_DELADDR; assert(client.ParseL3Address(&msg) && s.l3Addresses.size()==1);
 msg.header.nlmsg_type=RTM_NEWADDR; msg.life.ifa_prefered=91;
 assert(!client.ParseL3Address(&msg) && s.l3Addresses.size()==1);
 msg.life.ifa_prefered=30; msg.addressAttr.rta_len=19; assert(!client.ParseL3Address(&msg));
 msg.addressAttr.rta_len=20; msg.flags=0;
 for(int i=3;i<=9;++i){msg.address[15]=i;assert(client.ParseL3Address(&msg));}
 msg.address[15]=10;assert(!client.ParseL3Address(&msg) && s.IpAddrMap.size()==8);
 std::cout<<"L3 netlink parser: attribute ordering, DAD states, per-address lifetime/delete, capacity PASS\\n";
}
''')
    subprocess.run(['g++','-std=c++17','-Wall','-Wextra','-Werror','-I'+str(out),str(out/'parser.cpp'),'-o',str(out/'parser.exe')],check=True)
    subprocess.run([str(out/'parser.exe')],check=True)
    put('dhcp_logger.h', '#define DEFINE_DHCPLOG_DHCP_LABEL(...)\n#define DHCP_LOGI(...) ((void)0)\n#define DHCP_LOGE(...) ((void)0)\n')
    put('dhcp_ipv6_define.h', '')
    put('dhcp_ipv6_info.h', '''#pragma once
#include <algorithm>
#include <chrono>
#include <vector>
#include <string>
#include <cstdint>
#include <chrono>
namespace OHOS { namespace DHCP {
constexpr int DHCP_INET6_ADDRSTRLEN=128;
struct DhcpIpv6Info{char dnsAddr[128]{},dnsAddr2[128]{};std::vector<std::string> vectorDnsAddr;};
struct DnsServerEntry{std::string address;uint64_t expiry;};
}}
''')
    for name in ('include/dhcp_ipv6_dns_repository.h','src/dhcp_ipv6_dns_repository.cpp'):
        put(Path(name).name,(repo/'services/dhcp_client'/name).read_text(encoding='utf-8'))
    put('dns.cpp','''#include "dhcp_ipv6_dns_repository.cpp"
#include <cassert>
#include <thread>
#include <iostream>
int main(){using namespace OHOS::DHCP;DnsServerRepository r(0);DhcpIpv6Info info;
 assert(r.AddServers(30,{"fd77::53"})); assert(r.AddServers(1,{"fd77::54"}));
 assert(r.SetCurrentServers(info) && info.vectorDnsAddr.size()==2);
 std::this_thread::sleep_for(std::chrono::milliseconds(1100));
 assert(r.Expire());r.SetCurrentServers(info);assert(info.vectorDnsAddr.size()==1 && info.vectorDnsAddr[0]=="fd77::53");
 assert(r.AddServers(0,{"fd77::53"}));r.SetCurrentServers(info);assert(info.vectorDnsAddr.empty());
 std::cout<<"RDNSS repository: active expiry, independent surviving record, zero lifetime withdrawal PASS\\n";
}
''')
    subprocess.run(['g++','-std=c++17','-pthread','-I'+str(out),str(out/'dns.cpp'),'-o',str(out/'dns.exe')],check=True)
    subprocess.run([str(out/'dns.exe')],check=True)
