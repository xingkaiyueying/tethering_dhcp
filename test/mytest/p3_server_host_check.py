"""Execute production NearLink server registry and scoped binding functions.
The OS worker/socket and option allocator are explicit doubles; no product proof.
"""
from pathlib import Path
import subprocess
import tempfile

repo = Path(__file__).resolve().parents[2]
src = repo / 'services/dhcp_server'
main = (src / 'src/dhcp_dhcpd.cpp').read_text()
registry = main[main.index('static std::mutex g_nearlinkServersMutex;'):main.index('enum SignalEvent')]
pool = (src / 'src/dhcp_address_pool.cpp').read_text()
bindings = pool[pool.index('#define DHCP_POOL_INIT_SIZE'):pool.index('int CheckIpAvailability(')]
init = pool[pool.index('int InitAddressPool('):pool.index('int IsReserved(')]
release = pool[pool.index('int RemoveBinding('):pool.index('int AddLease(')]
with tempfile.TemporaryDirectory(prefix='p3-dhcp-server-') as directory:
    out = Path(directory)
    (out / 'netinet').mkdir()
    (out / 'netinet/ip.h').write_text('#pragma once\n#include <winsock2.h>\n#include <ws2tcpip.h>\n')
    code = r'''
#include <cassert>
#include <cstring>
#include <cstdio>
#include <map>
#include <vector>
#include <mutex>
#include <thread>
#include <chrono>
#include "dhcp_config.h"
#include "dhcp_nearlink_scope.h"
#define EOK 0
#define DHCP_LOGE(...) ((void)0)
#define DHCP_LOGD(...) ((void)0)
#define DHCP_LOGW(...) ((void)0)
int strcpy_s(char*d,size_t n,const char*s){if(strlen(s)>=n)return -1;strcpy(d,s);return 0;}
int memcpy_s(void*d,size_t n,const void*s,size_t k){if(k>n)return -1;memcpy(d,s,k);return 0;}
int memset_s(void*d,size_t n,int c,size_t k){if(k>n)return -1;memset(d,c,k);return 0;}
int strncpy_s(char*d,size_t n,const char*s,size_t k){if(k>=n)return -1;memcpy(d,s,k);d[k]=0;return 0;}
extern "C" {
int InitOptionList(PDhcpOptionList p){*p={};return 0;}
int AppendAddressOption(PDhcpOption p,uint32_t a){memcpy(p->data,&a,4);p->length=4;return 0;}
int PushBackOption(PDhcpOptionList p,PDhcpOption){++p->size;return 0;}
void FreeOptionList(PDhcpOptionList p){*p={};}
void ClearOptions(PDhcpOptionList p){*p={};}
int HasInitialized(PDhcpOptionList){return 1;}
}
uint64_t Tmspsec(){return 100;}
uint32_t ParseIpAddr(const char*s){unsigned a,b,c,d;char tail;if(sscanf(s,"%u.%u.%u.%u%c",&a,&b,&c,&d,&tail)!=4 || a>255||b>255||c>255||d>255)return 0;return (a<<24)|(b<<16)|(c<<8)|d;}
struct Context {std::string iface;int status=0;};
using PDhcpServerContext=Context*;
using DeviceConnectFun=void(*)(const char*);
DeviceConnectFun deviceConnectFun=nullptr;
std::map<std::string,int> freed;
int failFree=0, failStart=0, failStartCall=0;
PDhcpServerContext InitializeServer(DhcpConfig *c){return new Context{c->ifname,0};}
void RegisterDhcpCallback(Context*,int(*)(int,int,const char*)){}
void RegisterDeviceChangedCallback(Context*,DeviceConnectFun){}
int StartDhcpServer(Context*c){c->status=failStart?5:2;return failStartCall;}
int StopDhcpServer(Context*c){c->status=5;return 0;}
int GetServerStatus(Context*c){return c->status;}
int FreeServerContext(Context**c){if(failFree)return 1;++freed[(*c)->iface];delete *c;*c=nullptr;return 0;}
int ServerActionCallback(int,int,const char*){return 0;}
''' + bindings + r'''
uint32_t AddressDistribute(DhcpAddressPool*,uint8_t*){return 0;}
''' + init + release + registry + r'''
int main(){
    assert(IsNearlinkDhcpInterface("sleip12") && !IsNearlinkDhcpInterface("sleipx"));
    uint8_t key[16]={2,1,2,3,4,5}; DhcpAddressPool first{},second{};
    AddressBinding *a,*b;
    {DhcpNearlinkBindingScope scope("bt-pan"); a=AddNewBinding(key,nullptr);a->ipAddress=44;}
    assert(InitAddressPool(&first,"sleip0",nullptr)==0);
    {DhcpNearlinkBindingScope scope("sleip0");a=AddNewBinding(key,nullptr);a->ipAddress=77;}
    assert(InitAddressPool(&second,"sleip1",nullptr)==0);
    {DhcpNearlinkBindingScope scope("sleip1");b=AddNewBinding(key,nullptr);b->ipAddress=78;}
    assert(a!=b && a->ipAddress==77);
    {DhcpNearlinkBindingScope scope("bt-pan");assert(QueryBinding(key,nullptr)->ipAddress==44);}
    {DhcpNearlinkBindingScope scope("sleip1");assert(ReleaseBinding(key)==0);}
    {DhcpNearlinkBindingScope scope("sleip0");assert(QueryBinding(key,nullptr)->ipAddress==77);}
    FreeAddressPool(&second);
    {DhcpNearlinkBindingScope scope("sleip0");assert(QueryBinding(key,nullptr)->ipAddress==77);}
    InitAddressPool(&second,"sleip1",nullptr);
    {DhcpNearlinkBindingScope scope("sleip1");assert(!QueryBinding(key,nullptr));}
    std::thread t0([]{assert(StartNearlinkDhcpServerMain("sleip0","255.255.255.0","172.24.0.2,172.24.0.20","172.24.0.1")==0);});
    std::thread t1([]{assert(StartNearlinkDhcpServerMain("sleip1","255.255.255.0","172.24.1.2,172.24.1.20","172.24.1.1")==0);});
    t0.join();t1.join();assert(g_nearlinkServers.size()==2);
    auto survivor=g_nearlinkServers.at("sleip0");
    failFree=1;assert(StopNearlinkDhcpServerMain("sleip1")!=0 && g_nearlinkServers.size()==2);
    failFree=0;assert(StopNearlinkDhcpServerMain("sleip1")==0);
    assert(g_nearlinkServers.size()==1 && survivor->status==2 && freed["sleip0"]==0);
    assert(StopNearlinkDhcpServerMain("sleip1")==0); // idempotent
    assert(StopNearlinkDhcpServerMain("sleip0")==0 && g_nearlinkServers.empty());
    failStart=1;assert(StartNearlinkDhcpServerMain("sleip1","255.255.255.0","172.24.1.2,172.24.1.20","172.24.1.1")!=0);
    assert(g_nearlinkServers.empty());
    failStartCall=1;failFree=1;
    assert(StartNearlinkDhcpServerMain("sleip1","255.255.255.0","172.24.1.2,172.24.1.20","172.24.1.1")!=0);
    assert(g_nearlinkServers.size()==1);
    failFree=0;assert(StopNearlinkDhcpServerMain("sleip1")==0 && g_nearlinkServers.empty());
    puts("production registry/bindings: concurrent per-interface start, independent stop, retained failed cleanup, ephemeral reuse and legacy scope PASS");
}
'''
    cpp = out / 'test.cpp'
    cpp.write_text(code)
    common = repo / 'services/utils/include'
    includes = [out, src / 'include', common]
    # Locate dhcp_define.h without copying or changing its layout.
    includes += sorted({p.parent for p in repo.rglob('dhcp_define.h')})
    exe = out / 'test.exe'
    subprocess.run(['g++', '-std=c++17', '-pthread', *[f'-I{p}' for p in includes], str(cpp), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
    # Drive the real receive/destination functions with two overlapping OS recv doubles.
    server = (src / 'src/dhcp_s_server.cpp').read_text()
    receive = server[server.index('struct sockaddr_in *BroadcastAddrIn(void)\n{'):server.index('void InitReply(')]
    packet_code = r'''
#include <winsock2.h>
#include <ws2tcpip.h>
#include <vector>
#include <atomic>
#include <thread>
#include <cassert>
#include <cstring>
#include <cstdio>
#include "dhcp_message.h"
#include "dhcp_s_define.h"
#define EOK 0
#define RECV_BUFFER_SIZE 2048
#define DHCP_SERVER_SLEEP_TIMEOUTS 600000
#define DHCP_LOGI(...) ((void)0)
#define DHCP_LOGE(...) ((void)0)
#define DHCP_LOGW(...) ((void)0)
#define DHCP_LOGD(...) ((void)0)
using sockaddr=struct sockaddr;
int memcpy_s(void*d,size_t n,const void*s,size_t k){if(k>n)return -1;memcpy(d,s,k);return 0;}
int IsEmptyHWAddr(const uint8_t*){return 0;}
int IsReserved(uint8_t*){return 0;}
bool HasNearlinkBindingScope(){return true;}
std::atomic<int> arrived{0};
int host_select(int,fd_set*,void*,void*,timeval*){return 1;}
int host_recvfrom(int sock,uint8_t*buffer,int,int,sockaddr*source,socklen_t*){
    // Order the two writes to avoid test-side races; both receives finish after both writes.
    if(sock==2)while(arrived.load()!=1)std::this_thread::yield();
    DhcpMessage packet{};packet.op=BOOTREQUEST;packet.hlen=6;packet.xid=sock;packet.chaddr[0]=sock;
    memcpy(buffer,&packet,sizeof(packet));
    reinterpret_cast<sockaddr_in*>(source)->sin_addr.s_addr=sock;
    arrived.fetch_add(1);
    while(arrived.load()!=2)std::this_thread::yield();
    return sizeof(packet);
}
#define select host_select
#define recvfrom host_recvfrom
''' + receive + r'''
int main(){
    auto run=[](int id){DhcpMsgInfo message{};
        auto destination=DestinationAddr(id);
        assert(ReceiveDhcpMessage(id,&message)==0);
        assert(message.packet.xid==static_cast<uint32_t>(id) && message.packet.chaddr[0]==id);
        assert(SourceIpAddress()==static_cast<uint32_t>(id));
        assert(destination->sin_addr.s_addr==htonl(id));
    };
    std::thread first(run,1),second(run,2);first.join();second.join();
    puts("production concurrent receives: xid, source and unicast destination remain per worker PASS");
}
'''
    packet_cpp = out / 'packet.cpp'
    packet_cpp.write_text(packet_code)
    packet_exe = out / 'packet.exe'
    subprocess.run(['g++', '-std=c++17', '-pthread', *[f'-I{p}' for p in includes],
                    str(packet_cpp), '-o', str(packet_exe), '-lws2_32'], check=True)
    subprocess.run([str(packet_exe)], check=True)
    # Compile the complete main adapter with real DHCP declarations. Only platform utilities are stubbed.
    (out / 'dhcp_logger.h').write_text('''#pragma once
#define DEFINE_DHCPLOG_DHCP_LABEL(...)
#define DHCP_LOGE(...) ((void)0)
#define DHCP_LOGD(...) ((void)0)
#define DHCP_LOGI(...) ((void)0)
#define DHCP_LOGW(...) ((void)0)
''')
    (out / 'dhcp_common_utils.h').write_text('''#pragma once
#include <string>
namespace OHOS::DHCP { inline long long CheckDataLegal(const std::string&){return 1;} }
''')
    (out / 'securec.h').write_text('''#pragma once
#include <cstring>
#define EOK 0
#define strcpy_s host_strcpy_s
#define memcpy_s host_memcpy_s
inline int host_strcpy_s(char*d,size_t n,const char*s){if(strlen(s)>=n)return -1;strcpy(d,s);return 0;}
inline int host_memcpy_s(void*d,size_t n,const void*s,size_t k){if(k>n)return -1;memcpy(d,s,k);return 0;}
inline char *strtok_r(char*s,const char*d,char**){return strtok(s,d);}
''')
    subprocess.run(['g++', '-std=c++17', '-fsyntax-only', *[f'-I{p}' for p in includes],
                    str(src / 'src/dhcp_dhcpd.cpp')], check=True)
    print('full DHCP main adapter syntax: real headers / platform utility doubles PASS')
    # Execute real stop/free methods, including a worker finishing after a first
    # free timeout. Socket/worker completion and the wait clock are explicit doubles.
    stop = server[server.index('int StopDhcpServer(PDhcpServerContext ctx)'):server.index('int GetServerStatus(')]
    free_context = server[server.index('int FreeServerContext(PDhcpServerContext *ctx)'):]
    stop_code = r'''
#include <atomic>
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include "dhcp_nearlink_scope.h"
#define DHCP_LOGI(...) ((void)0)
#define DHCP_LOGE(...) ((void)0)
constexpr int RET_SUCCESS=0,RET_FAILED=-1;
enum {LS_IDLE,LS_STARING,LS_RUNNING,LS_RELOADNG,LS_STOPING,LS_STOPED};
struct ServerContext {std::atomic<int> looperState{LS_IDLE};int addressPool=0;};
struct DhcpServerContext {char ifname[32];ServerContext *instance;};
using PDhcpServerContext=DhcpServerContext*;
ServerContext *GetServerInstance(PDhcpServerContext c){return c?c->instance:nullptr;}
int freedPools=0,waits=0;
void FreeAddressPool(int*){++freedPools;}
void usleep(unsigned){++waits;}
''' + stop + free_context + r'''
PDhcpServerContext context(int state,const char *name="sleip0") {
    auto c=static_cast<PDhcpServerContext>(malloc(sizeof(DhcpServerContext)));
    strcpy(c->ifname,name);c->instance=new ServerContext;c->instance->looperState=state;return c;
}
int main() {
    for(int state:{LS_IDLE,LS_STOPED}) {
        auto c=context(state);waits=0;
        assert(StopDhcpServer(c)==0 && c->instance->looperState==state);
        assert(FreeServerContext(&c)==0 && !c && waits==0);
    }
    for(int state:{LS_STARING,LS_RUNNING,LS_RELOADNG,LS_STOPING}) {
        auto c=context(state);assert(StopDhcpServer(c)==0 && c->instance->looperState==LS_STOPING);
        assert(StopDhcpServer(c)==0 && c->instance->looperState==LS_STOPING);
        waits=0;int prior=freedPools;
        assert(FreeServerContext(&c)!=0 && c && waits==5 && freedPools==prior);
        c->instance->looperState=LS_STOPED; // worker drains after the timed-out free
        assert(StopDhcpServer(c)==0 && c->instance->looperState==LS_STOPED);
        assert(FreeServerContext(&c)==0 && !c);
    }
    auto c=context(LS_STOPED,"wlan0");assert(StopDhcpServer(c)==0);
    assert(c->instance->looperState==LS_STOPING); // legacy stop behavior remains
    delete c->instance;c->instance=nullptr;free(c);
    puts("production stop/free: stopped/idle idempotence, late drain retry and timeout ownership PASS");
}
'''
    stop_cpp = out / 'stop.cpp'
    stop_cpp.write_text(stop_code)
    stop_exe = out / 'stop.exe'
    subprocess.run(['g++', '-std=c++17', *[f'-I{p}' for p in includes],
                    str(stop_cpp), '-o', str(stop_exe)], check=True)
    subprocess.run([str(stop_exe)], check=True)
