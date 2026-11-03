"""Execute production shared-server allocation/reply functions with socket and clock doubles."""
from pathlib import Path
import subprocess
import tempfile

repo=Path(__file__).resolve().parents[2]
server=(repo/'services/dhcp_server/src/dhcp_s_server.cpp').read_text(encoding='utf-8')
pool=(repo/'services/dhcp_server/src/dhcp_address_pool.cpp').read_text(encoding='utf-8')
def function(source,signature):
    start=source.index(signature+'\n{')
    end=source.index('{',start)+1
    depth=1
    while depth:
        depth+=(source[end]=='{')-(source[end]=='}')
        end+=1
    return source[start:end]+'\n'
with tempfile.TemporaryDirectory(prefix='shared-dhcp-') as directory:
    out=Path(directory)
    code=r'''
#include <winsock2.h>
#include <ws2tcpip.h>
#include <map>
#include <mutex>
#include <set>
#include <cstring>
#include <cstdint>
#include <cassert>
#include <iostream>
#include "dhcp_nearlink_scope.h"
#define DHCP_LOGI(...) ((void)0)
#define DHCP_LOGD(...) ((void)0)
#define DHCP_LOGW(...) ((void)0)
#define DHCP_LOGE(...) ((void)0)
constexpr int DHCP_HWADDR_LENGTH=16,MAC_ADDR_LENGTH=6,EOK=0,DHCP_LEASE_TIME=3600;
constexpr int BIND_MODE_DYNAMIC=0,BIND_PENDING=0,BIND_RELEASED=1,BIND_MODE_STATIC=2,BIND_MODE_RESERVED=3;
constexpr int DHCP_RELEASE_REMOVE_MODE=0,DHCP_TRUE=1,DHCP_FALSE=0,RET_ERROR=-1,RET_FAILED=-1,RET_SUCCESS=0;
struct AddressBinding {int bindingMode=0,bindingStatus=0;uint8_t chaddr[16]{};uint32_t bindingTime=0,pendingTime=0,expireIn=0,leaseTime=0,ipAddress=0;};
struct Options{};using PDhcpOptionList=Options*;
struct DhcpAddressPool {
 char ifname[16]{};uint32_t serverId=0,gateway=0,netmask=0,leaseTime=3600,distribution=0;
 struct {uint32_t beginAddress=0,endAddress=0;} addressRange;
 std::map<uint32_t,AddressBinding> leaseTable;
 AddressBinding *(*binding)(uint8_t*,Options*)=nullptr,*(*newBinding)(uint8_t*,Options*)=nullptr;
 uint32_t (*distribue)(DhcpAddressPool*,uint8_t*)=nullptr;
};
int memcpy_s(void*d,size_t n,const void*s,size_t m){assert(m<=n);memcpy(d,s,m);return 0;}
uint32_t Tmspsec(){return 100;}uint32_t Tmspusec(){return 100;}
uint32_t HostTotal(uint32_t){return 254;}
uint32_t NextIpAddress(uint32_t ip,uint32_t,unsigned){return (ip&255)==254?(ip&0xffffff00)+1:ip+1;}
int IsEmptyHWAddr(const uint8_t*a){for(int i=0;i<16;++i)if(a[i])return false;return true;}
int IsExpire(AddressBinding *b){return b->expireIn&&b->expireIn<100;}
int AddrEquels(const uint8_t*a,const uint8_t*b,int n){return memcmp(a,b,n)==0;}
int IpInRange(uint32_t ip,uint32_t first,uint32_t last,uint32_t mask){return (ip&mask)==(first&mask)&&ip>=first&&ip<=last;}
AddressBinding *GetLease(DhcpAddressPool*,uint32_t);
int AddLease(DhcpAddressPool*,AddressBinding*),RemoveBinding(uint8_t*),IsReserved(uint8_t*),IsReservedIp(DhcpAddressPool*,uint32_t);
'''
    code+=pool[pool.index('static int g_releaseRemoveMode'):pool.index('int CheckIpAvailability(')]
    signatures=[
      'AddressBinding *GetLease(DhcpAddressPool *pool, uint32_t ipAddress)',
      'int AddLease(DhcpAddressPool *pool, AddressBinding *lease)',
      'int RemoveBinding(uint8_t macAddr[DHCP_HWADDR_LENGTH])',
      'int ReleaseBinding(uint8_t macAddr[DHCP_HWADDR_LENGTH])',
      'int IsReserved(uint8_t macAddr[DHCP_HWADDR_LENGTH])',
      'int IsReservedIp(DhcpAddressPool *pool, uint32_t ipAddress)',
      'int CheckIpAvailability(DhcpAddressPool *pool, uint8_t macAddr[DHCP_HWADDR_LENGTH], uint32_t distIp)',
      'int CheckRangeAvailability(\n    DhcpAddressPool *pool, uint8_t macAddr[DHCP_HWADDR_LENGTH], uint32_t distIp, int *outOfRange)',
      'uint32_t NextIpOffset(uint32_t netmask)',
      'uint32_t AddressDistribute(DhcpAddressPool *pool, uint8_t macAddr[DHCP_HWADDR_LENGTH])']
    for signature in signatures:code+=function(pool,signature)
    code+=r'''
struct Packet {uint32_t xid=42,yiaddr=0;uint8_t chaddr[16]{};};
struct DhcpMsgInfo {Packet packet;Options options;int length=300;};using PDhcpMsgInfo=DhcpMsgInfo*;
struct ServerContext {DhcpAddressPool addressPool;int broadCastFlagEnable=1,serverFd=10;};
struct DhcpServerContext {char ifname[16]{};ServerContext *instance=nullptr;};using PDhcpServerContext=DhcpServerContext*;
ServerContext *GetServerInstance(PDhcpServerContext ctx){return ctx?ctx->instance:nullptr;}
sockaddr_in broadcast{},destination{};
sockaddr_in *BroadcastAddrIn(){return &broadcast;}sockaddr_in *DestinationAddrIn(){return &destination;}
bool GetBroadCastFlag(PDhcpMsgInfo){return false;}
std::string Ip4IntConvertToStr(uint32_t,bool){return "192.168.77.2";}
const char *ParseStrMac(const uint8_t*,size_t){return "02:11:22:33:44:55";}
int arps=0,sends=0,sendResult=300;
int AddArpEntry(const char*,const std::string&,const std::string&){++arps;return 0;}
int Send(int,const void*,int,int,const sockaddr*,int){++sends;return sendResult;}
constexpr int REPLY_PACKET_MAX_LEN=1500;
#define sendto Send
'''
    code+=function(server,'AddressBinding *GetBinding(DhcpAddressPool *pool, PDhcpMsgInfo received)')
    code+=function(server,'static int32_t TransmitOfferOrAckPacket(PDhcpServerContext ctx, PDhcpMsgInfo reply)')
    code+=r'''
int main(){
 DhcpAddressPool pool;strcpy(pool.ifname,"sleip0");pool.netmask=0xffffff00;pool.addressRange={0xac180002,0xac1800fe};
 pool.serverId=pool.gateway=0xac180001;pool.binding=QueryBinding;pool.newBinding=AddNewBinding;pool.distribue=AddressDistribute;
 std::set<uint32_t> unique;
 for(uint8_t id=1;id<=32;++id){DhcpMsgInfo message;message.packet.chaddr[0]=2;message.packet.chaddr[5]=id;
  auto binding=GetBinding(&pool,&message);assert(binding&&unique.insert(binding->ipAddress).second);
  assert(GetBinding(&pool,&message)==binding);assert(binding->ipAddress>=0xac180002&&binding->ipAddress<=0xac1800fe);
 }
 assert(unique.size()==32);
 DhcpMsgInfo message;message.packet.chaddr[0]=2;message.packet.chaddr[5]=1;
 auto original=GetBinding(&pool,&message)->ipAddress;
 {NearlinkDhcpBindingScope legacy("wlan0");auto binding=AddNewBinding(message.packet.chaddr,&message.options);binding->ipAddress=0xc0a80102;
  {NearlinkDhcpBindingScope scope("sleip0");assert(QueryBinding(message.packet.chaddr,nullptr)->ipAddress==original);}
  assert(QueryBinding(message.packet.chaddr,nullptr)->ipAddress==0xc0a80102);
 }
 pool.addressRange={0xac180102,0xac1801fe};pool.gateway=pool.serverId=0xac180101;
 auto changed=GetBinding(&pool,&message);assert(changed&&changed->ipAddress>=0xac180102&&changed->ipAddress<=0xac1801fe);
 ServerContext instance;DhcpServerContext ctx;strcpy(ctx.ifname,"sleip0");ctx.instance=&instance;
 assert(TransmitOfferOrAckPacket(&ctx,&message)==0&&arps==0&&sends==1);
 sendResult=-1;assert(TransmitOfferOrAckPacket(&ctx,&message)!=0);
 message.length=0;assert(TransmitOfferOrAckPacket(&ctx,&message)!=0);
 message.length=300;sendResult=300;strcpy(ctx.ifname,"wlan0");assert(TransmitOfferOrAckPacket(&ctx,&message)==0&&arps==1);
 std::cout<<"shared_dhcp=PASS (32 unique leases, renewal reuse, private binding scope, subnet reallocation, directed broadcast dispatch, send failure, legacy ARP)\n";
}
'''
    (out/'test.cpp').write_text(code,encoding='utf-8')
    exe=out/'check.exe'
    subprocess.run(['g++','-std=c++17','-I'+str(repo/'services/dhcp_server/include'),str(out/'test.cpp'),'-o',str(exe),'-lws2_32'],check=True)
    subprocess.run([str(exe)],check=True)
