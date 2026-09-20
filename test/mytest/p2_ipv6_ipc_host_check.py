"""Production DHCP result serializer/parser with an explicit byte-Parcel mock, not real IPC."""
from pathlib import Path
import subprocess
import tempfile

repo = Path(__file__).resolve().parents[2]

def block(path, signature):
    text = (repo / path).read_text(encoding='utf-8')
    start = text.index(signature)
    left = text.index('{', start)
    depth = 1
    right = left + 1
    while depth:
        depth += (text[right] == '{') - (text[right] == '}')
        right += 1
    return text[start:right]

probe = (repo / 'test/mytest/sleip_dhcp_stage2.c').read_text(encoding='utf-8')
callback = block('test/mytest/sleip_dhcp_stage2.c', 'static void OnL3Ipv6')
drain = block('test/mytest/sleip_dhcp_stage2.c', 'static void DrainL3Ipv6Snapshots')
assert 'NlIpShareUpdateValidatedAddress' not in callback
assert 'g_ipv6Pending.push_back' in callback
assert 'ProcessL3Ipv6Snapshot' in drain
assert 'DrainL3Ipv6Snapshots();' in probe
print('DHCP probe IPC identity: callback queues snapshots and caller thread drains evidence PASS')

types = 'interfaces/inner_api/include/dhcp_define.h'
code = r'''
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include <cassert>
#include <iostream>
constexpr uint32_t LIFETIME_INFINITY = UINT32_MAX;
constexpr int DHCP_MAX_DNS_SIZE=16, DHCP_MAX_ADDR_SIZE=16;
class MessageParcel {
public:
 std::vector<uint8_t> bytes; size_t cursor=0; int calls=0, failAt=-1;
 size_t GetReadableBytes() const {return bytes.size()-cursor;}
 template<class T> bool Write(T v) {if(calls++==failAt)return false;auto p=(uint8_t*)&v;bytes.insert(bytes.end(),p,p+sizeof(v));return true;}
 template<class T> bool Read(T& v) {if(GetReadableBytes()<sizeof(v))return false;memcpy(&v,bytes.data()+cursor,sizeof(v));cursor+=sizeof(v);return true;}
 bool WriteInt32(int32_t v){return Write(v);} bool ReadInt32(int32_t& v){return Read(v);}
 bool WriteUint32(uint32_t v){return Write(v);} bool ReadUint32(uint32_t& v){return Read(v);}
 bool WriteUint8(uint8_t v){return Write(v);} bool ReadUint8(uint8_t& v){return Read(v);}
 bool WriteBool(bool v){return Write(v);} bool ReadBool(bool& v){return Read(v);}
 bool WriteString(const std::string& s){if(!WriteInt32(s.size()))return false;bytes.insert(bytes.end(),s.begin(),s.end());return true;}
 bool ReadString(std::string& s){int32_t n=0;if(!ReadInt32(n)||n<0||(size_t)n>GetReadableBytes())return false;s.assign((char*)bytes.data()+cursor,n);cursor+=n;return true;}
};
'''
code += block(types, 'struct L3Ipv6Address {') + ';\n'
code += block(types, 'struct DhcpResult {') + ';\n'
code += 'struct DhcpClientCallbackProxy { static bool WriteDhcpResult(const DhcpResult&, MessageParcel&); };\n'
code += 'struct DhcpClientCallBackStub { static DhcpResult DeserializeDhcpResult(MessageParcel&); };\n'
code += block('services/dhcp_client/src/dhcp_client_callback_proxy.cpp', 'bool DhcpClientCallbackProxy::WriteDhcpResult')
code += block('frameworks/native/src/dhcp_client_callback_stub.cpp', 'DhcpResult DhcpClientCallBackStub::DeserializeDhcpResult')
code += r'''
int main(){
 DhcpResult value; value.iptype=1;value.isOptSuc=true;value.vectorDnsAddr={"fd77::53"};
 MessageParcel legacy; assert(DhcpClientCallbackProxy::WriteDhcpResult(value,legacy));
 auto old=DhcpClientCallBackStub::DeserializeDhcpResult(legacy);assert(old.iptype==1&&!old.l3Ipv6);
 value.l3Ipv6=true;L3Ipv6Address address;address.address="fd77::2";address.ifindex=7;
 address.prefixLength=64;address.flags=0x40;address.preferredLifetime=20;address.validLifetime=40;
 value.l3Addresses.push_back(address);
 MessageParcel full;assert(DhcpClientCallbackProxy::WriteDhcpResult(value,full));
 auto decoded=DhcpClientCallBackStub::DeserializeDhcpResult(full);
 assert(decoded.iptype==1&&decoded.l3Ipv6&&decoded.l3Addresses.size()==1);
 assert(decoded.l3Addresses[0].flags==0x40&&decoded.l3Addresses[0].validLifetime==40);
 for(size_t i=0;i<full.bytes.size();++i){
  if(i==legacy.bytes.size())continue; // exact old layout remains compatible
  MessageParcel truncated;truncated.bytes.assign(full.bytes.begin(),full.bytes.begin()+i);
  assert(DhcpClientCallBackStub::DeserializeDhcpResult(truncated).iptype==-1);
 }
 for(int i=0;i<full.calls;++i){MessageParcel failed;failed.failAt=i;assert(!DhcpClientCallbackProxy::WriteDhcpResult(value,failed));}
 MessageParcel tail;tail.bytes=full.bytes;tail.bytes.push_back(0);assert(DhcpClientCallBackStub::DeserializeDhcpResult(tail).iptype==-1);
 value.l3Addresses[0].preferredLifetime=41;MessageParcel bad;assert(DhcpClientCallbackProxy::WriteDhcpResult(value,bad));
 assert(DhcpClientCallBackStub::DeserializeDhcpResult(bad).iptype==-1);
 value.l3Addresses.resize(9);MessageParcel oversized;assert(!DhcpClientCallbackProxy::WriteDhcpResult(value,oversized));
 std::cout<<"DHCP result codec: legacy/sidecar roundtrip, all byte truncations, write failures, invalid lifetime/count/trailing data PASS\n";
}
'''
with tempfile.TemporaryDirectory(prefix='p2-dhcp-ipc-') as tmp:
    out = Path(tmp)
    (out / 'test.cpp').write_text(code, encoding='utf-8')
    subprocess.run(['g++', '-std=c++17', '-Wall', '-Wextra', '-Werror', str(out/'test.cpp'), '-o', str(out/'test.exe')], check=True)
    subprocess.run([str(out/'test.exe')], check=True)
