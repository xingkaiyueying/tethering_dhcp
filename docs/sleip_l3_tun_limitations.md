# sleip0 L3 TUN DHCPv4 边界

- `L3_TUN` 使用 NearLink 六字节 Layer2 ID 作为 DHCP `chaddr` 和 Option 61 的稳定主体。
- `sleip0` 是无 Ethernet header、无 ARP 层的 L3 TUN，因此该模式在 DHCPACK 后跳过地址冲突 ARP 探测和 DHCPDECLINE。
- 接口索引、PF_PACKET/SOCK_DGRAM IPv4/UDP 收发、DORA、续租、server 租约和停止路径继续复用现有实现。
- 默认 `L2_PACKET=0`，仍通过 `SIOCGIFHWADDR` 获取硬件地址并保留原 ARP/DECLINE 行为。
- 这是星闪 IP 网络共享 Demo 的私有限制，不改变通用 RFC 2131 行为，也不是公共 API 或标准符合性声明。
