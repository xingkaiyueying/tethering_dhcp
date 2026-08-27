# Stage 0 DHCP inventory and L3 interface draft

Baseline (this branch): created from `origin/dev` at `96e26d3aef6dcc17dc0007908a25289b2f8f096e`.
Working tree was clean at branch creation.

## Client state machine (reusable)

`services/dhcp_client/include/dhcp_client_def.h` already has:

- `DHCP_STATE_INIT`
- `DHCP_STATE_SELECTING`
- `DHCP_STATE_REQUESTING`
- `DHCP_STATE_BOUND`
- `DHCP_STATE_RENEWING`
- `DHCP_STATE_REBINDING`
- `DHCP_STATE_INITREBOOT`
- `DHCP_STATE_RELEASED`
- `DHCP_STATE_DECLINE`

Do not copy this state machine into NearLink. Stage 2 injects `IDhcpPacketTransport` / `IDhcpConflictDetector`.

## Client sockets and ARP (must not be used on TUN)

| Path | Behavior | L3_TUN action |
|---|---|---|
| `dhcp_socket.cpp` `CreateRawSocket()` | `PF_PACKET` | forbidden |
| `dhcp_socket.cpp` `CreateKernelSocket()` | `PF_INET/SOCK_DGRAM` UDP | reuse as L3 backend |
| `dhcp_function.cpp` `GetLocalInterface()` | reads iface MAC | forbidden; use `clientKey` |
| `dhcp_client_state_machine.cpp` `IpConflictDetect()` | ARP | L3 detector only checks local interface addresses |
| `dhcp_client_state_machine.cpp` initial DORA | `SendToDhcpPacket()` raw | go through transport |

## Server ARP unicast (must be gated)

`services/dhcp_server/src/dhcp_s_server.cpp` `TransmitOfferOrAckPacket()` calls `AddArpEntry()` on the non-broadcast path (`dhcp_common_utils.cpp`, `SIOCSARP`). L3_TUN must skip that branch and emit OFFER/first ACK/NAK as TUN broadcasts.

`DhcpRange::leaseHours` is integer hours. `UpdateLeasesTime()` writes the global config file. V2 uses `DhcpServerConfigV2::leaseSeconds` per instance; see `dhcp_l3_lease_timing.h`.

## Draft interfaces in this branch

- `interfaces/inner_api/include/dhcp_l3_lease_timing.h`
- `interfaces/inner_api/include/dhcp_l3_config_v2.h`

Not implemented yet (stage 2): `StartDhcpClientV2` / `StartDhcpServerV2` IPC, L3 socket backend, lease event callbacks, `InvalidateDhcpLeaseV2`.
