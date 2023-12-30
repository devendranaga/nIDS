# Supported Protocols

The following protocols are supported.

| S.No | Protocol Name | Layer |
|------|---------------|-------|
| 1 | Ethernet | L2 |
| 2 | IEEE 802.1AE | L2 |
| 3 | ARP | L2 |
| 4 | VLAN | L2 |
| 5 | Double VLAN Tag | L2 |
| 6 | IEEE 802.1AD (Q in Q) | L2 |
| 7 | PPPOE | L2 |
| 8 | IPv4 | L3 |
| 9 | IPv6 | L3 |
| 10 | TCP | L4 |
| 11 | IPIP (Tunnel) | L4 |
| 12 | UDP | L4 |
| 13 | ICMP | L4 |
| 14 | ICMP6 | L4 |
| 15 | DHCP | APP |
| 16 | NTP | APP |
| 17 | TLS | APP (only version matching!) |
| 18 | MQTT | APP |
| 19 | IPv6-ESP | L3 / L4 |
| 20 | IPv6-AH | L3 / L4 |
| 21 | IPv6-in-IPv6 | L3 / L4 |
| 22 | IGMP v3 | L4 |
| 23 | VRRP (Control plane) | L4 |
| 24 | GRE (Control plane) | L4 |
| 25 | 6in4 (Tunnel) | L4 |

Below are some of the supported Automotive protocols.

| S.No | Protocol Name | Layer |
|------|---------------|-------|
| 1 | DoIP | APP |
| 2 | UDS | APP |
| 3 | SOME/IP | APP |

DoIP tunnels in the UDS frames during diagnostics requests.



