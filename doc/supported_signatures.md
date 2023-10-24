# Supported Signatures

| S.No | Protocol | Signature |
|------|----------|-----------|
| 1 | Eth | Ethertype unknown |
| 2 | Eth | Ethernet header length is too short |
| 3 | ARP | Header length not 28 |
| 4 | ARP | Hw length invalid |
| 5 | ARP | Protocol address length invalid |
| 6 | ARP | Invalid ARP::OP |
| 7 | VLAN | Invalid VLAN ID |
| 8 | IPV4 | Header length too small / big / invalid |
| 9 | IPV4 | Invalid Version |
| 10 | IPV4 | Invalid Flags |
| 11 | IPV6 | Too short header length |
| 12 | IPV6 | Invalid Version |
| 13 | TCP | short header length |
| 14 | TCP | All flags set |
| 15 | TCP | No flags set |
| 16 | UDP | Invalid src port |
| 17 | UDP | Invalid dst port |
| 18 | UDP | Too small udp header length |
| 19 | ICMP | ICMP Invalid type |
| 20 | ICMP | ICMP invalid destination unreachable code |
| 21 | ICMP | ICMP invalid time exceeded code |
| 22 | ICMP6 | ICMP6 Unsupported type |
| 23 | DHCP | Invalid DHCP magic |


