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
| 15 | TCP | Invalid src port |
| 16 | TCP | Invalid dst port |
| 17 | TCP | Both SYN and FIN are set |
| 18 | TCP | Invalid TCP options |
| 19 | TCP | No flags set |
| 20 | UDP | Invalid src port |
| 21 | UDP | Invalid dst port |
| 22 | UDP | Too small udp header length |
| 23 | ICMP | ICMP Invalid type |
| 24 | ICMP | ICMP invalid destination unreachable code |
| 25 | ICMP | ICMP invalid time exceeded code |
| 26 | ICMP | ICMP Timestamp req / response headers are too small |
| 27 | ICMP | ICMP Info message header is too small |
| 28 | ICMP | ICMP covert channel is active |
| 29 | ICMP6 | ICMP6 Unsupported type |
| 30 | DHCP | Invalid DHCP magic |
| 31 | Exploit Filter | Win32.Blaster worm dest port 4444 is matched |



