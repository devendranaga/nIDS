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
| 8 | MACsec | Both SC and SCB are set |
| 9 | MACsec | Both ES and SC are set |
| 10 | IPv4 | Header length too small / big / invalid |
| 11 | IPv4 | Invalid Version |
| 12 | IPv4 | Invalid Flags |
| 13 | IPv4 | Invalid options |
| 14 | IPv4 | Header checksum invalid |
| 15 | IPv4 | Protocol unsupported |
| 16 | IPV6 | Too short header length |
| 17 | IPV6 | Invalid Version |
| 18 | TCP | short header length |
| 19 | TCP | All flags set |
| 20 | TCP | Invalid src port |
| 21 | TCP | Invalid dst port |
| 22 | TCP | Both SYN and FIN are set |
| 23 | TCP | Invalid TCP options |
| 24 | TCP | No flags set |
| 25 | UDP | Invalid src port |
| 26 | UDP | Invalid dst port |
| 27 | UDP | Too small udp header length |
| 28 | ICMP | ICMP Invalid type |
| 29 | ICMP | ICMP invalid destination unreachable code |
| 30 | ICMP | ICMP invalid time exceeded code |
| 31 | ICMP | ICMP Timestamp req / response headers are too small |
| 32 | ICMP | ICMP Info message header is too small |
| 33 | ICMP | ICMP covert channel is active |
| 34 | ICMP6 | ICMP6 Unsupported type |
| 35 | DHCP | Invalid DHCP magic |
| 36 | Exploit Filter | Win32.Blaster worm dest port 4444 is matched |



