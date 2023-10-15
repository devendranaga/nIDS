/**
 * @brief - implements parser
 * 
 * @copyright - 2023-present All rights reserved. Devendra Naga.
*/
#ifndef __FW_PARSER_H__
#define __FW_PARSER_H__

#include <logger.h>
// ethernet header
#include <eth.h>
// VLAN header
#include <vlan.h>
// ARP header
#include <arp.h>
// IPV4 header
#include <ipv4.h>
// IPV6 header
#include <ipv6.h>
// UDP header
#include <udp.h>
// ICMP6 header
#include <icmp6.h>
// DHCP header
#include <dhcp.h>

#include <packet.h>
#include <port_numbers.h>
#include <rule_parser.h>
#include <os_signatures.h>

namespace firewall {

/**
 * @brief - defines which protocols are available.
*/
struct protocol_bits {
    public:
        explicit protocol_bits() :
                            eth(0),
                            ipv4(0),
                            arp(0),
                            vlan(0),
                            udp(0),
                            ipv6(0),
                            icmp6(0),
                            dhcp(0)
        { }
        ~protocol_bits() { }

        void set_eth() { eth = 1; }
        void set_ipv4() { ipv4 = 1; }
        void set_arp() { arp = 1; }
        void set_vlan() { vlan = 1; }
        void set_udp() { udp = 1; }
        void set_ipv6() { ipv6 = 1; }
        void set_icmp6() { icmp6 = 1; }
        void set_dhcp() { dhcp = 1; }
        bool has_eth() const { return eth == 1; }
        bool has_ipv4() const { return ipv4 == 1; }
        bool has_arp() const { return arp == 1; }
        bool has_vlan() const { return vlan == 1; }
        bool has_udp() const { return udp == 1; }
        bool has_ipv6() const { return ipv6 == 1; }
        bool has_icmp6() const { return icmp6 == 1; }
        bool has_dhcp() const { return dhcp == 1; }

    private:
        uint32_t eth:1;
        uint32_t ipv4:1;
        uint32_t arp:1;
        uint32_t vlan:1;
        uint32_t udp:1;
        uint32_t ipv6:1;
        uint32_t icmp6:1;
        uint32_t dhcp:1;
};

/**
 * @brief - Implements packet parser.
*/
struct parser {
    public:
        explicit parser(logger *log);
        ~parser();

        // ethernet header
        eth_hdr eh;

        // VLAN header
        vlan_hdr vh;

        // ARP header
        arp_hdr arp_h;

        // IPV4 header
        ipv4_hdr ipv4_h;

        // IPV6 header
        ipv6_hdr ipv6_h;

        // UDP header
        udp_hdr udp_h;

        // ICMP6 header
        icmp6_hdr icmp6_h;

        // DHCP header
        dhcp_hdr dhcp_h;

        // parsed protocols so far
        protocol_bits protocols_avail;

        // OS type
        os_type os_type_t;

        uint32_t pkt_len;

        int run(packet &pkt);

        protocols_types get_protocol_type()
        {
            if (protocols_avail.has_ipv4()) {
                return static_cast<protocols_types>(ipv4_h.protocol);
            } else if (protocols_avail.has_ipv6()) {
                return static_cast<protocols_types>(ipv6_h.nh);
            }

            return static_cast<protocols_types>(protocols_types::Protocol_Max);
        }

        bool has_port()
        {
            if (protocols_avail.has_udp()) {
                return true;
            }

            return false;
        }

        Port_Numbers get_dst_port()
        {
            if (protocols_avail.has_udp()) {
                return static_cast<Port_Numbers>(udp_h.dst_port);
            }

            return Port_Numbers::Port_Number_Max;
        }

    private:
        void detect_os_signature();
        event_description parse_l4(packet &pkt);
        event_description parse_app(packet &pkt);

        logger *log_;
        bool pkt_dump_;
};

}

#endif
