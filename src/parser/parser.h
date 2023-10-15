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
// UDP header
#include <udp.h>
#include <packet.h>
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
                            udp(0)
        { }
        ~protocol_bits() { }

        void set_eth() { eth = 1; }
        void set_ipv4() { ipv4 = 1; }
        void set_arp() { arp = 1; }
        void set_vlan() { vlan = 1; }
        void set_udp() { udp = 1; }
        bool has_eth() { return eth == 1; }
        bool has_ipv4() { return ipv4 == 1; }
        bool has_arp() { return arp == 1; }
        bool has_vlan() { return vlan == 1; }
        bool has_udp() { return udp == 1; }

    private:
        uint32_t eth:1;
        uint32_t ipv4:1;
        uint32_t arp:1;
        uint32_t vlan:1;
        uint32_t udp:1;
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

        // ipv4 header
        ipv4_hdr ipv4_h;

        udp_hdr udp_h;

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
            }

            return static_cast<protocols_types>(protocols_types::Protocol_Max);
        }

    private:
        void detect_os_signature();

        logger *log_;
};

}

#endif
