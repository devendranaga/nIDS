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
// MACsec header
#include <macsec.h>
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
// TCP header
#include <tcp.h>
// ICMP header
#include <icmp.h>
// ICMP6 header
#include <icmp6.h>
// DHCP header
#include <dhcp.h>
// NTP header
#include <ntp.h>
// TLS header
#include <tls.h>
#if defined(FW_ENABLE_AUTOMOTIVE)
// DoIP header
#include <doip.h>
#endif
// MQTT header
#include <mqtt.h>
// Known exploits
#include <known_exploits.h>

#include <packet.h>
#include <port_numbers.h>
#include <rule_parser.h>
#include <os_signatures.h>
#include <packet_stats.h>
#include <arp_filter.h>
#include <icmp_filter.h>

namespace firewall {

/**
 * @brief - defines which protocols are available.
*/
struct protocol_bits {
    public:
        explicit protocol_bits() :
                            eth(0),
                            macsec(0),
                            ipv4(0),
                            arp(0),
                            vlan(0),
                            icmp(0),
                            tcp(0),
                            udp(0),
                            ipv6(0),
                            icmp6(0),
                            dhcp(0),
                            ntp(0),
                            doip(0),
                            tls(0),
                            mqtt(0)
        { }
        ~protocol_bits() { }

        void set_eth() { eth = 1; }
        void set_macsec() { macsec = 1; }
        void set_ipv4() { ipv4 = 1; }
        void set_arp() { arp = 1; }
        void set_vlan() { vlan = 1; }
        void set_icmp() { icmp = 1; }
        void set_tcp() { tcp = 1; }
        void set_udp() { udp = 1; }
        void set_ipv6() { ipv6 = 1; }
        void set_icmp6() { icmp6 = 1; }
        void set_dhcp() { dhcp = 1; }
        void set_ntp() { ntp = 1; }
        void set_doip() { doip = 1; }
        void set_tls() { tls = 1; }
        void set_mqtt() { mqtt = 1; }
        bool has_eth() const { return eth == 1; }
        bool has_macsec() const { return macsec == 1; }
        bool has_ipv4() const { return ipv4 == 1; }
        bool has_arp() const { return arp == 1; }
        bool has_vlan() const { return vlan == 1; }
        bool has_icmp() const { return icmp == 1; }
        bool has_tcp() const { return tcp == 1; }
        bool has_udp() const { return udp == 1; }
        bool has_ipv6() const { return ipv6 == 1; }
        bool has_icmp6() const { return icmp6 == 1; }
        bool has_dhcp() const { return dhcp == 1; }
        bool has_ntp() const { return ntp == 1; }
        bool has_doip() const { return doip == 1; }
        bool has_tls() const { return tls == 1; }
        bool has_mqtt() const { return mqtt == 1; }

    private:
        uint32_t eth:1;
        uint32_t macsec:1;
        uint32_t ipv4:1;
        uint32_t arp:1;
        uint32_t vlan:1;
        uint32_t icmp:1;
        uint32_t tcp:1;
        uint32_t udp:1;
        uint32_t ipv6:1;
        uint32_t icmp6:1;
        uint32_t dhcp:1;
        uint32_t ntp:1;
        uint32_t doip:1;
        uint32_t tls:1;
        uint32_t mqtt:1;
};

/**
 * @brief - Implements packet parser.
*/
struct parser {
    public:
        explicit parser(const std::string ifname, logger *log);
        ~parser();

        // ethernet header
        std::shared_ptr<eth_hdr> eh;

        // MACsec header
        std::shared_ptr<ieee8021ae_hdr> macsec_h;

        // VLAN header
        std::shared_ptr<vlan_hdr> vh;

        // ARP header
        std::shared_ptr<arp_hdr> arp_h;

        // IPV4 header
        std::shared_ptr<ipv4_hdr> ipv4_h;

        // IPV6 header
        std::shared_ptr<ipv6_hdr> ipv6_h;

        // IPv6 Encapsulation header
        std::shared_ptr<ipv6_hdr> ipv6_encap_h;

        // IPV6 Authentication header
        std::shared_ptr<ipv6_ah_hdr> ipv6_ah_h;

        // TCP header
        std::shared_ptr<tcp_hdr> tcp_h;

        // UDP header
        std::shared_ptr<udp_hdr> udp_h;

        // ICMP header
        std::shared_ptr<icmp_hdr> icmp_h;

        // ICMP6 header
        std::shared_ptr<icmp6_hdr> icmp6_h;

        // DHCP header
        std::shared_ptr<dhcp_hdr> dhcp_h;

        // NTP header
        std::shared_ptr<ntp_hdr> ntp_h;

#if defined(FW_ENABLE_AUTOMOTIVE)
        // DoIP header
        std::shared_ptr<doip_hdr> doip_h;
#endif

        // TLS header
        std::shared_ptr<tls_hdr> tls_h;

        // MQTT header
        std::shared_ptr<mqtt_hdr> mqtt_h;

        // parsed protocols so far
        protocol_bits protocols_avail;

        // OS type
        os_type os_type_t;

        uint32_t pkt_len;

        int run(packet &pkt);

        protocols_types get_protocol_type()
        {
            if (protocols_avail.has_ipv4()) {
                return static_cast<protocols_types>(ipv4_h->protocol);
            } else if (protocols_avail.has_ipv6()) {
                return static_cast<protocols_types>(ipv6_h->nh);
            }

            return static_cast<protocols_types>(protocols_types::Protocol_Max);
        }

        bool contain_ipv4()
        {
            if (static_cast<Ether_Type>(eh->ethertype) == Ether_Type::Ether_Type_IPv4)
                return true;

            return false;
        }

        bool has_port()
        {
            if (protocols_avail.has_udp() ||
                protocols_avail.has_tcp()) {
                return true;
            }

            return false;
        }

        Port_Numbers get_dst_port()
        {
            if (protocols_avail.has_udp()) {
                return static_cast<Port_Numbers>(udp_h->dst_port);
            } else if (protocols_avail.has_tcp()) {
                return static_cast<Port_Numbers>(tcp_h->dst_port);
            }

            return Port_Numbers::Port_Number_Max;
        }

        Port_Numbers get_src_port()
        {
            if (protocols_avail.has_udp()) {
                return static_cast<Port_Numbers>(udp_h->src_port);
            } else if (protocols_avail.has_tcp()) {
                return static_cast<Port_Numbers>(tcp_h->src_port);
            }

            return Port_Numbers::Port_Number_Max;
        }

    private:
        void detect_os_signature();
        event_description parse_l4(packet &pkt);
        event_description parse_app_pkt(packet &pkt, Port_Numbers port);
        event_description parse_app(packet &pkt);
        event_description run_arp_filter(packet &pkt, logger *log, bool pkt_dump);
        bool exploit_search(packet &pkt);

        std::string ifname_;
        logger *log_;
        exploit_match expl_;
        bool pkt_dump_;
};

}

#endif
