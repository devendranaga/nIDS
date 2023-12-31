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
// IEEE 802.1ad header
#include <ieee_8021ad.h>
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
// IGMP header
#include <igmp.h>
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
// SOME/IP header
#include <some_ip.h>
// EAP header
#include <eap.h>
// PPPOE header
#include <pppoe.h>
// GRE header
#include <gre.h>
// VRRP header
#include <vrrp.h>
// TFTP header
#include <tftp.h>
// Known exploits
#include <known_exploits.h>

#include <packet.h>
#include <port_numbers.h>
#include <rule_parser.h>
#include <os_signatures.h>
#include <packet_stats.h>
#include <eth_filter.h>
#include <arp_filter.h>
#include <icmp_filter.h>
#include <port_filter.h>

namespace firewall {

/**
 * @brief - defines which protocols are available.
*/
struct protocol_bits {
    public:
        explicit protocol_bits() :
                            eth(0),
                            macsec(0),
                            pppoe(0),
                            ipv4(0),
                            ieee8021ad(0),
                            arp(0),
                            vlan(0),
                            icmp(0),
                            tcp(0),
                            udp(0),
                            ipv6(0),
                            icmp6(0),
                            igmp(0),
                            dhcp(0),
                            ntp(0),
                            doip(0),
                            tls(0),
                            mqtt(0),
                            someip(0),
                            eap(0),
                            gre(0),
                            vrrp(0),
                            tftp(0)
        { }
        ~protocol_bits() { }

        void set_eth() { eth = 1; }
        void set_macsec() { macsec = 1; }
        void set_ipv4() { ipv4 = 1; }
        void set_ieee8021ad() { ieee8021ad = 1; }
        void set_arp() { arp = 1; }
        void set_vlan() { vlan = 1; }
        void set_icmp() { icmp = 1; }
        void set_tcp() { tcp = 1; }
        void set_udp() { udp = 1; }
        void set_ipv6() { ipv6 = 1; }
        void set_icmp6() { icmp6 = 1; }
        void set_igmp() { igmp = 1; }
        void set_dhcp() { dhcp = 1; }
        void set_ntp() { ntp = 1; }
        void set_doip() { doip = 1; }
        void set_tls() { tls = 1; }
        void set_mqtt() { mqtt = 1; }
        void set_someip() { someip = 1; }
        void set_eap() { eap = 1; }
        void set_pppoe() { pppoe = 1; }
        void set_gre() { gre = 1; }
        void set_vrrp() { vrrp = 1; }
        void set_tftp() { tftp = 1; }
        /**
         * @brief - Has the packet contain ethernet ?
         *
         * @return true on success false on failure.
        */
        bool has_eth() const { return eth == 1; }

        /**
         * @brief - Has the packet contain macsec ?
         *
         * @return true on success false on failure.
        */
        bool has_macsec() const { return macsec == 1; }
        /**
         * @brief - Has the parser found an ipv4 packet ?
         *
         * @return true on success false on failure.
         */
        bool has_ipv4() const { return ipv4 == 1; }
        bool has_ieee8021ad() const { return ieee8021ad == 1; }
        bool has_arp() const { return arp == 1; }
        /**
         * @brief - Has the parser found a vlan frame ?
         *
         * @return true on success false on failure.
         */
        bool has_vlan() const { return vlan == 1; }
        bool has_icmp() const { return icmp == 1; }
        /**
         * @brief - Has the parser found a tcp packet ?
         *
         * @return true on success false on failure.
         */
        bool has_tcp() const { return tcp == 1; }
        /**
         * @brief - Has the parser found a udp packet ?
         *
         * @return true on success false on failure.
         */
        bool has_udp() const { return udp == 1; }
        bool has_ipv6() const { return ipv6 == 1; }
        bool has_icmp6() const { return icmp6 == 1; }
        bool has_igmp() const { return igmp == 1; }
        bool has_dhcp() const { return dhcp == 1; }
        bool has_ntp() const { return ntp == 1; }
        bool has_doip() const { return doip == 1; }
        bool has_tls() const { return tls == 1; }
        bool has_mqtt() const { return mqtt == 1; }
        bool has_someip() const { return someip == 1; }
        bool has_eap() const { return eap == 1; }
        bool has_pppoe() const { return pppoe == 1; }
        bool has_gre() const { return gre == 1; }
        bool has_vrrp() const { return vrrp == 1; }
        bool has_tftp() const { return tftp == 1; }

    private:
        uint32_t eth:1;
        uint32_t macsec:1;
        uint32_t pppoe:1;
        uint32_t ipv4:1;
        uint32_t ieee8021ad:1;
        uint32_t arp:1;
        uint32_t vlan:1;
        uint32_t icmp:1;
        uint32_t tcp:1;
        uint32_t udp:1;
        uint32_t ipv6:1;
        uint32_t icmp6:1;
        uint32_t igmp:1;
        uint32_t dhcp:1;
        uint32_t ntp:1;
        uint32_t doip:1;
        uint32_t tls:1;
        uint32_t mqtt:1;
        uint32_t someip:1;
        uint32_t eap:1;
        uint32_t gre:1;
        uint32_t vrrp:1;
        uint32_t tftp:1;
};

/**
 * @brief - defines what has been detected, it could be that the parsing
 *          might have failed and protocol_bits represent successfully
 *          parsed packets.
*/
struct protocol_present_bits {
    uint32_t eth:1;
    uint32_t vlan:1;
    uint32_t pppoe:1;
    uint32_t arp:1;
    uint32_t ieee8021ad:1;
    uint32_t macsec:1;
    uint32_t ieee8021x_eap:1;
    uint32_t ipv4:1;
    uint32_t ipv6:1;
    uint32_t ipsec_ah:1;
    uint32_t tcp:1;
    uint32_t udp:1;
    uint32_t icmp:1;
    uint32_t icmp6:1;
    uint32_t igmp:1;
    uint32_t dhcp:1;
    uint32_t ntp:1;
#if defined(FW_ENABLE_AUTOMOTIVE)
    uint32_t doip:1;
    uint32_t someip:1;
#endif
    uint32_t tls:1;
    uint32_t mqtt:1;
    uint32_t gre:1;
    uint32_t vrrp:1;
    uint32_t tftp:1;

    explicit protocol_present_bits()
    {
        std::memset(this, 0, sizeof(*this));
    }
    ~protocol_present_bits() { }
};

/**
 * @brief - Implements packet parser.
*/
struct parser {
    public:
        explicit parser(const std::string ifname,
                        rule_config *rule_list,
                        logger *log);
        ~parser();

        // ethernet header
        eth_hdr eh;

        // MACsec header
        ieee8021ae_hdr macsec_h;

        // IEEE 802.1ad header
        ieee8021ad_hdr ieee8021ad_h;

        // VLAN header
        vlan_hdr vh;

        // ARP header
        arp_hdr arp_h;

        // IPV4 header
        ipv4_hdr ipv4_h;

        // IPV6 header
        ipv6_hdr ipv6_h;

        // IPv6 Encapsulation header
        std::shared_ptr<ipv6_hdr> ipv6_encap_h;

        // IPSec Authentication header
        ipsec_ah_hdr ipsec_ah_h;

        // TCP header
        tcp_hdr tcp_h;

        // UDP header
        udp_hdr udp_h;

        // ICMP header
        icmp_hdr icmp_h;

        // ICMP6 header
        icmp6_hdr icmp6_h;

        // IGMP header
        igmp_hdr igmp_h;

        // DHCP header
        dhcp_hdr dhcp_h;

        // NTP header
        ntp_hdr ntp_h;

#if defined(FW_ENABLE_AUTOMOTIVE)
        // DoIP header
        doip_hdr doip_h;

        // SOME/IP header
        someip_hdr someip_h;
#endif

        // TLS header
        tls_hdr tls_h;

        // MQTT header
        mqtt_hdr mqtt_h;

        ieee8021x_hdr ieee8021x_h;

        // PPPOE header
        pppoe_hdr pppoe_h;

        // GRE header
        gre_hdr gre_h;

        // VRRP header
        vrrp_hdr vrrp_h;

        // TFTP header
        tftp_hdr tftp_h;

        // present protocols.. they might have failed parse.
        protocol_present_bits present_bits;

        // parsed protocols so far sucessfully.
        protocol_bits protocols_avail;

        // OS type
        os_type os_type_t;

        uint32_t pkt_len;

        int run(packet &pkt);

        protocols_types get_protocol_type()
        {
            //
            // sometimes we get tunneled frames,
            // in that case we need to find the real protocol type
            // for now we parsed IPV4 in GRE.
            if (protocols_avail.has_gre()) {
                if (gre_h.ipv4_h)
                    return gre_h.ipv4_h->get_protocol();
            } else if (protocols_avail.has_ipv4()) {
                return ipv4_h.get_protocol();
            } else if (protocols_avail.has_ipv6()) {
                return static_cast<protocols_types>(ipv6_h.nh);
            }

            return static_cast<protocols_types>(protocols_types::Protocol_Max);
        }

        bool contain_ipv4()
        {
            if (static_cast<Ether_Type>(eh.ethertype) == Ether_Type::Ether_Type_IPv4)
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
                return static_cast<Port_Numbers>(udp_h.dst_port);
            } else if (protocols_avail.has_tcp()) {
                return static_cast<Port_Numbers>(tcp_h.dst_port);
            }

            return Port_Numbers::Port_Number_Max;
        }

        Port_Numbers get_src_port()
        {
            if (protocols_avail.has_udp()) {
                return static_cast<Port_Numbers>(udp_h.src_port);
            } else if (protocols_avail.has_tcp()) {
                return static_cast<Port_Numbers>(tcp_h.src_port);
            }

            return Port_Numbers::Port_Number_Max;
        }

        rule_config *get_rules() { return rule_list_; }

    private:
        void detect_os_signature();
        event_description parse_l4(packet &pkt);
        event_description parse_app_pkt(packet &pkt, Port_Numbers port);
        event_description parse_app(packet &pkt);
        event_description parse_custom_ports(packet &pkt);
        event_description parse_custom_app_ports(packet &pkt,
                                                 Packet_Direction dir,
                                                 App_Type type,
                                                 int port);
        event_description run_arp_filter(packet &pkt, logger *log, bool pkt_dump);
        void run_rule_filters(packet &pkt,
                              logger *log,
                              bool pkt_dump);
        bool exploit_search(packet &pkt);

        std::string ifname_;
        rule_config *rule_list_;
        logger *log_;
        exploit_match expl_;
        bool pkt_dump_;
};

}

#endif

