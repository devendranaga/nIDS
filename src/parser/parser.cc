/**
 * @brief - implements parser.
 * 
 * @copyright - 2023-present. All rights reserved. Devendra Naga.
*/
#include <logger.h>
#include <parser.h>
#include <packet_stats.h>
#include <event_mgr.h>
#include <protocols_types.h>
#include <port_numbers.h>

namespace firewall {

parser::parser(const std::string ifname, logger *log) :
                        ifname_(ifname),
                        log_(log),
                        pkt_dump_(true)
{ }
parser::~parser() { }

/**
 * Detect OS signatures by looking at the TTL value of ipv4 frame.
 * 
 * see : https://packetpushers.net/ip-time-to-live-and-hop-limit-basics/
*/
void parser::detect_os_signature()
{
    uint32_t ttl = 0;

    if (protocols_avail.has_ipv4()) {
        ttl = ipv4_h->ttl;
    }

    switch (ttl) {
        case 255:
            os_type_t = os_type::Linux_2_4;
        break;
        case 64:
            os_type_t = os_type::Linux_4_10_2015_or_Later;
        break;
        case 128:
            os_type_t = os_type::Win_10;
        break;
        default:
            os_type_t = os_type::Unknown;
        break;
    }
}

event_description parser::parse_l4(packet &pkt)
{
    event_description evt_desc = event_description::Evt_Unknown_Error;
    protocols_types proto;

    //
    // parse the rest of l4 frames.
    proto = get_protocol_type();
    switch (proto) {
        case protocols_types::Protocol_Udp: {
            udp_h = std::make_shared<udp_hdr>();
            if (!udp_h)
                return event_description::Evt_Unknown_Error;

            evt_desc = udp_h->deserialize(pkt, log_, pkt_dump_);
            protocols_avail.set_udp();
        } break;
        case protocols_types::Protocol_Icmp: {
            icmp_h = std::make_shared<icmp_hdr>();
            if (!icmp_h)
                return event_description::Evt_Unknown_Error;

            evt_desc = icmp_h->deserialize(pkt, log_, pkt_dump_);
            protocols_avail.set_icmp();
        } break;
        case protocols_types::Protocol_Icmp6: {
            icmp6_h = std::make_shared<icmp6_hdr>();
            if (!icmp6_h)
                return event_description::Evt_Unknown_Error;

            evt_desc = icmp6_h->deserialize(pkt, log_, pkt_dump_);
            protocols_avail.set_icmp6();
        } break;
        case protocols_types::Protocol_Tcp: {
            tcp_h = std::make_shared<tcp_hdr>();
            if (!tcp_h)
                return event_description::Evt_Unknown_Error;

            evt_desc = tcp_h->deserialize(pkt, log_, pkt_dump_);
            protocols_avail.set_tcp();
        } break;
        default:
            evt_desc = event_description::Evt_Unknown_Error;
        break;
    }

    //
    // parse failure or unsupported protocol
    if (evt_desc != event_description::Evt_Parse_Ok) {
        return evt_desc;
    }

    //
    // parse application
    if (this->has_port()) {
        //
        // matching exploit dst port results in dropping the frame
        // and generate immediate event.
        //
        // parse_app happens only if the known exploit is not matched.
        if (exploit_search(pkt) == false) {
            evt_desc = parse_app(pkt);
        }
    }

    return evt_desc;
}

bool parser::exploit_search(packet &pkt)
{
    Port_Numbers port;
    bool contains_exploit = false;

    //
    // match dst_port first
    port = this->get_dst_port();
    contains_exploit = expl_.match(port);

    //
    // try src_port match afterwards
    if (contains_exploit == false) {
        port = this->get_src_port();
        contains_exploit = expl_.match(port);
    }

    //
    // if a match found in either src_port or dst_port
    if (contains_exploit) {
        event_mgr *evt_mgr = event_mgr::instance();

        evt_mgr->store(event_type::Evt_Deny,
                       expl_.get_matching_evt_desc(port),
                       *this);
        return true;
    }

    return false;
}

event_description parser::parse_app(packet &pkt)
{
    event_description evt_desc = event_description::Evt_Unknown_Error;
    Port_Numbers dst_port;

    dst_port = this->get_dst_port();

    switch (dst_port) {
        case Port_Numbers::Port_Number_DHCP_Server:
        case Port_Numbers::Port_Number_DHCP_Client: {
            dhcp_h = std::make_shared<dhcp_hdr>();
            if (!dhcp_h)
                return event_description::Evt_Unknown_Error;

            evt_desc = dhcp_h->deserialize(pkt, log_, pkt_dump_);
            protocols_avail.set_dhcp();
        } break;
        case Port_Numbers::Port_Number_NTP: {
            ntp_h = std::make_shared<ntp_hdr>();
            if (!ntp_h)
                return event_description::Evt_Unknown_Error;

            evt_desc = ntp_h->deserialize(pkt, log_, pkt_dump_);
            protocols_avail.set_ntp();
        } break;
        case Port_Numbers::Port_Number_TLS: {
            tls_h = std::make_shared<tls_hdr>();
            if (!tls_h)
                return event_description::Evt_Unknown_Error;

            evt_desc = tls_h->deserialize(pkt, log_, pkt_dump_);
            protocols_avail.set_tls();
        } break;
        default:
            evt_desc = event_description::Evt_Unknown_Error;
        break;
    }

    return evt_desc;
}

int parser::run(packet &pkt)
{
    event_mgr *evt_mgr = event_mgr::instance();
    ether_type ether;
    event_description evt_desc = event_description::Evt_Unknown_Error;

	printf("size %lu\n", sizeof(parser));

    eh = std::make_shared<eth_hdr>();
    if (!eh)
        return -1;

    //
    // deserialize ethernet header
    evt_desc = eh->deserialize(pkt, log_, pkt_dump_);
    if (evt_desc != event_description::Evt_Parse_Ok) {
        evt_mgr->store(event_type::Evt_Deny, evt_desc, *this);
        return -1;
    }
    protocols_avail.set_eth();

    ether = eh->get_ethertype();

    //
    // check if its vlan, parse it
    if (eh->has_ethertype_vlan()) {
        vh = std::make_shared<vlan_hdr>();
        if (!vh)
            return -1;

        evt_desc = vh->deserialize(pkt, log_, pkt_dump_);
        if (evt_desc != event_description::Evt_Parse_Ok) {
            evt_mgr->store(event_type::Evt_Deny, evt_desc, *this);
            return -1;
        }
        protocols_avail.set_vlan();
        ether = eh->get_ethertype();
    }

    //
    // parse the rest of the l2 / l3 frames.
    switch (ether) {
        case ether_type::Ether_Type_ARP: {
            arp_h = std::make_shared<arp_hdr>();
            if (!arp_h)
                return -1;

            evt_desc = arp_h->deserialize(pkt, log_, pkt_dump_);
            protocols_avail.set_arp();
        } break;
        case ether_type::Ether_Type_IPv4: {
            ipv4_h = std::make_shared<ipv4_hdr>();
            if (!ipv4_h)
                return -1;

            evt_desc = ipv4_h->deserialize(pkt, log_, pkt_dump_);
            protocols_avail.set_ipv4();
        } break;
        case ether_type::Ether_Type_IPv6: {
            ipv6_h = std::make_shared<ipv6_hdr>();
            if (!ipv6_h)
                return -1;

            evt_desc = ipv6_h->deserialize(pkt, log_, pkt_dump_);
            protocols_avail.set_ipv6();
        } break;
        default:
            evt_desc = event_description::Evt_Unknown_Error;
        break;
    }

    //
    // parser failed to parse the input packet, deny it.
    if (evt_desc != event_description::Evt_Parse_Ok) {
        evt_mgr->store(event_type::Evt_Deny, evt_desc, *this);
        return -1;
    }

    if (protocols_avail.has_ipv4() ||
        protocols_avail.has_ipv6()) {
        evt_desc = parse_l4(pkt);
        //
        // parser failed to parse the input packet, deny it.
        if (evt_desc != event_description::Evt_Parse_Ok) {
            evt_mgr->store(event_type::Evt_Deny, evt_desc, *this);
            return -1;
        }
    }

    //
    // detect the OS signature
    detect_os_signature();

    return 0;
}

}
