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
#include <packet_stats.h>

namespace firewall {

parser::parser(const std::string ifname,
               rule_config *rule_list,
               logger *log) :
                        ipv6_encap_h(nullptr),
                        ifname_(ifname),
                        rule_list_(rule_list),
                        log_(log),
                        pkt_dump_(true)
{
}
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
        ttl = ipv4_h.ttl;
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
    firewall_pkt_stats *stats = firewall_pkt_stats::instance();

    //
    // parse the rest of l4 frames.
    proto = get_protocol_type();

    //
    // special cases
    //
    // 1. ipv6 in ipv6 due to ipv6-ah
    //
    // we get ipv6 header and the nh points to ipv6-ah
    // once we decode ipv6-ah, the nh points to ipv6 or ipv4
    // for now we parsed ipv6 frame due to the fact that the availability
    // of the replay file to test this out.
    //
    // so once ipv6 is parsed below, we set the proto to
    // further parse the next protocol.
    //
    // So the call comes from the ipv6 parsing the ipv6-ah.
    // ipv6-ah sets the nh of the original ipv6 packet so
    // that we can parse.
    if (proto == protocols_types::Protocol_IPv6_Encapsulation) {
        ipv6_encap_h = std::make_shared<ipv6_hdr>();
        if (!ipv6_encap_h)
            return event_description::Evt_Out_Of_Memory;

        evt_desc = ipv6_encap_h->deserialize(pkt, log_, pkt_dump_);
        if (evt_desc != event_description::Evt_Parse_Ok)
            return evt_desc;

        proto = static_cast<protocols_types>(ipv6_encap_h->nh);
    }

    switch (proto) {
        case protocols_types::Protocol_Udp: {
            present_bits.udp = 1;
            stats->stats_update(Pktstats_Type::Type_UDP_Rx, ifname_);

            evt_desc = udp_h.deserialize(pkt, log_, pkt_dump_);
            if (evt_desc == event_description::Evt_Parse_Ok)
                protocols_avail.set_udp();
        } break;
        case protocols_types::Protocol_Icmp: {
            //
            // set ICMP is present
            present_bits.icmp = 1;

            //
            // update icmp rx stats
            stats->stats_update(Pktstats_Type::Type_ICMP_Rx, ifname_);

            evt_desc = icmp_filter::instance()->run_auto_sig_checks(
                                             *this, log_, pkt_dump_);
            if (evt_desc != event_description::Evt_Parse_Ok)
                break;

            evt_desc = icmp_h.deserialize(pkt, log_, pkt_dump_);
            if (evt_desc == event_description::Evt_Parse_Ok)
                protocols_avail.set_icmp();
        } break;
        case protocols_types::Protocol_Icmp6: {
            present_bits.icmp6 = 1;

            evt_desc = icmp6_h.deserialize(pkt, log_, pkt_dump_);
            if (evt_desc == event_description::Evt_Parse_Ok)
                protocols_avail.set_icmp6();
        } break;
        case protocols_types::Protocol_Igmp: {
            present_bits.igmp = 1;

            evt_desc = igmp_h.deserialize(pkt, log_, pkt_dump_);
            if (evt_desc == event_description::Evt_Parse_Ok)
                protocols_avail.set_igmp();
        } break;
        case protocols_types::Protocol_Tcp: {
            present_bits.tcp = 1;
            stats->stats_update(Pktstats_Type::Type_TCP_Rx, ifname_);

            evt_desc = tcp_h.deserialize(pkt, log_, pkt_dump_);
            if (evt_desc == event_description::Evt_Parse_Ok)
                protocols_avail.set_tcp();
        } break;
        //
        // Since ESP is an encrypted frame and we cannot track it
        // Pass this frame.
        case protocols_types::Protocol_ESP: {
            evt_desc = event_description::Evt_Parse_Ok;
        } break;
        case protocols_types::Protocol_GREP: {
            present_bits.gre = 1;
            evt_desc = gre_h.deserialize(pkt, log_, pkt_dump_);
            if (evt_desc == event_description::Evt_Parse_Ok)
                protocols_avail.set_gre();
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

event_description parser::parse_app_pkt(packet &pkt, Port_Numbers port)
{
    event_description evt_desc = event_description::Evt_Unknown_Error;

   switch (port) {
        //
        // DHCP operates on two ports one server and one client
        case Port_Numbers::Port_Number_DHCP_Server:
        case Port_Numbers::Port_Number_DHCP_Client: {
            present_bits.dhcp = 1;

            evt_desc = dhcp_h.deserialize(pkt, log_, pkt_dump_);
            if (evt_desc == event_description::Evt_Parse_Ok)
                protocols_avail.set_dhcp();
        } break;
        case Port_Numbers::Port_Number_NTP: {
            present_bits.ntp = 1;

            evt_desc = ntp_h.deserialize(pkt, log_, pkt_dump_);
            if (evt_desc == event_description::Evt_Parse_Ok)
                protocols_avail.set_ntp();
        } break;
        case Port_Numbers::Port_Number_TLS: {
            present_bits.tls = 1;

            evt_desc = tls_h.deserialize(pkt, log_, pkt_dump_);
            if (evt_desc == event_description::Evt_Parse_Ok)
                protocols_avail.set_tls();
        } break;
#if defined(FW_ENABLE_AUTOMOTIVE)
        case Port_Numbers::Port_Number_DoIP: {
            present_bits.mqtt = 1;

            evt_desc = doip_h.deserialize(pkt, log_, pkt_dump_);
            if (evt_desc == event_description::Evt_Parse_Ok)
                protocols_avail.set_doip();
        } break;
#endif
        case Port_Numbers::Port_Number_MQTT: {
            present_bits.mqtt = 1;

            evt_desc = mqtt_h.deserialize(pkt, log_, pkt_dump_);
            if (evt_desc == event_description::Evt_Parse_Ok)
                protocols_avail.set_mqtt();
        } break;
        default:
            evt_desc = event_description::Evt_Unknown_Port;
        break;
    }

    //
    // for unknown ports lets call custom parser and find if
    // the port number is defined in the configuration.
    if (evt_desc == event_description::Evt_Unknown_Port) {
        evt_desc = parse_custom_ports(pkt);
    }

    return evt_desc;
}

event_description parser::parse_app(packet &pkt)
{
    event_description evt_desc = event_description::Evt_Unknown_Error;

    evt_desc = parse_app_pkt(pkt, this->get_dst_port());
    if (evt_desc == event_description::Evt_Unknown_Error) {
        evt_desc = parse_app_pkt(pkt, this->get_src_port());
    }

    return evt_desc;
}

int parser::run(packet &pkt)
{
    event_mgr *evt_mgr = event_mgr::instance();
    Ether_Type ether;
    event_description evt_desc = event_description::Evt_Unknown_Error;
    firewall_pkt_stats *stats = firewall_pkt_stats::instance();

    present_bits.eth = 1;

    //
    // deserialize ethernet header
    evt_desc = eh.deserialize(pkt, log_, pkt_dump_);
    if (evt_desc != event_description::Evt_Parse_Ok) {
        evt_mgr->store(event_type::Evt_Deny, evt_desc, *this);
        return -1;
    }
    protocols_avail.set_eth();

    ether = eh.get_ethertype();

    //
    // check if its IEEE 802.1ad provider bridge, parse it
    if (eh.has_ethertype_8021ad()) {
        present_bits.ieee8021ad = 1;

        evt_desc = ieee8021ad_h.deserialize(pkt, log_, pkt_dump_);
        if (evt_desc != event_description::Evt_Parse_Ok) {
            evt_mgr->store(event_type::Evt_Deny, evt_desc, *this);
            return -1;
        }
        protocols_avail.set_ieee8021ad();
        ether = ieee8021ad_h.get_ethertype();
    }

    //
    // check if its vlan, parse it
    if (eh.has_ethertype_vlan()) {
        present_bits.vlan = 1;
        stats->stats_update(Pktstats_Type::Type_VLAN_Rx, ifname_);

        evt_desc = vh.deserialize(pkt, log_, pkt_dump_);
        if (evt_desc != event_description::Evt_Parse_Ok) {
            evt_mgr->store(event_type::Evt_Deny, evt_desc, *this);
            return -1;
        }
        protocols_avail.set_vlan();
        ether = vh.get_ethertype();
    }

    //
    // Parse macsec frame.
    if (ether == Ether_Type::Ether_Type_MACsec) {
        present_bits.macsec = 1;

        evt_desc = macsec_h.deserialize(pkt, log_, pkt_dump_);
        if (evt_desc != event_description::Evt_Parse_Ok) {
            evt_mgr->store(event_type::Evt_Deny, evt_desc, *this);
            return -1;
        }

        protocols_avail.set_macsec();

        //
        // We cannot decrypt the frame, we simply return the parse ok.
        if (macsec_h.is_an_encrypted_frame()) {
            return 0;
        }
        //
        // We have an authenticated frame here, lets decode it further.
        ether = macsec_h.get_ethertype();
    }

    if (ether == Ether_Type::Ether_Type_PPPOE) {
        present_bits.pppoe = 1;
        evt_desc = pppoe_h.deserialize(pkt, log_, pkt_dump_);
        if (evt_desc != event_description::Evt_Parse_Ok) {
            evt_mgr->store(event_type::Evt_Deny, evt_desc, *this);
            return -1;
        }

        protocols_avail.set_pppoe();

        //
        // PPPOE has different protocol numbers so get them converted to
        // ethertype.
        ether = pppoe_h.get_ethertype();
    }

    //
    // parse the rest of the l2 / l3 frames.
    switch (ether) {
        case Ether_Type::Ether_Type_ARP: {
            evt_desc = run_arp_filter(pkt, log_, pkt_dump_);
        } break;
        case Ether_Type::Ether_Type_IPv4: {
            present_bits.ipv4 = 1;
            stats->stats_update(Pktstats_Type::Type_IPv4_Rx, ifname_);

            evt_desc = ipv4_h.deserialize(pkt, log_, pkt_dump_);
            if (evt_desc == event_description::Evt_IPV4_Hdr_Chksum_Invalid) {
                firewall_pkt_stats::instance()->stats_update(evt_desc, ifname_);
            }
            if (evt_desc == event_description::Evt_Parse_Ok)
                protocols_avail.set_ipv4();
        } break;
        case Ether_Type::Ether_Type_IPv6: {
            present_bits.ipv6 = 1;
            stats->stats_update(Pktstats_Type::Type_IPv6_Rx, ifname_);

            evt_desc = ipv6_h.deserialize(pkt, log_, pkt_dump_);
            if (evt_desc == event_description::Evt_Parse_Ok)
                protocols_avail.set_ipv6();
        } break;
        case Ether_Type::Ether_Type_IEEE8021X: {
            present_bits.ieee8021x_eap = 1;
            evt_desc = ieee8021x_h.deserialize(pkt, log_, pkt_dump_);
            if (evt_desc == event_description::Evt_Parse_Ok)
                protocols_avail.set_eap();
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

    //
    // run the rule filters
    run_rule_filters(pkt, log_, pkt_dump_);

    return 0;
}

event_description parser::run_arp_filter(packet &pkt,
                                         logger *log, bool pkt_dump)
{
    event_description evt_desc = event_description::Evt_Unknown_Error;
    arp_filter *arp_f;
    firewall_pkt_stats *stats = firewall_pkt_stats::instance();

    present_bits.arp = 1;
    stats->stats_update(Pktstats_Type::Type_ARP_Rx, ifname_);

    //
    // deserialize ARP frame
    evt_desc = arp_h.deserialize(pkt, log_, pkt_dump_);
    if (evt_desc != event_description::Evt_Parse_Ok)
       return evt_desc;

    protocols_avail.set_arp();

    //
    // run the filter
    arp_f = arp_filter::instance();
    evt_desc = arp_f->add_arp_frame(*this);

    //arp_f->print_arp_table(log);

    return evt_desc;
}

void parser::run_rule_filters(packet &p,
                              logger *log,
                              bool pkt_dump)
{
    std::vector<rule_config_item>::iterator it;
    int denied = -1;

    for (it = rule_list_->rules_cfg_.begin();
         it != rule_list_->rules_cfg_.end(); it ++) {
        //
        // run eh filtering
        if (it->sig_mask.eth_sig.active()) {
            denied = eth_filter::instance()->run_filter(*this, it, log, pkt_dump);
            if (denied != 0)
                break;
        }

        //
        // run port filtering
        if (it->sig_mask.port_list_sig.port_list)
            port_filter::instance()->run(*this, it, log, pkt_dump);

        if (it->sig_mask.icmp_sig.icmp_non_zero_payload)
            icmp_filter::instance()->run_filter(*this, it, log_, pkt_dump_);
    }
}

event_description parser::parse_custom_app_ports(packet &pkt,
                                                 Packet_Direction dir,
                                                 App_Type app_type,
                                                 int port)
{
    event_description evt_desc = event_description::Evt_Unknown_Error;

    if ((udp_h.dst_port == port) ||
        (udp_h.src_port == port)) {
#if defined(FW_ENABLE_AUTOMOTIVE)
       if (app_type == App_Type::SomeIP) {
           evt_desc = someip_h.deserialize(pkt, log_, pkt_dump_);
       }
#endif
    }

    return evt_desc;
}

event_description parser::parse_custom_ports(packet &pkt)
{
    event_description evt_desc = event_description::Evt_Unknown_Port;
    Packet_Direction dir;
    App_Type app_type;
    int port = -1;

    for (auto it : rule_list_->rules_cfg_) {
        port = -1;

        if (this->protocols_avail.has_udp() && it.sig_mask.udp_sig.port) {
            dir = it.udp_rule.dir;
            app_type = it.udp_rule.app_type;
            port = it.udp_rule.port;
        }

        if (port != -1) {
            evt_desc = parse_custom_app_ports(pkt, dir, app_type, port);
            if (evt_desc != event_description::Evt_Parse_Ok)
                return evt_desc;
        }
    }

   return evt_desc;
}

}

