/**
 * @brief - implements parser.
 * 
 * @copyright - 2023-present. All rights reserved. Devendra Naga.
*/
#include <logger.h>
#include <parser.h>
#include <event_mgr.h>
#include <protocols_types.h>

namespace firewall {

parser::parser(logger *log): log_(log) { }
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

int parser::run(packet &pkt)
{
    event_mgr *evt_mgr = event_mgr::instance();
    ether_type ether;
    event_description evt_desc = event_description::Evt_Unknown_Error;
    bool pkt_dump = true;
    protocols_types proto;

    //
    // deserialize ethernet header
    evt_desc = eh.deserialize(pkt, log_, pkt_dump);
    if (evt_desc != event_description::Evt_Unknown_Error) {
        evt_mgr->store(event_type::Evt_Deny, evt_desc, *this);
        return -1;
    }
    protocols_avail.set_eth();

    ether = eh.get_ethertype();

    //
    // check if its vlan, parse it
    if (eh.has_ethertype_vlan()) {
        vh.deserialize(pkt, log_, pkt_dump);
        protocols_avail.set_vlan();
        ether = eh.get_ethertype();
    }

    //
    // parse the rest of the l2 / l3 frames.
    switch (ether) {
        case ether_type::Ether_Type_ARP: {
            evt_desc = arp_h.deserialize(pkt, log_, pkt_dump);
            protocols_avail.set_arp();
        } break;
        case ether_type::Ether_Type_IPv4: {
            evt_desc = ipv4_h.deserialize(pkt, log_, pkt_dump);
            protocols_avail.set_ipv4();
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

    //
    // parse the rest of l4 frames.
    proto = get_protocol_type();
    switch (proto) {
        case static_cast<protocols_types>(protocols_types::Protocol_Udp): {
            evt_desc = udp_h.deserialize(pkt, log_, pkt_dump);
            protocols_avail.set_udp();
        } break;
        default:
            evt_desc = event_description::Evt_Unknown_Error;
        break;
    }

    //
    // detect the OS signature
    detect_os_signature();

    if (evt_desc != event_description::Evt_Parse_Ok) {
        // log the event and return
    }

    return 0;
}

}
