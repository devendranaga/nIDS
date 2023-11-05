/**
 * @brief - implements ICMP filter.
 *
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
*/
#include <parser.h>
#include <event_def.h>
#include <icmp_filter.h>

namespace firewall {

event_description icmp_filter::run_filter(parser &p, packet &pkt, logger *log, bool debug)
{
    event_description evt_desc;

    p.icmp_h = std::make_shared<icmp_hdr>();
    if (!p.icmp_h)
        return event_description::Evt_Unknown_Error;

    //
    // more fragments or frag_off is present
    // in an ICMP frame. Deny all ICMP frames with fragments by default.
    if ((p.ipv4_h->more_frag) || (p.ipv4_h->frag_off != 0)) {
        return event_description::Evt_Icmp_Pkt_Fragmented; 
    }

    //
    // ipv4_h->dst_addr is multicast for ICMP packet
    if (p.ipv4_h->is_dst_multicast()) {
        return event_description::Evt_Icmp_Dest_Addr_Multicast_In_IPv4;
    }

    //
    // ipv4_h->dst_addr is brodcast for ICMP packet
    if (p.ipv4_h->is_dst_broadcast()) {
        return event_description::Evt_Icmp_Dest_Addr_Broadcast_In_IPv4;
    }

    evt_desc = p.icmp_h->deserialize(pkt, log, debug);
    if (evt_desc != event_description::Evt_Parse_Ok)
        return evt_desc;

    return evt_desc;
}

}
