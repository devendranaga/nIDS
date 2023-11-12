/**
 * @brief - implements ICMP filter.
 *
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
*/
#include <parser.h>
#include <event_def.h>
#include <icmp_filter.h>
#include <event_mgr.h>

namespace firewall {

event_description icmp_filter::run_filter(parser &p, packet &pkt, logger *log, bool debug)
{
    rule_config *rules = rule_config::instance();
    std::vector<rule_config_item>::iterator it;
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
    if (evt_desc != event_description::Evt_Parse_Ok) {
        return evt_desc;
    }

    //
    // run rule filter
    for (it = rules->rules_cfg_.begin(); it != rules->rules_cfg_.end(); it ++) {
        //
        // check for non zero payload (echo-req and echo-reply)
        if (it->sig_mask.icmp_sig.icmp_non_zero_payload &&
            (it->type == rule_type::Deny)) {
            check_nonzero_len_payloads(p, it->rule_id, it->type);
        }
    }

    return evt_desc;
}

void icmp_filter::check_nonzero_len_payloads(parser &p,
                                             uint32_t rule_id,
                                             rule_type type)
{
    event_mgr *evt_mgr = event_mgr::instance();
    event_description evt_desc = event_description::Evt_Unknown_Error;

    if ((p.icmp_h->echo_req) &&
        (p.icmp_h->echo_req->data_len != 0)) {
        evt_desc = event_description::Evt_Icmp_Non_Zero_Echo_Req_Payload_Len;
    } else if ((p.icmp_h->echo_reply) &&
               (p.icmp_h->echo_reply->data_len != 0)) {
        evt_desc = event_description::Evt_Icmp_Non_Zero_ECho_Reply_Payload_Len;
    }

    if (evt_desc != event_description::Evt_Unknown_Error) {
        evt_mgr->store(event_type::Evt_Deny,
                       evt_desc,
                       rule_id,
                       p);
    }
}

}
