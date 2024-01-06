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

event_description icmp_filter::run_auto_sig_checks(parser &p, logger *log, bool debug)
{
    event_description evt_desc = event_description::Evt_Parse_Ok;

    //
    // more fragments or frag_off is present
    // in an ICMP frame. Deny all ICMP frames with fragments by default.
    if (p.ipv4_h.is_a_frag())
        evt_desc = event_description::Evt_Icmp_Pkt_Fragmented;

    //
    // ipv4_h.dst_addr is multicast for ICMP packet
    if (p.ipv4_h.is_dst_multicast() &&
        (evt_desc == event_description::Evt_Parse_Ok))
        evt_desc = event_description::Evt_Icmp_Dest_Addr_Multicast_In_IPv4;

    //
    // ipv4_h.dst_addr is brodcast for ICMP packet
    if (p.ipv4_h.is_dst_broadcast() &&
        (evt_desc == event_description::Evt_Parse_Ok))
        evt_desc = event_description::Evt_Icmp_Dest_Addr_Broadcast_In_IPv4;

    //
    // chance of a smurf attack
    //
    // in general, the sender expect us to provide a echo-reply on to
    // the directed broadcast address, in turn flooding the replies on
    // the entire network.
    if (p.ipv4_h.is_src_directed_broadcast() &&
        (evt_desc == event_description::Evt_Parse_Ok))
        evt_desc = event_description::Evt_Icmp_Src_IPv4_Addr_Is_Direct_Broadcast;

    return evt_desc;
}

void icmp_filter::run_filter(parser &p,
                             std::vector<rule_config_item>::iterator &rule,
                             logger *log, bool debug)
{
    //
    // run rule filter
    //
    // check for non zero payload (echo-req and echo-reply)
    check_nonzero_len_payloads(p, rule->rule_id, rule->type);

    // add the ICMP frame for tracking
    manage_icmp(p);
}

void icmp_filter::manage_icmp(parser &p)
{
    event_mgr *evt_mgr = event_mgr::instance();
    std::vector<icmp_info>::iterator it;
    uint32_t src_ipaddr = 0;
    uint32_t dst_ipaddr = 0;
    uint32_t id = 0;
    icmp_info i;

    if (p.protocols_avail.has_ipv4()) {
        src_ipaddr = p.ipv4_h.src_addr;
        dst_ipaddr = p.ipv4_h.dst_addr;
    }

    if (p.protocols_avail.has_icmp()) {
        if (p.icmp_h.echo_req)
            id = p.icmp_h.echo_req->id;
        if (p.icmp_h.echo_reply)
            id = p.icmp_h.echo_reply->id;
    }

    std::unique_lock<std::mutex> lock(table_lock_);

    //
    // try finding the previous query
    for (it = icmp_list_.begin(); it != icmp_list_.end(); it ++) {
        if ((it->sender_ip == src_ipaddr) &&
            (it->dest_ip == dst_ipaddr) &&
            (it->id == id)) {
            break;
        } else if ((it->sender_ip == dst_ipaddr) &&
                   (it->sender_ip == src_ipaddr) &&
                   (it->id == id)) {
            break;
        }
    }

    //
    // new echo-request and echo-reply
    if (it == icmp_list_.end()) {
        //
        // new echo request.. lets add it
        if (p.icmp_h.echo_req) {
            i.sender_ip = p.ipv4_h.src_addr;
            i.dest_ip = p.ipv4_h.dst_addr;

            icmp_seq_info seq_info;

            seq_info.state = Icmp_State::Echo_Req_Observed;
            seq_info.seq = p.icmp_h.echo_req->seq_no;
            timestamp_perf(&seq_info.seq_ts);
            i.seq_info.push_back(seq_info);
            i.id = p.icmp_h.echo_req->id;
            i.n_icmp = 0;

            timestamp_perf(&i.cur_echo_req_time);

            icmp_list_.push_back(i);
        } else if (p.icmp_h.echo_reply) {
            //
            // we've received echo-reply without echo-request
            evt_mgr->store(
                    event_type::Evt_Deny,
                    event_description::Evt_ICmp_Echo_Reply_Received_Without_Echo_Req,
                    p);
            return;
        }
    } else {
        if (p.icmp_h.echo_reply) {
            it->sender_ip = p.ipv4_h.src_addr;
            it->dest_ip = p.ipv4_h.dst_addr;

            std::vector<icmp_seq_info>::iterator it1;
            bool matching_seq_no = false;

            for (it1 = it->seq_info.begin(); it1 != it->seq_info.end(); it1 ++) {
                if (it1->seq == p.icmp_h.echo_reply->seq_no) {
                    matching_seq_no = true;
                    if (it1->state == Icmp_State::Echo_Reply_Observed) {
                        // duplicate frame received
                    } else {
                        it1->state = Icmp_State::Echo_Reply_Observed;
                    }
                    break;
                }
            }

            if (matching_seq_no) {
                it->seq_info.erase(it1);
            } else {
                // sequence number do not match
                //
                // echo-request and echo-reply do not match with the sequence number
                printf("invalid seq no %d for the requested echo_reply\n",
                            p.icmp_h.echo_reply->seq_no);
            }

            it->prev_echo_reply_time = it->cur_echo_reply_time;
            //
            // update the echo_reply
            timestamp_perf(&it->cur_echo_reply_time);
        }
        if (p.icmp_h.echo_req) {
            it->sender_ip = p.ipv4_h.src_addr;
            it->dest_ip = p.ipv4_h.dst_addr;

            icmp_seq_info seq_info;

            seq_info.state = Icmp_State::Echo_Req_Observed;
            seq_info.seq = p.icmp_h.echo_req->seq_no;
            timestamp_perf(&seq_info.seq_ts);
            it->seq_info.push_back(seq_info);

            it->prev_echo_req_time = it->prev_echo_req_time;

            //
            // update the echo_req with new sequence number
            timestamp_perf(&it->cur_echo_req_time);
        }
    }
}

/**
 * @brief - manage the timeout. echo-request and echo-reply with sequence numbers match.
*/
void icmp_filter::list_mgr_thread()
{
    tunables *tunable_config;
    struct timespec tp;

    tunable_config = tunables::instance();

    while (1) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        std::vector<icmp_info>::iterator it;

        timestamp_perf(&tp);
        std::unique_lock<std::mutex> lock(table_lock_);
        for (it = icmp_list_.begin(); it != icmp_list_.end(); it ++) {
            std::vector<icmp_seq_info>::iterator it1;
            for (it1 = it->seq_info.begin(); it1 != it->seq_info.end(); ) {
                double delta = diff_time_ns(&tp, &it1->seq_ts) / 1000000;
                // over the interval.. free up the memory
                if (delta >= tunable_config->icmp_t.icmp_entry_timeout_ms) {
                    it->seq_info.erase(it1);
                } else {
                    it1 ++;
                }
            }
        }
    }
}

/**
 * @brief - Check for non-zero payload length of ICMP echo-request and echo-reply frames.
*/
void icmp_filter::check_nonzero_len_payloads(parser &p,
                                             uint32_t rule_id,
                                             rule_type type)
{
    event_mgr *evt_mgr = event_mgr::instance();
    event_description evt_desc = event_description::Evt_Unknown_Error;

    //
    // if filter is configured to drop all pings with non-zero data length
    //
    if ((p.icmp_h.echo_req) &&
        (p.icmp_h.echo_req->data_len != 0)) {
        evt_desc = event_description::Evt_Icmp_Non_Zero_Echo_Req_Payload_Len;
    } else if ((p.icmp_h.echo_reply) &&
               (p.icmp_h.echo_reply->data_len != 0)) {
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

