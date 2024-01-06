/**
 * @brief - Implements ARP filter.
 *
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
 */
#include <common.h>
#include <parser.h>
#include <arp_filter.h>

namespace firewall {

event_description arp_filter::add_arp_frame(parser &p)
{
    std::vector<arp_entry>::iterator it;
    bool new_arp_entry = true;

    {
        std::unique_lock<std::mutex> lock(lock_);

        for (it = arp_table_.begin(); it != arp_table_.end(); it ++) {
            //
            // we already have sender's mac in our table.
            //
            // the packet could be arp req or reply. sender's mac gets swapped in reply
            // into target_hw_addr.
            if ((std::memcmp(it->sender_mac, p.arp_h.sender_hw_addr, FW_MACADDR_LEN) == 0) ||
                 (std::memcmp(it->sender_mac, p.arp_h.target_hw_addr, FW_MACADDR_LEN) == 0)) {
                new_arp_entry = false;
                break;
            }
        }

        if (new_arp_entry) {
            arp_entry arp_e(p.arp_h.sender_hw_addr,
                            p.arp_h.target_hw_addr,
                            p.arp_h.sender_proto_addr,
                            p.arp_h.target_proto_addr);

            //
            // if ARP Request is received set it
            if (p.arp_h.operation == static_cast<uint16_t>(Arp_Operation::Request)) {
                arp_e.state = Arp_State::Req;
            }
            arp_table_.push_back(arp_e);
        } else {
            //
            // ARP table entry is updated to resolved.
            if (p.arp_h.operation == static_cast<uint16_t>(Arp_Operation::Reply)) {
                std::memcpy(it->target_mac, p.arp_h.sender_hw_addr, FW_MACADDR_LEN);
                it->target_ipaddr = p.arp_h.sender_proto_addr;
                it->state = Arp_State::Resp;
                it->resolved = true;
            }

            tunables *t_conf = tunables::instance();
            timespec cur;
            double delta;

            clock_gettime(CLOCK_MONOTONIC, &cur);
            delta = diff_time_ns(&cur, &it->last_seen) / 1000000;

            it->last_seen = cur;

            if (delta < t_conf->arp_t.interframe_gap_msec)
                return event_description::Evt_ARP_Flood_Maybe_In_Progress;
        }
    }

    //print_arp_table(log_);

    return event_description::Evt_Parse_Ok;
}

}

