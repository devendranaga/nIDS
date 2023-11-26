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
            if (std::memcmp(it->mac, p.arp_h->sender_hw_addr, FW_MACADDR_LEN) == 0) {
                new_arp_entry = false;
                break;
            }
        }

        if (new_arp_entry) {
            arp_entry arp_e;

            std::memcpy(arp_e.mac, p.arp_h->sender_hw_addr, FW_MACADDR_LEN);
            arp_e.ipaddr = p.arp_h->sender_proto_addr;
            arp_e.state = Arp_State::Unknown;
            clock_gettime(CLOCK_MONOTONIC, &arp_e.last_seen);

            if (p.arp_h->operation == static_cast<uint16_t>(Arp_Operation::Request)) {
                arp_e.state = Arp_State::Req;
            }
            arp_table_.push_back(arp_e);
        } else {
            struct timespec cur;
            double delta_nsec;

            clock_gettime(CLOCK_MONOTONIC, &cur);
            delta_nsec = diff_timespec(&cur, &it->last_seen);
            //
            // check if the received / sent ARP frame is within the gap
            // of the interframe space
            if ((delta_nsec / 1000000.0) <
                 filter_conf_.inter_frame_gap_from_same_mac_msec) {
                it->last_seen = cur;
                return event_description::Evt_ARP_Flood_Maybe_In_Progress;
            }
        }
    }

    return event_description::Evt_Parse_Ok;
}

}

