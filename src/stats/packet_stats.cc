/**
 * @brief - Implements storage of packet statistics.
 *
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
*/
#include <packet_stats.h>

namespace firewall {

void firewall_pkt_stats::inc_n_rx(const std::string ifname)
{
    for (auto it : stats_) {
        if (it.ifname == ifname) {
            it.n_rx ++;
            break;
        }
    }
}

void firewall_pkt_stats::inc_n_deny(const std::string ifname)
{
    for (auto it : stats_) {
        if (it.ifname == ifname) {
            it.n_deny ++;
            break;
        }
    }
}

void firewall_pkt_stats::inc_n_allowed(const std::string ifname)
{
    for (auto it : stats_) {
        if (it.ifname == ifname) {
            it.n_allowed ++;
            break;
        }
    }
}

void firewall_pkt_stats::inc_n_events(const std::string ifname)
{
    for (auto it : stats_) {
        if (it.ifname == ifname) {
            it.n_events ++;
            break;
        }
    }
}

void firewall_pkt_stats::inc_n_icmp_chksum_err(const std::string ifname)
{
    for (auto it : stats_) {
        if (it.ifname == ifname) {
            it.n_icmp_chksum_errors ++;
            break;
        }
    }
}

void firewall_pkt_stats::inc_n_ipv4_chksum_err(const std::string ifname)
{
    for (auto it : stats_) {
        if (it.ifname == ifname) {
            it.n_ipv4_chksum_errors ++;
            break;
        }
    }
}

void firewall_pkt_stats::stats_update(event_description evt_desc,
                                      const std::string &ifname)
{
    switch (evt_desc) {
        case event_description::Evt_IPV4_Hdr_Chksum_Invalid: {
            inc_n_ipv4_chksum_err(ifname);
        } break;
        case event_description::Evt_Icmp_Inval_Chksum: {
            inc_n_icmp_chksum_err(ifname);
        } break;
        default:
            return;
    }
}

void firewall_pkt_stats::stats_update(Pktstats_Type type,
                                      const std::string &ifname)
{
    switch (type) {
        case Pktstats_Type::Type_Rx: {
            inc_n_rx(ifname);
        } break;
        case Pktstats_Type::Type_Deny: {
            inc_n_deny(ifname);
        } break;
        case Pktstats_Type::Type_Events: {
            inc_n_events(ifname);
        } break;
        case Pktstats_Type::Type_Allowed: {
            inc_n_allowed(ifname);
        } break;
        default:
            return;
    }
}

}
