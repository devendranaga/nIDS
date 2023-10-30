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

}
