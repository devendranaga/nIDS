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
        }
    }
}

void firewall_pkt_stats::inc_n_deny(const std::string ifname)
{
    for (auto it : stats_) {
        if (it.ifname == ifname) {
            it.n_deny ++;
        }
    }
}

void firewall_pkt_stats::inc_n_allowed(const std::string ifname)
{
    for (auto it : stats_) {
        if (it.ifname == ifname) {
            it.n_deny ++;
        }
    }
}

void firewall_pkt_stats::inc_n_events(const std::string ifname)
{
    for (auto it : stats_) {
        if (it.ifname == ifname) {
            it.n_deny ++;
        }
    }
}

}
