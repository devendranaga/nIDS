/**
 * @brief - Implements storage of packet statistics.
 *
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
*/
#include <packet_stats.h>

namespace firewall {

void firewall_pkt_stats::stats_update(event_description evt_desc,
                                      const std::string &ifname)
{
    switch (evt_desc) {
        case event_description::Evt_IPV4_Hdr_Chksum_Invalid: {
            stats_[ifname].n_ipv4_chksum_errors ++;
        } break;
        case event_description::Evt_Icmp_Inval_Chksum: {
            stats_[ifname].n_icmp_chksum_errors ++;
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
            stats_[ifname].n_rx ++;
        } break;
        case Pktstats_Type::Type_VLAN_Rx: {
            stats_[ifname].n_vlan_processed ++;
        } break;
        case Pktstats_Type::Type_ARP_Rx: {
            stats_[ifname].n_arp_processed ++;
        } break;
        case Pktstats_Type::Type_IPv4_Rx: {
            stats_[ifname].n_ipv4_processed ++;
        } break;
        case Pktstats_Type::Type_IPv6_Rx: {
            stats_[ifname].n_ipv6_processed ++;
        } break;
        case Pktstats_Type::Type_TCP_Rx: {
            stats_[ifname].n_tcp_processed ++;
        } break;
        case Pktstats_Type::Type_UDP_Rx: {
            stats_[ifname].n_udp_processed ++;
        } break;
        case Pktstats_Type::Type_ICMP_Rx: {
            stats_[ifname].n_icmp_processed ++;
        } break;
        case Pktstats_Type::Type_Deny: {
            stats_[ifname].n_deny ++;
        } break;
        case Pktstats_Type::Type_Allowed: {
            stats_[ifname].n_allowed ++;
        } break;
        case Pktstats_Type::Type_Events: {
            stats_[ifname].n_events ++;
        } break;
        case Pktstats_Type::Type_Startup_Time: {
            timestamp_wall(&stats_[ifname].startup_time);
        } break;
        default:
            return;
    }
}

void firewall_pkt_stats::get(const std::string &ifname, firewall_intf_stats &if_stats)
{
    if_stats = stats_[ifname];
}

}
