/**
 * @brief - Implements storage of packet statistics.
 *
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
*/
#ifndef __FW_PACKET_STATS_H__
#define __FW_PACKET_STATS_H__

#include <stdint.h>
#include <string>
#include <memory>
#include <map>
#include <time.h>
#include <sys/time.h>
#include <event_def.h>
#include <time_util.h>

namespace firewall {

/**
 * @brief - implements firewall_interface stats.
*/
struct firewall_intf_stats {
    std::string ifname;
    struct timespec startup_time;
    uint64_t n_rx;
    uint64_t n_deny;
    uint64_t n_allowed;
    uint64_t n_events;
    uint64_t n_vlan_processed;
    uint64_t n_arp_processed;
    uint64_t n_ipv4_processed;
    uint64_t n_ipv6_processed;
    uint64_t n_udp_processed;
    uint64_t n_tcp_processed;
    uint64_t n_ipv4_chksum_errors;
    uint64_t n_icmp_chksum_errors;

    explicit firewall_intf_stats() :
                    ifname(""),
                    n_rx(0),
                    n_deny(0),
                    n_allowed(0),
                    n_events(0),
                    n_ipv4_chksum_errors(0),
                    n_icmp_chksum_errors(0)
    { }
    ~firewall_intf_stats() { }
};

enum class Pktstats_Type {
    Type_Rx,
    Type_Startup_Time,
    Type_VLAN_Rx,
    Type_ARP_Rx,
    Type_IPv4_Rx,
    Type_IPv6_Rx,
    Type_UDP_Rx,
    Type_TCP_Rx,
    Type_Deny,
    Type_Allowed,
    Type_Events,
};

/**
 * @brief - defines packet statistics
*/
class firewall_pkt_stats {
    public:
        static firewall_pkt_stats *instance() 
        {
            static firewall_pkt_stats stats;
            return &stats;
        }

        /**
         * @brief - update the stats based on the input event.
         * 
         * @param [in] evt_desc - event description
         * @param [in] ifname - interface name
        */
        void stats_update(event_description evt_desc,
                          const std::string &ifname);

        /**
         * @brief - update the stats based on the counters.
         * 
         * @param [in] type - packet stats type
         * @param [in] ifname - interface name
        */
        void stats_update(Pktstats_Type type,
                          const std::string &ifname);
        void get(const std::string &ifname, firewall_intf_stats &if_stats);
        void get(std::map<std::string, firewall_intf_stats> &stats) { stats = stats_; }
        firewall_pkt_stats(const firewall_pkt_stats &) = delete;
        const firewall_pkt_stats &operator=(const firewall_pkt_stats &) = delete;
        firewall_pkt_stats(const firewall_pkt_stats &&) = delete;
        const firewall_pkt_stats &&operator=(const firewall_pkt_stats &&) = delete;

        ~firewall_pkt_stats() { }

    private:
        explicit firewall_pkt_stats() { }
        std::map<std::string, firewall_intf_stats> stats_;
};

}

#endif

