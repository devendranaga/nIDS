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
#include <vector>
#include <event_def.h>

namespace firewall {

/**
 * @brief - implements firewall_interface stats.
*/
struct firewall_intf_stats {
    std::string ifname;
    uint64_t n_rx;
    uint64_t n_deny;
    uint64_t n_allowed;
    uint64_t n_events;
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

        firewall_pkt_stats(const firewall_pkt_stats &) = delete;
        const firewall_pkt_stats &operator=(const firewall_pkt_stats &) = delete;
        firewall_pkt_stats(const firewall_pkt_stats &&) = delete;
        const firewall_pkt_stats &&operator=(const firewall_pkt_stats &&) = delete;

        ~firewall_pkt_stats() { }

    private:
        explicit firewall_pkt_stats() { }
        std::vector<firewall_intf_stats> stats_;

        /**
         * @brief - increment rx count for the given interface.
         *
         * @param [in] ifname - interface name.
         */
        void inc_n_rx(const std::string ifname);

        /**
         * @brief - increment denied packet count.
         *
         * @param [in] ifname -interface name.
         */
        void inc_n_deny(const std::string ifname);

        /**
         * @brief - increment n_allowed.
         *
         * @param [in] ifname - interface name.
        */
        void inc_n_allowed(const std::string ifname);

        /**
         * @brief - increment n_events.
         *
         * @param [in] ifname - interface name.
        */
        void inc_n_events(const std::string ifname);

        /**
         * @brief - increment icmp checksum errors.
         *
         * @param [in] ifname - interface name.
        */
        void inc_n_icmp_chksum_err(const std::string ifname);

        /**
         * @brief - increment ipv4 checksum errors.
         *
         * @param [in] ifname - interface name.
        */
        void inc_n_ipv4_chksum_err(const std::string ifname);
};

}

#endif

