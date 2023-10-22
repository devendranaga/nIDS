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

namespace firewall {

struct firewall_intf_stats {
    std::string ifname;
    uint64_t n_rx;
    uint64_t n_deny;
    uint64_t n_allowed;
    uint64_t n_events;

    explicit firewall_intf_stats() :
                    ifname(""),
                    n_rx(0),
                    n_deny(0),
                    n_allowed(0),
                    n_events(0)
    { }
    ~firewall_intf_stats() { }
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

        void inc_n_rx(const std::string ifname);
        void inc_n_deny(const std::string ifname);
        void inc_n_allowed(const std::string ifname);
        void inc_n_events(const std::string ifname);

        firewall_pkt_stats(const firewall_pkt_stats &) = delete;
        const firewall_pkt_stats &operator=(const firewall_pkt_stats &) = delete;
        firewall_pkt_stats(const firewall_pkt_stats &&) = delete;
        const firewall_pkt_stats &&operator=(const firewall_pkt_stats &&) = delete;

        ~firewall_pkt_stats() { }

    private:
        explicit firewall_pkt_stats() { }
        std::vector<firewall_intf_stats> stats_;
};

}

#endif
