#ifndef __FW_PACKET_STATS_H__
#define __FW_PACKET_STATS_H__

#include <stdint.h>

namespace firewall {

/**
 * @brief - Ethernet statistics
*/
struct firewall_pkt_stats_eth {
    uint64_t rx_inval_dst;
    uint64_t rx_inval_src;
    uint64_t rx_inval_ethertype;

    explicit firewall_pkt_stats_eth() : rx_inval_dst(0),
                                        rx_inval_src(0),
                                        rx_inval_ethertype(0)
    { }
    ~firewall_pkt_stats_eth() { }

    void inc_rx_inval_dst() { rx_inval_dst ++; }
    void inc_rx_inval_src() { rx_inval_src ++; }
    void inc_rx_inval_ethertype() { rx_inval_ethertype ++; }
};

/**
 * @brief - defines packet statistics
*/
struct firewall_pkt_stats {
    uint64_t rx_count;

    firewall_pkt_stats_eth eth_stats;

    explicit firewall_pkt_stats() : rx_count(0)
    { }
    ~firewall_pkt_stats() { }

    void inc_rx_count() { rx_count ++; }
};

}

#endif
