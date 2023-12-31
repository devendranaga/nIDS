/**
 * @brief - implements ethernet header frame serialize and deserialize.
 *
 * @copyright 2023-present All rights reserved. Devendra Naga.
*/
#ifndef __FW_PROTOCOLS_ETH_H__
#define __FW_PROTOCOLS_ETH_H__

#include <stdint.h>
#include <string.h>
#include <common.h>
#include <ether_types.h>
#include <logger.h>
#include <packet.h>
#include <event_def.h>

namespace firewall {

/**
 * @brief - Implements ethernet header.
*/
struct eth_hdr {
    uint8_t src_mac[FW_MACADDR_LEN];
    uint8_t dst_mac[FW_MACADDR_LEN];
    uint16_t ethertype;

    inline bool has_ethertype_ipv4() const
    {
        return (Ether_Type)ethertype == Ether_Type::Ether_Type_IPv4;
    }

    inline bool has_ethertype_vlan() const
    {
        return (Ether_Type)ethertype == Ether_Type::Ether_Type_VLAN;
    }

    inline bool has_ethertype_8021ad() const
    {
        return (Ether_Type)ethertype == Ether_Type::Ether_Type_8021_AD;
    }

    inline bool has_ethertype_arp() const
    {
        return (Ether_Type)ethertype == Ether_Type::Ether_Type_ARP;
    }

    inline bool has_ethertype_ipv6() const
    {
        return (Ether_Type)ethertype == Ether_Type::Ether_Type_IPv6;
    }

    //
    // bit 1 of the first byte if set is locally adminsterd
    inline bool is_locally_administered(uint8_t *mac) const
    {
        return !!(mac[0] & 0x02);
    }

    //
    // bit 0 of the first byte if set is multicast
    inline bool is_multicast(uint8_t *mac) const
    {
        return !!(mac[0] & 0x01);
    }

    Ether_Type get_ethertype() const
    {
        return (Ether_Type)ethertype;
    }

    void serialize(packet &p);
    event_description deserialize(packet &p, logger *log, bool debug = false);

    inline bool is_zero_src_mac() const
    {
        const uint8_t zmac[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        return memcmp(src_mac, zmac, sizeof(src_mac));
    }

    inline bool is_broadcast_dst_mac() const
    {
        const uint8_t bmac[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
        return memcmp(dst_mac, bmac, sizeof(dst_mac));
    }

    /**
     * @brief - Get ethernet header length.
     *
     * @return ethernet header length.
     */
    inline uint16_t get_hdr_len() const { return eth_hdr_len_; }

    private:
        void print(logger *log);
        const uint16_t eth_hdr_len_ = 14;
};

};

#endif


