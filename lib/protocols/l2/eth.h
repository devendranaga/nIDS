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

namespace firewall {

/**
 * @brief - Implements ethernet header.
*/
struct eth_hdr {
	uint8_t src_mac[FW_MACADDR_LEN];
	uint8_t dst_mac[FW_MACADDR_LEN];
	uint16_t ethertype;

	inline bool has_ethertype_ipv4()
	{
		return (ether_type)ethertype == ether_type::Ether_Type_IPv4;
	}

	inline bool has_ethertype_vlan()
	{
		return (ether_type)ethertype == ether_type::Ether_Type_VLAN;
	}

	inline bool has_ethertype_arp()
	{
		return (ether_type)ethertype == ether_type::Ether_Type_ARP;
	}

	ether_type get_ethertype()
	{
		return (ether_type)ethertype;
	}

	void serialize(packet &p);
	void deserialize(packet &p, logger *log, bool debug = false);

	bool is_zero_src_mac()
	{
		uint8_t zmac[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
		return memcmp(src_mac, zmac, sizeof(src_mac));
	}

	bool is_broadcast_dst_mac()
	{
		uint8_t bmac[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
		return memcmp(dst_mac, bmac, sizeof(dst_mac));
	}

	private:
		void print(logger *log);
};

};

#endif


