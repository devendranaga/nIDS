#ifndef __FW_PROTOCOLS_ETH_H__
#define __FW_PROTOCOLS_ETH_H__

#include <stdint.h>
#include <common.h>
#include <ether_types.h>
#include <logger.h>
#include <packet.h>

namespace firewall {

struct eth_hdr {
	uint8_t src_mac[FW_MACADDR_LEN];
	uint8_t dst_mac[FW_MACADDR_LEN];
	uint16_t ethertype;

	inline bool has_ethertype_ipv4()
	{
		return (ether_type)ethertype == ether_type::Ether_Type_IPv4;
	}

	void serialize(packet &p);
	void deserialize(packet &p);
	void print(logger *log);
};

};

#endif


