#ifndef __FW_ETHER_TYPES_H__
#define __FW_ETHER_TYPES_H__

#include <stdint.h>

namespace firewall {

enum class ether_type : uint16_t {
	Ether_Type_IPv4 	= 0x0800,
	Ether_Type_VLAN 	= 0x8100,
	Ether_Type_ARP 		= 0x0806,
};

}

#endif

