/**
 * @brief - defines list of supported ethertypes.
 * 
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
*/
#ifndef __FW_ETHER_TYPES_H__
#define __FW_ETHER_TYPES_H__

#include <stdint.h>

namespace firewall {

/**
 * @brief - defines ethertypes.
*/
enum class Ether_Type : uint16_t {
    Ether_Type_IPv4      = 0x0800,
    Ether_Type_VLAN      = 0x8100,
    Ether_Type_ARP       = 0x0806,
    Ether_Type_IPv6      = 0x86DD,
    Ether_Type_IEEE8021X = 0x888E,
    Ether_Type_8021_AD   = 0x88A8,
    Ether_Type_MACsec    = 0x88E5,
    Ether_Type_Unknown   = 0xFFFF,
};

}

#endif

