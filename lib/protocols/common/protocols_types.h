/**
 * @brief - Implements protocol list.
*/
#ifndef __FW_PROTOCOLS_TYPES_H__
#define __FW_PROTOCOLS_TYPES_H__

namespace firewall {

//
// Describes a list of supported protocol types.
enum class protocols_types {
    Protocol_Icmp = 1,
    Protocol_Igmp = 2,
    // Gateway-Gateway protocol
    Protocol_GGP = 3,
    // IP in IP
    Protocol_IPIP = 4,
    Protocol_Tcp = 6,
    Protocol_Udp = 17,
    Protocol_Max,
};

}

#endif

