/**
 * @brief - Implements protocol list.
 *
 * @copyright - 2023-present. All rights reserved. Devendra Naga.
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
    Protocol_IPv6_Encapsulation = 41,
    Protocol_GREP = 47,
    // Encapsulated Security Payload
    Protocol_ESP = 50,
    Protocol_AH = 51,
    Protocol_Icmp6 = 58,
    Protocol_Max,
};

const std::string get_protocol_str(protocols_types protocol);

}

#endif

