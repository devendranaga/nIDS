/**
 * @brief - Implements protocols_types.
 *
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
*/
#include <string>
#include <protocols_types.h>

namespace firewall {

static const struct {
    protocols_types type;
    std::string str;
} protocols_types_map[] = {
    {protocols_types::Protocol_Icmp, "ICMP"},
    {protocols_types::Protocol_Igmp, "IGMP"},
    {protocols_types::Protocol_IPIP, "IPIP"},
    {protocols_types::Protocol_Tcp, "TCP"},
    {protocols_types::Protocol_Udp, "UDP"},
    {protocols_types::Protocol_GREP, "GRE"},
    {protocols_types::Protocol_ESP, "IPsec-ESP"},
    {protocols_types::Protocol_AH, "IPsec-AH"},
    {protocols_types::Protocol_Icmp6, "ICMP6"},
    {protocols_types::Protocol_VRRP, "VRRP"},
};

const std::string get_protocol_str(protocols_types protocol)
{
    for (auto it : protocols_types_map) {
        if (it.type == protocol)
            return it.str;
    }

    return "Unknown";
}

}
