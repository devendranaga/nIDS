#include <ether_types.h>

namespace firewall {

const struct {
    Ether_Type ethertype;
    const std::string str;
} ethertype_str_map[] = {
    {Ether_Type::Ether_Type_IPv4, "IPV4"},
    {Ether_Type::Ether_Type_IPv6, "IPv6"},
    {Ether_Type::Ether_Type_PPPOE, "PPPoE"},
    {Ether_Type::Ether_Type_VLAN, "VLAN"},
    {Ether_Type::Ether_Type_8021_AD, "802.1AD"},
    {Ether_Type::Ether_Type_ARP, "ARP"},
    {Ether_Type::Ether_Type_MACsec, "MACsec"},
    {Ether_Type::Ether_Type_Loop, "Loop"},
};

const std::string ethertype_to_str(Ether_Type type)
{
    for (auto it : ethertype_str_map) {
        if (type == it.ethertype)
            return it.str;
    }

    return "Unknown";
}

}
