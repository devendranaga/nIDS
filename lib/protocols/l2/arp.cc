/**
 * @brief - Implements ARP serialize and deserialize.
 * 
 * @copyright - 2023-present All rights reserved. Devendra Naga.
*/
#include <eth.h>
#include <arp.h>

namespace firewall {

int arp_hdr::serialize(packet &p)
{
    return -1;
}

event_description arp_hdr::deserialize(packet &p)
{
    if (p.remaining_len() < arp_hdr_len) {
        return event_description::Evt_ARP_Hdrlen_Too_Small;
    }

    p.deserialize(hw_type);
    p.deserialize(proto_type);
    p.deserialize(hw_addr_len);
    if (hw_addr_len != ARP_HW_ADDR_LEN) {
        return event_description::Evt_ARP_HW_Addr_Len_Inval;
    }
    p.deserialize(proto_addr_len);
    if (proto_addr_len != ARP_PROTO_ADDR_LEN) {
        return event_description::Evt_ARP_Protocol_Addr_Len_Inval;
    }
    p.deserialize(operation);
    if ((operation < static_cast<uint16_t>(arp_operation::Request)) ||
        (operation > static_cast<uint16_t>(arp_operation::InArp_Reply))) {
        return event_description::Evt_ARP_Inval_Operation;
    }
    p.deserialize(sender_hw_addr);
    p.deserialize(sender_proto_addr);
    p.deserialize(target_hw_addr);
    p.deserialize(target_proto_addr);

    return event_description::Evt_Parse_Ok;
}

void arp_hdr::print(logger *log)
{

}

}
