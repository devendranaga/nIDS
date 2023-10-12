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
