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

event_description arp_hdr::deserialize(packet &p, logger *log, bool debug)
{
    if (p.remaining_len() < arp_hdr_len_) {
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

    if (debug) {
        print(log);
    }

    return event_description::Evt_Parse_Ok;
}

void arp_hdr::print(logger *log)
{
    log->verbose("ARP: {\n");
    log->verbose("\t hw_type: %d\n", hw_type);
    log->verbose("\t proto_type: %d\n", proto_type);
    log->verbose("\t hw_addr_len: %d\n", hw_addr_len);
    log->verbose("\t proto_addr_len: %d\n", proto_addr_len);
    log->verbose("\t operation: %d\n", operation);
    log->verbose("\t sender_hw_addr: %02x:%02x:%02x:%02x:%02x:%02x\n",
                    sender_hw_addr[0], sender_hw_addr[1],
                    sender_hw_addr[2], sender_hw_addr[3],
                    sender_hw_addr[4], sender_hw_addr[5]);
    log->verbose("\t sender_proto_addr: %u\n", sender_proto_addr);
    log->verbose("\t target_hw_addr: %02x:%02x:%02x:%02x:%02x:%02x\n",
                    target_hw_addr[0], target_hw_addr[1],
                    target_hw_addr[2], target_hw_addr[3],
                    target_hw_addr[4], target_hw_addr[5]);
    log->verbose("\t sender_proto_addr: %u\n", target_proto_addr);
    log->verbose("}\n");
}

}
