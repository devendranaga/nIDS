#ifndef __FW_EVENT_DEF_H__
#define __FW_EVENT_DEF_H__

#include <stdint.h>
#include <packet.h>

namespace firewall {

// constants set by the firewall.
// these are internally detected by the firewall without having to
// give any rules.
//
// if the firewall detects the corresponding events, it will simply
// block the frame and event with the below corresponding rule and the
// event description.
enum class rule_ids {
    Rule_Id_Unsupported_Ethertype       = 0x00000001,
    Rule_Id_ARP_Hdrlen_Too_Small        = 0x00000002,
    Rule_Id_ARP_HW_Addr_Len_Inval       = 0x00000003,
    Rule_Id_ARP_Protocol_Addr_Len_Inval = 0x00000004,
};

//
// event description contains exactly what type of event has occured
enum class event_description {
    Evt_Eth_Src_Mac_Matched,
    Evt_Eth_Dst_Mac_Matched,
    Evt_Eth_Ethertype_Matched,
    Evt_ARP_Hdrlen_Too_Small,
    Evt_ARP_HW_Addr_Len_Inval,
    Evt_ARP_Protocol_Addr_Len_Inval,
    Evt_IPV4_Hdrlen_Too_Small,
    Evt_Unknown_Error,
    Evt_Parse_Ok,
};

enum class event_type {
    Evt_Allow,
    Evt_Deny,
    Evt_Alert,
};

struct event {
    event_type evt_type;
    event_description evt_details;
    uint32_t rule_id;
    uint8_t src_mac[6];
    uint8_t dst_mac[6];
    uint16_t ethertype;
    uint32_t protocol;
    uint32_t src_port;
    uint32_t dst_port;
    uint32_t pkt_len;

    explicit event() : evt_type(event_type::Evt_Deny),
                       evt_details(event_description::Evt_Unknown_Error),
                       rule_id(0),
                       ethertype(0),
                       protocol(0),
                       src_port(0),
                       dst_port(0),
                       pkt_len(0)
    {
        memset(src_mac, 0, sizeof(src_mac));
        memset(dst_mac, 0, sizeof(dst_mac));
    }
    ~event() { }

    void create(uint32_t rule_id,
                event_type evt_type,
                event_description evt_details,
                const packet &pkt);
};

}

#endif
