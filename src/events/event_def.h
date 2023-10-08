#ifndef __FW_EVENT_DEF_H__
#define __FW_EVENT_DEF_H__

#include <stdint.h>
#include <packet.h>

namespace firewall {

enum class event_description {
    Evt_Eth_Src_Mac_Matched,
    Evt_Eth_Dst_Mac_Matched,
    Evt_Eth_Ethertype_Matched,
    Evt_Unknown_Error,
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
