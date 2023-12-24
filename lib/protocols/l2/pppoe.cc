/**
 * @brief - Implements PPPOE serialize and deserialize.
 *
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
*/
#include <pppoe.h>

namespace firewall {

event_description pppoe_link_control_protocol::deserialize(packet &p, logger *log, bool debug)
{
    int final_len = 0;

    p.deserialize(code);
    p.deserialize(id);
    p.deserialize(len);
    p.deserialize(magic_no);

    final_len = len - (sizeof(code) + sizeof(id) + sizeof(len) + sizeof(magic_no));

    p.deserialize(data, final_len);

    return event_description::Evt_Parse_Ok;
}

event_description pppoe_hdr::deserialize(packet &p, logger *log, bool debug)
{
    event_description evt_desc = event_description::Evt_Unknown_Error;
    uint8_t byte_val;

    p.deserialize(byte_val);
    version = (byte_val & 0xF0) >> 4;
    type = (byte_val & 0x0F);

    p.deserialize(code);
    p.deserialize(session_id);
    p.deserialize(payload_len);
    p.deserialize(protocol);

    if (protocol == PPPOE_LINK_CONTROL_PROTOCOL) {
        evt_desc = opt.lcp.deserialize(p, log, debug);
        if (evt_desc != event_description::Evt_Parse_Ok)
            return evt_desc;
    }

    if (debug)
        print(log);

    return event_description::Evt_Parse_Ok;
}

/**
 * @brief - convert from PPPOE types to Ethertype.
*/
Ether_Type pppoe_hdr::get_ethertype()
{
    if (protocol == PPPOE_PROTOCOL_IPV6)
        return Ether_Type::Ether_Type_IPv6;

    return Ether_Type::Ether_Type_Unknown;
}

}

