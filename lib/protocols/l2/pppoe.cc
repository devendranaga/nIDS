/**
 * @brief - Implements PPPOE serialize and deserialize.
 *
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
*/
#include <pppoe.h>

namespace firewall {

event_description pppoe_hdr::deserialize(packet &p, logger *log, bool debug)
{
    uint8_t byte_val;

    p.deserialize(byte_val);
    version = (byte_val & 0xF0) >> 4;
    type = (byte_val & 0x0F);

    p.deserialize(code);
    p.deserialize(session_id);
    p.deserialize(payload_len);
    p.deserialize(protocol);

    return event_description::Evt_Parse_Ok;
}

}

