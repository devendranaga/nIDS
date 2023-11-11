/**
 * @brief - Implements SOME/IP serialize and deserialize.
 * 
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
*/
#include <some_ip.h>

namespace firewall {

event_description someip_hdr::deserialize(packet &p, logger *log, bool debug)
{
    while (p.off < p.buf_len) {
        someip_pdu pdu;
        uint8_t byte1;

        //
        // Malformed or short SOME/IP header
        if (p.remaining_len() < pdu.get_hdr_len())
            return event_description::Evt_SomeIP_Hdr_Len_Too_Small;

        p.deserialize(pdu.service_id);
        p.deserialize(pdu.method_id);

        p.deserialize(pdu.length);
        p.deserialize(pdu.client_id);
        p.deserialize(pdu.session_id);
        p.deserialize(pdu.version);
        p.deserialize(pdu.interface_version);

        p.deserialize(byte1);
        if (!!(byte1 & 0x40)) {
            pdu.msg_type_ack = 1;
        }
        if (!!(byte1 & 0x20)) {
            pdu.msg_type_tp = 1;
        }
        pdu.msg_type = byte1 & 0x1F;
        p.deserialize(pdu.return_code);
        pdu.payload_len = pdu.length - (sizeof(pdu.service_id) + sizeof(pdu.method_id) + sizeof(pdu.length));

        if (pdu.payload_len > 0) {
            p.deserialize(pdu.payload, pdu.payload_len);
        }

        someip_pdu_list_.emplace_back(pdu);
    }

    if (debug)
        print(log);

    return event_description::Evt_Parse_Ok;
}

}
