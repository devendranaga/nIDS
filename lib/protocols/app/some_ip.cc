#include <some_ip.h>

namespace firewall {

event_description someip_hdr::deserialize(packet &p, logger *log, bool debug)
{
    while (p.off < static_cast<uint32_t>(p.remaining_len())) {
        someip_pdu pdu;
        uint8_t byte1;
        uint32_t len_start_off;

        if (p.remaining_len() < pdu.get_hdr_len())
            return event_description::Evt_SomeIP_Hdr_Len_Too_Small;

        p.deserialize(pdu.service_id);
        p.deserialize(pdu.method_id);

        len_start_off = p.off;

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
        pdu.payload_len = p.off - len_start_off;

        if (pdu.payload_len > 0) {
            pdu.payload = (uint8_t *)calloc(1, pdu.payload_len);
            if (!pdu.payload) {
                return event_description::Evt_Out_Of_Memory;
            }
            p.deserialize(pdu.payload, pdu.payload_len);
        }

        someip_pdu_list_.push_back(pdu);
    }
    return event_description::Evt_Parse_Ok;
}

}
