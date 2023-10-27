/**
 * @brief - implements IEEE 802.1AE MACsec serialize and deserialize.
 * 
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
*/
#include <macsec.h>

namespace firewall {

event_description ieee8021ae_hdr::deserialize(packet &p, logger *log, bool debug)
{
    uint8_t byte;

    if (p.remaining_len() < macsec_hdr_len_min_) {
        return event_description::Evt_MACsec_Hdr_Len_Too_Small;
    }

    p.deserialize(byte);
    tci.ver = !!(byte & 0x80);
    tci.es = !!(byte & 0x40);
    tci.sc = !!(byte & 0x20);
    tci.scb = !!(byte & 0x10);
    tci.e = !!(byte & 0x08);
    tci.c = !!(byte & 0x04);
    tci.an = byte & 0x03;

    //
    // ES and SC are exclusive and cannot be set at same time
    // same apply to SC and sCB.
    if (tci.sc && tci.scb) {
        return event_description::Evt_MACsec_TCI_SC_SCB_Set;
    }
    if (tci.es && tci.sc) {
        return event_description::Evt_MACsec_TCI_ES_SC_Set;
    }
    p.deserialize(short_len);
    p.deserialize(pkt_number);
    if (tci.sc) {
        p.deserialize(sci.mac);
        p.deserialize(sci.port_id);
    }
    data_len = p.remaining_len() - MACSEC_ICV_LEN;
    data = (uint8_t *)calloc(1, data_len);
    if (!data) {
        return event_description::Evt_Unknown_Error;
    }
    p.deserialize(data, data_len);
    p.deserialize(icv, MACSEC_ICV_LEN);

    if (debug)
        print(log);

    return event_description::Evt_Parse_Ok;
}

}
