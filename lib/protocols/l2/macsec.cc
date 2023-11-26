/**
 * @brief - implements IEEE 802.1AE MACsec serialize and deserialize.
 * 
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
*/
#include <macsec.h>

namespace firewall {

int ieee8021ae_hdr::serialize(packet &p)
{
    uint8_t byte = 0;

    byte |= tci.ver << 7;
    byte |= tci.es << 6;
    byte |= tci.sc << 5;
    byte |= tci.scb << 4;
    byte |= tci.e << 3;
    byte |= tci.c << 2;
    byte |= tci.an;

    p.serialize(byte);

    p.serialize(short_len);
    p.serialize(pkt_number);
    if (tci.sc) {
        p.serialize(sci.mac);
        p.serialize(sci.port_id);
    }

    if (data) {
        p.serialize(data, data_len);
    }
    p.serialize(icv, MACSEC_ICV_LEN);

    return 0;
}

event_description ieee8021ae_hdr::deserialize(packet &p, logger *log, bool debug)
{
    uint8_t byte;

    //
    // drop the shorter frame
    if (p.remaining_len() < macsec_hdr_len_min_)
        return event_description::Evt_MACsec_Hdr_Len_Too_Small;

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
    if (tci.sc && tci.scb)
        return event_description::Evt_MACsec_TCI_SC_SCB_Set;

    if (tci.es && tci.sc)
        return event_description::Evt_MACsec_TCI_ES_SC_Set;

    p.deserialize(short_len);
    p.deserialize(pkt_number);
    if (tci.sc) {
        p.deserialize(sci.mac);
        p.deserialize(sci.port_id);
    }

    uint32_t icv_off = p.buf_len - MACSEC_ICV_LEN;
    std::memcpy(icv, &p.buf[icv_off], MACSEC_ICV_LEN);

    //
    // we will know ethertype in cleartext if the frame is only authenticated
    //
    // so we can still parse the rest of the content
    if (is_an_authenticated_frame()) {
        p.deserialize(ethertype);

        //
        // Ignore the ICV length
        p.buf_len -= MACSEC_ICV_LEN;
    } else {
        data_len = p.remaining_len() - MACSEC_ICV_LEN;
        data = (uint8_t *)calloc(1, data_len);
        if (!data) {
            return event_description::Evt_Unknown_Error;
        }
        p.deserialize(data, data_len);
    }

    if (debug)
        print(log);

    return event_description::Evt_Parse_Ok;
}

}
