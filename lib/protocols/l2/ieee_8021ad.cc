#include <ieee_8021ad.h>

namespace firewall {

const uint16_t reserved_vlan_ids[] = { 0, 4095 };

event_description
ieee8021ad_hdr::deserialize(packet &p, logger *log, bool debug)
{
    uint8_t val = 0;

    //
    // drop if header length is too short
    if (p.remaining_len() < len_)
        return event_description::Evt_8021AD_INVAL_Hdr_Len;

    p.deserialize(val);

    pri = (val & 0xE0) >> 5;
    dei = !!(val & 0x10);

    vid = (val & 0x0F) << 8;

    p.deserialize(val);

    vid |= val;

    p.deserialize(ethertype);

    if (debug)
        print(log);

    return event_description::Evt_Parse_Ok;
}

}
