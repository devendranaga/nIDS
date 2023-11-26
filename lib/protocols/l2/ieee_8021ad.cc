#include <ieee_8021ad.h>

namespace firewall {

const uint16_t reserved_vlan_ids[] = { 0, 4095 };

event_description
ieee8021ad_hdr::deserialize(packet &p, logger *log, bool debug)
{
    uint8_t val = 0;

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
