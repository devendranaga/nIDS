/**
 * @brief - implements vlan serialize and deserialize.
 * 
 * @copyright - 2023-present All rights reserved. Devendra Naga.
*/
#include <vlan.h>

namespace firewall {

//
// reserved vlan ids
static const uint16_t reserved_vlan_ids[] = {
    0, 4095
};

int vlan_hdr::serialize(packet &p)
{
    return -1;
}

event_description vlan_hdr::deserialize(packet &p, logger *log, bool debug)
{
    if (p.remaining_len() < vlan_hdrlen_) {
        return event_description::Evt_VLAN_Hdrlen_Too_Short;
    }

    pri = (p.buf[p.off] & 0xE0) >> 5;
    dei = !!(p.buf[p.off] & 0x10) >> 4;
    vid = ((p.buf[p.off] & 0x0F) << 8) | p.buf[p.off + 1];
    for (auto i : reserved_vlan_ids) {
        if (vid == i) {
            return event_description::Evt_VLAN_Inval_VID;
        }
    }

    p.off += 2;

    p.deserialize(ethertype);
    if (debug) {
        print(log);
    }

    return event_description::Evt_Parse_Ok;
}

void vlan_hdr::print(logger *log)
{
#if defined(FW_ENABLE_DEBUG)
    log->verbose("VLAN: {\n");
    log->verbose("\t pri: %d\n", pri);
    log->verbose("\t dei: %d\n", dei);
    log->verbose("\t vid: %d\n", vid);
    log->verbose("\t ethertype: 0x%04x\n", ethertype);
    log->verbose("}\n");
#endif
}

}

