#include <vrrp.h>

namespace firewall {

event_description vrrp_v2_hdr::deserialize(packet &p, logger *log, bool debug)
{
    p.deserialize(virtual_router_id);
    p.deserialize(priority);
    p.deserialize(addr_count);
    p.deserialize(auth_type);
    p.deserialize(adver_int);
    p.deserialize(checksum);
    p.deserialize(ipaddr);

    return event_description::Evt_Parse_Ok;
}

event_description vrrp_hdr::deserialize(packet &p, logger *log, bool debug)
{
    event_description evt_desc = event_description::Evt_Unknown_Error;
    uint8_t byte_val;

    p.deserialize(byte_val);

    version = (byte_val & 0xF0) >> 4;
    pkt_type = (byte_val & 0x0F);

    if (version == 2) {
        evt_desc = opt.v2_hdr.deserialize(p, log, debug);
        if (evt_desc != event_description::Evt_Parse_Ok)
            return evt_desc;
    }

    if (debug)
        print(log);

    return event_description::Evt_Parse_Ok;
}

}
