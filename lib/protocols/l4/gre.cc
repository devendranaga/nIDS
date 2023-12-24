#include <ipv4.h>
#include <gre.h>

namespace firewall {

event_description gre_hdr::deserialize(packet &p, logger *log, bool debug)
{
    event_description evt_desc = event_description::Evt_Unknown_Error;
    uint16_t byte_val;

    //
    // short Gre header length.. skip it.
    if (p.remaining_len() < min_hdr_len_)
        return event_description::Evt_Gre_Invalid_Hdr_Len;

    p.deserialize(byte_val);

    flags.checksum_bit = !!(byte_val & 0x8000);
    flags.routing_bit = !!(byte_val & 0x4000);
    flags.key_bit = !!(byte_val & 0x2000);
    flags.seq_no = !!(byte_val & 0x1000);
    flags.ssr = !!(byte_val & 0x0800);
    flags.recursion_control = (byte_val & 0x0700) >> 8;
    flags.flags = (byte_val & 0x00F8) >> 3;
    flags.version = (byte_val & 0x0007);

    p.deserialize(byte_val);

    protocol = static_cast<Ether_Type>(byte_val);

    if (debug)
        print(log);

    if (protocol == Ether_Type::Ether_Type_IPv4) {
        ipv4_h = std::make_shared<ipv4_hdr>();
        if (!ipv4_h)
            return event_description::Evt_Out_Of_Memory;

        evt_desc = ipv4_h->deserialize(p, log, debug);
        if (evt_desc != event_description::Evt_Parse_Ok)
            return evt_desc;
    }

    return event_description::Evt_Parse_Ok;
}

}


