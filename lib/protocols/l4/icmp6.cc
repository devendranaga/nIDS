/**
 * @brief - implements icmp6 serialize and deserialize.
 * 
 * @copyright - 2023-present. All rights reserved. Devendra Naga.
*/
#include <icmp6.h>

namespace firewall {

int icmp6_hdr::serialize(packet &p)
{
    return -1;
}

event_description icmp6_hdr::deserialize(packet &p, logger *log, bool debug)
{
    p.deserialize(type);
    if ((type < static_cast<uint8_t>(icmp6_types::Icmp6_Type_Router_Advertisement)) ||
        (type >= static_cast<uint8_t>(icmp6_types::Icmp6_Type_Max))) {
        return event_description::Evt_Icmp6_Icmp6_Type_Unsupported;
    }

    p.deserialize(code);
    p.deserialize(checksum);
    p.deserialize(cur_hoplimit);

    if (debug) {
        print(log);
    }

    return event_description::Evt_Parse_Ok;
}

void icmp6_hdr::print(logger *log)
{
#if defined(FW_ENABLE_DEBUG)
    log->verbose("ICMP6: {\n");
    log->verbose("\t type: %d\n", type);
    log->verbose("\t code: %d\n", code);
    log->verbose("\t checksum: 0x%04x\n", checksum);
    log->verbose("\t cur_hoplimit: %d\n", cur_hoplimit);
    log->verbose("}\n");
#endif
}

}
