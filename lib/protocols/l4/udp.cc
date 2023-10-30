/**
 * @brief - implements udp serialize and deserialize.
 * 
 * @copyright - 2023-present. All rights reserved. Devendra Naga.
*/
#include <udp.h>

namespace firewall {

int udp_hdr::serialize(packet &p)
{
    return -1;
}

event_description udp_hdr::deserialize(packet &p, logger *log, bool debug)
{
    if (p.remaining_len() < udp_hdrlen_) {
        return event_description::Evt_Udp_Len_Too_Short;
    }

    p.deserialize(src_port);
    p.deserialize(dst_port);
    p.deserialize(length);
    p.deserialize(checksum);

    if (src_port == 0) {
        return event_description::Evt_Udp_Src_Port_Invalid;
    }

    if (dst_port == 0) {
        return event_description::Evt_Udp_Dst_Port_Invalid;
    }

    //
    // UDP message length and the remaining frame data length are not matching
    // given msg length in the header is bigger than the remaining frame length.
    if (p.remaining_len() < length) {
        return event_description::Evt_Udp_Hdr_Msg_Len_Too_Big;
    }

    if (debug) {
        print(log);
    }

    return event_description::Evt_Parse_Ok;
}

void udp_hdr::print(logger *log)
{
#if defined(FW_ENABLE_DEBUG)
    log->verbose("UDP: {\n");
    log->verbose("\t src_port: %d\n", src_port);
    log->verbose("\t dst_port: %d\n", dst_port);
    log->verbose("\t length: %d\n", length);
    log->verbose("\t checksum: 0x%04x\n", checksum);
    log->verbose("}\n");
#endif
}

}
