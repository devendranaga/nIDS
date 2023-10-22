/**
 * @brief - Implements TCP serialize and deserialize.
 * 
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
*/

#include <tcp.h>

namespace firewall {

int tcp_hdr::serialize(packet &p)
{
    return -1;
}

event_description tcp_hdr::deserialize(packet &p, logger *log, bool debug)
{
    uint8_t flags = 0;

    p.deserialize(src_port);
    p.deserialize(dst_port);
    p.deserialize(seq_no);
    p.deserialize(ack_no);
    p.deserialize(hdr_len);
    p.deserialize(flags);

    reserved = (hdr_len & 0x0E) >> 1;
    ecn = (hdr_len & 0x01);
    hdr_len = (hdr_len & 0x0F) >> 4;
    cwr = !!(flags & 0x80);
    ecn_echo = !!(flags & 0x40);
    urg = !!(flags & 0x20);
    ack = !!(flags & 0x10);
    psh = !!(flags & 0x08);
    rst = !!(flags & 0x04);
    syn = !!(flags & 0x02);
    fin = !!(flags & 0x01);

    p.deserialize(window);
    p.deserialize(checksum);
    p.deserialize(urg_ptr);

    return event_description::Evt_Parse_Ok;
}

}
