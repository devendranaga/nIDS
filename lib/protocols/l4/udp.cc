/**
 * @brief - implements udp serialize and deserialize.
 * 
 * @copyright - 2023-present. All rights reserved. Devendra Naga.
*/
#include <arpa/inet.h>
#include <udp.h>
#include <protocols_types.h>

namespace firewall {

int udp_hdr::serialize(packet &p)
{
    return -1;
}

event_description udp_hdr::deserialize(packet &p, logger *log, bool debug)
{
    //
    // drop shorter udp packets
    if (p.remaining_len() < udp_hdrlen_)
        return event_description::Evt_Udp_Len_Too_Short;

    start_off = p.off;

    p.deserialize(src_port);
    p.deserialize(dst_port);
    p.deserialize(length);
    p.deserialize(checksum);

    end_off = p.off + p.remaining_len();

    if (src_port == 0)
        return event_description::Evt_Udp_Src_Port_Invalid;

    if (dst_port == 0)
        return event_description::Evt_Udp_Dst_Port_Invalid;

    //
    // UDP message length and the remaining frame data length are not matching
    // given msg length in the header is bigger than the remaining frame length.
    if (p.remaining_len() < (length - udp_hdrlen_))
        return event_description::Evt_Udp_Hdr_Msg_Len_Too_Big;

    if (debug)
        print(log);

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

int udp_hdr::validate_checksum(packet &p,
                               uint32_t src_ipaddr, uint32_t dst_ipaddr,
                               uint16_t protocol)
{
    uint32_t checksum = 0;
    uint32_t carry = 0;
    uint32_t i = 0;
    uint16_t *ptr;

    ipv4_pseudo_hdr psh;

    std::memset(&psh, 0, sizeof(psh));

    psh.src_ipaddr = src_ipaddr;
    psh.dst_ipaddr = dst_ipaddr;
    psh.zero = 0;
    psh.protocol = static_cast<uint8_t>(protocols_types::Protocol_Udp);
    psh.len = htons(length);

    ptr = psh.arr;

    //src_ipaddr = ntohl(src_ipaddr);
    //dst_ipaddr = ntohl(dst_ipaddr);
    //protocol = ntohs(protocol);

    checksum += ptr[0];
    checksum += ptr[1];
    checksum += ptr[2];
    checksum += ptr[3];
    checksum += ptr[4];
    checksum += ptr[5];

    uint32_t len = p.buf_len;

    if (p.buf_len % 2 != 0) {
        len = p.buf_len - 1;
    }

    for (i = start_off; i < len; i ++) {
        checksum += (p.buf[i + 1] << 8) + p.buf[i];
    }

    if (p.buf_len % 2 != 0) {
        checksum += (p.buf[len] << 8);
    }

    carry = (checksum & 0xFFFF0000) >> 16;
    checksum = ((checksum & 0xFFFF) + carry);

    return ~checksum;
}

}
