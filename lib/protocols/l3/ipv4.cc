/**
 * @brief - implements ipv4 protocol serialize and deserialize.
 * 
 * @copyright - 2023-present All rights reserved.
*/
#include <ipv4.h>

namespace firewall {

int ipv4_hdr::serialize(packet &p)
{
    return -1;
}

event_description ipv4_hdr::deserialize(packet &p, logger *log, bool debug)
{
    uint8_t byte_1;

    //
    // check header length too small.
    if (p.remaining_len() < IPV4_HDR_NO_OPTIONS) {
        return event_description::Evt_IPV4_Hdrlen_Too_Small;
    }

    start_off = p.off;

    version = (p.buf[p.off] & 0xF0) >> 4;
    if (version != IPV4_VERSION) {
        return event_description::Evt_IPV4_Version_Invalid;
    }

    hdr_len = (p.buf[p.off] & 0x0F) * IPV4_IHL_LEN;

    p.off ++;

    //
    // header length is too small or too big.
    if (hdr_len < IPV4_HDR_NO_OPTIONS) {
        return event_description::Evt_IPV4_Hdrlen_Too_Small;
    } else if (hdr_len > IPV4_HDR_LEN_MAX) {
        return event_description::Evt_IPV4_Hdrlen_Too_Big;
    }

    p.deserialize(byte_1);

    dscp = (byte_1 & 0xFC) >> 2;
    ecn = (byte_1 & 0x03);

    p.deserialize(total_len);
    p.deserialize(identification);
    p.deserialize(byte_1);

    reserved = !!(byte_1 & 0x80);
    dont_frag = !!(byte_1 & 0x40);
    more_frag = !!(byte_1 & 0x20);

    //
    // dont_fragment and more_fragment bits
    // cannot be set to 1 at the same time.
    if (dont_frag && more_frag) {
        return event_description::Evt_IPV4_Flags_Invalid;
    }

    frag_off = (byte_1 & 0x1F) << 8;

    p.deserialize(byte_1);

    frag_off |= byte_1;

    p.deserialize(ttl);
    p.deserialize(protocol);
    p.deserialize(hdr_chksum);
    p.deserialize(src_addr);
    p.deserialize(dst_addr);

    end_off = p.off;

    if (debug) {
        print(log);
    }

    return event_description::Evt_Parse_Ok;
}

void ipv4_hdr::print(logger *log)
{
    log->verbose("IPV4: {\n");
    log->verbose("\t version: %d\n", version);
    log->verbose("\t hdr_len: %d\n", hdr_len);
    log->verbose("\t dscp: %d\n", dscp);
    log->verbose("\t ecn: %d\n", ecn);
    log->verbose("\t total_len: %d\n", total_len);
    log->verbose("\t identification: 0x%04x\n", identification);
    log->verbose("\t flags: {\n");
    log->verbose("\t\t reserved: %d\n", reserved);
    log->verbose("\t\t dont_fragment: %d\n", dont_frag);
    log->verbose("\t\t more_fragment: %d\n", more_frag);
    log->verbose("\t }\n");
    log->verbose("\t frag_off: 0x%04x\n", frag_off);
    log->verbose("\t ttl: %d\n", ttl);
    log->verbose("\t protocol: %d\n", protocol);
    log->verbose("\t hdr_checksum: 0x%04x\n", hdr_chksum);
    log->verbose("\t src_addr: %u\n", src_addr);
    log->verbose("\t dst_addr: %u\n", dst_addr);
    log->verbose("}\n");
}

}

