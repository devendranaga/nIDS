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

bool ipv4_hdr::validate_checksum(packet &p)
{
    uint32_t csum = 0;
    uint32_t carry = 0;
    uint32_t i = 0;

    //
    // every two bytes are added until the end of the frame
    for (i = start_off; i < end_off; i += 2) {
        csum += (p.buf[i + 1] << 8) | p.buf[i];
    }

    // if over 0xFFFF, get the carry in the 3rd byte
    carry = (csum & 0xFF0000) >> 16;
    // find the resulting checksum without carry
    csum = csum & 0xFFFF;

    // the sum of checksum and carry now must be 0xFFFF
    // this means that the checksum is valid.
    if (csum + carry == 0xFFFF) {
        return true;
    }

    return false;
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

    //
    // validate the checksum
    if (validate_checksum(p) == false) {
        return event_description::Evt_IPV4_Hdr_Chksum_Invalid;
    }

    return event_description::Evt_Parse_Ok;
}

void ipv4_hdr::print(logger *log)
{
    std::string ipaddr_str;

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

    get_ipaddr_str(src_addr, ipaddr_str);
    log->verbose("\t src_addr: %u (%s)\n", src_addr, ipaddr_str.c_str());

    get_ipaddr_str(dst_addr, ipaddr_str);
    log->verbose("\t dst_addr: %u (%s)\n", dst_addr, ipaddr_str.c_str());
    log->verbose("}\n");
}

void ipv4_hdr::get_ipaddr_str(uint32_t ipaddr, std::string &ipaddr_str)
{
    char ip[32] = {0};

    snprintf(ip, sizeof(ip), "%d.%d.%d.%d",
                            (ipaddr & 0x000000FF),
                            (ipaddr & 0x0000FF00) >> 8,
                            (ipaddr & 0x00FF0000) >> 16,
                            (ipaddr & 0xFF000000) >> 24);

    ipaddr_str = ip;
}

}

