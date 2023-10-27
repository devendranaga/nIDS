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
    event_description evt_desc;
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

    //
    // parse options
    if (hdr_len > IPV4_HDR_NO_OPTIONS) {
        evt_desc = opt.deserialize(p, log, hdr_len - IPV4_HDR_NO_OPTIONS, debug);
        if (evt_desc != event_description::Evt_Parse_Ok) {
            return evt_desc;
        }
    }

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
#if defined(FW_ENABLE_DEBUG)
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
    log->verbose("\t options: {\n");
    opt.print(log);
    log->verbose("\t }\n");
    log->verbose("}\n");
#endif
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

event_description ipv4_options::deserialize(packet &p, logger *log, uint32_t opt_len, bool debug)
{
    event_description evt_desc = event_description::Evt_IPV4_Unknown_Opt;
    uint32_t copy_on_frag;
    uint32_t cls;
    IPv4_Opt opt;
    uint8_t val = 0;
    uint32_t len = opt_len + p.off;

    while (p.off < len) {
        p.deserialize(val);
        copy_on_frag = !!(val & 0x80);
        cls = (val & 0x60) >> 5;
        opt = static_cast<IPv4_Opt>(val & 0x1F);

        switch (opt) {
            case IPv4_Opt::Nop: {
            } break;
            case IPv4_Opt::Timestamp: {
                ts = std::make_shared<ipv4_opt_timestamp>(copy_on_frag, cls);
                if (!ts) {
                    return event_description::Evt_Unknown_Error;
                }
                evt_desc = ts->deserialize(p, log, debug);
            } break;
            case IPv4_Opt::Router_Alert: {
                ra = std::make_shared<ipv4_opt_router_alert>(copy_on_frag, cls);
                if (!ra) {
                    return event_description::Evt_Unknown_Error;
                }
                evt_desc = ra->deserialize(p, log, debug);
            } break;
            default:
                evt_desc = event_description::Evt_IPV4_Unknown_Opt;
            break;
        }
    }
    return evt_desc;
}

event_description ipv4_opt_timestamp::deserialize(packet &p, logger *log, bool debug)
{
    uint8_t byte;
    uint32_t len_parsed = 4;

    p.deserialize(len);
    p.deserialize(ptr);
    p.deserialize(byte);
    overflow = (byte & 0xF0) >> 4;
    flag = (byte & 0x0F);

    while (len_parsed < len) {
        if (flag == 0) {
            ipv4_opt_ts_data ts_data;

            p.deserialize(ts_data.ts);
            ts_list.push_back(ts_data);
        }

        len_parsed += 4;
    }

    return event_description::Evt_Parse_Ok;
}

event_description ipv4_opt_router_alert::deserialize(packet &p, logger *log, bool debug)
{
    p.deserialize(len);
    p.deserialize(router_alert);

    return event_description::Evt_Parse_Ok;
}

}

