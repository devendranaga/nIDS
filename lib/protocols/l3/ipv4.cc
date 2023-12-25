/**
 * @brief - implements ipv4 protocol serialize and deserialize.
 * 
 * @copyright - 2023-present All rights reserved.
*/
#include <ipv4.h>
#include <ipv6.h>

namespace firewall {

protocols_types ipv4_hdr::get_protocol()
{
    //
    // IP in IP tunnel
    if (ipip)
        return static_cast<protocols_types>(ipip->protocol);

    //
    // 6 in 4 tunnel
    if (ipv6_in_ipv4)
        return static_cast<protocols_types>(ipv6_in_ipv4->nh);

    return static_cast<protocols_types>(protocol);
}

int ipv4_hdr::serialize(packet &p)
{
    uint8_t byte;
    uint16_t byte_2;
    uint8_t hdr_chksum_off = 0;

    start_off = p.off;

    //
    // version and hdr length
    byte = version << 4;
    byte |= (IPV4_HDR_NO_OPTIONS / 4);

    p.serialize(byte);

    // DSCP and ECN
    byte = dscp << 2;
    byte |= ecn;

    p.serialize(byte);

    // total len
    p.serialize(total_len);

    // IDentification
    p.serialize(identification);

    // flags
    byte = 0;
    if (reserved) {
        byte = 0x80;
    }
    if (dont_frag) {
        byte |= 0x40;
    }
    if (more_frag) {
        byte |= 0x20;
    }

    // fragmentation off
    byte |= (frag_off & 0xFF00) >> 8;
    p.serialize(byte);

    byte = (frag_off & 0x00FF);
    p.serialize(byte);

    // TTL
    p.serialize(ttl);

    // Protocol
    p.serialize(protocol);

    byte_2 = 0;

    // Header checksum
    hdr_chksum_off = p.off;
    p.serialize(byte_2);

    // Source ipv4 address
    p.serialize(src_addr);

    // Destination ipv4 address
    p.serialize(dst_addr);

    end_off = p.off;

    // Header checksum
    hdr_chksum = this->generate_checksum(p);
    p.buf[hdr_chksum_off] = (hdr_chksum & 0x00FF);
    p.buf[hdr_chksum_off + 1] = (hdr_chksum & 0xFF00) >> 8;

    return 0;
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

uint16_t ipv4_hdr::generate_checksum(packet &p)
{
    uint32_t csum = 0;
    uint32_t carry = 0;
    uint32_t i = 0;

    for (i = start_off; i < end_off; i += 2) {
        csum += (p.buf[i + 1] << 8) | p.buf[i];
    }

    carry = (csum & 0xFF0000) >> 16;
    csum = csum & 0xFFFF;
    csum += carry;

    return ~csum;
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
    //
    // total length smaller than header length
    if (total_len < hdr_len)
        return event_description::Evt_IPv4_Total_Len_Smaller_Than_Hdr_Len;

    p.deserialize(identification);
    p.deserialize(byte_1);

    reserved = !!(byte_1 & 0x80);
    //
    // IPv4 Reserved bit is set
    if (reserved != 0) {
        return event_description::Evt_IPv4_Reserved_Set;
    }
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
    //
    // TTL zero means that packet lifetime is expired.
    if (ttl == 0) {
        return event_description::Evt_IPv4_Zero_TTL;
    }

    p.deserialize(protocol);
    p.deserialize(hdr_chksum);
    p.deserialize(src_addr);
    p.deserialize(dst_addr);

    //
    // Source and Destination IPv4 addresses are same
    if (!is_src_loopback() &&
        !is_dst_loopback() &&
        (src_addr == dst_addr)) {
        return event_description::Evt_IPv4_Src_And_Dst_Addr_Same;
    }

    //
    // drop if Src IPv4 address is a broadcast address
    if (is_broadcast(src_addr)) {
        return event_description::Evt_IPv4_Src_Is_Broadcast;
    }

    //
    // drop if Src IPv4 address is a multicast address
    if (is_multicast(src_addr)) {
        return event_description::Evt_IPv4_Src_Is_Multicast;
    }

    //
    // IPv4 Src address is reserved
    if (is_reserved(src_addr)) {
        return event_description::Evt_IPv4_Src_Is_Reserved;
    }

    //
    // IPv4 Dst address is reserved
    if (is_reserved(dst_addr)) {
        return event_description::Evt_IPv4_Dst_Is_Reserved;
    }

    //
    // parse options
    if (hdr_len > IPV4_HDR_NO_OPTIONS) {
        evt_desc = opt.deserialize(p, log, hdr_len - IPV4_HDR_NO_OPTIONS, debug);
        if (evt_desc != event_description::Evt_Parse_Ok)
            return evt_desc;
    }

    if (p.remaining_len() < (int32_t)(total_len - hdr_len))
        return event_description::Evt_IPv4_Invalid_Total_Len;

    end_off = p.off;

    if (debug)
        print(log);

    if (static_cast<protocols_types>(protocol) ==
                protocols_types::Protocol_IPIP) {
        ipip = std::make_shared<ipv4_hdr>();
        if (!ipip)
            return event_description::Evt_Out_Of_Memory;

        evt_desc = ipip->deserialize(p, log, debug);
        if (evt_desc != event_description::Evt_Parse_Ok)
            return evt_desc;
    } else if (static_cast<protocols_types>(protocol) ==
                protocols_types::Protocol_IPv6_Encapsulation) {
        ipv6_in_ipv4 = std::make_shared<ipv6_hdr>();
        if (!ipv6_in_ipv4)
            return event_description::Evt_Out_Of_Memory;

        evt_desc = ipv6_in_ipv4->deserialize(p, log, debug);
        if (evt_desc != event_description::Evt_Parse_Ok)
            return evt_desc;
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
    get_ipaddr(ipaddr, ipaddr_str);
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
            case IPv4_Opt::End_Of_Options: {
                // 0 bytes in length - generally is 0
                p.off ++;
            } break;
            case IPv4_Opt::Nop: {
            } break;
            case IPv4_Opt::Timestamp: {
                ts = std::make_shared<ipv4_opt_timestamp>(copy_on_frag, cls);
                if (!ts)
                    return event_description::Evt_Unknown_Error;

                evt_desc = ts->deserialize(p, log, debug);
            } break;
            case IPv4_Opt::Router_Alert: {
                ra = std::make_shared<ipv4_opt_router_alert>(copy_on_frag, cls);
                if (!ra)
                    return event_description::Evt_Unknown_Error;

                evt_desc = ra->deserialize(p, log, debug);
            } break;
            case IPv4_Opt::Commercial_IP_Security: {
                comm_sec = std::make_shared<ipv4_opt_comm_sec>(copy_on_frag, cls);
                if (!comm_sec)
                    return event_description::Evt_Unknown_Error;

                evt_desc = comm_sec->deserialize(p, log, debug);
            } break;
            case IPv4_Opt::Strict_Source_Route: {
                ssr = std::make_shared<ipv4_opt_strict_source_route>(copy_on_frag, cls);
                if (!ssr)
                    return event_description::Evt_Unknown_Error;

                evt_desc = ssr->deserialize(p, log, debug);
            } break;
            case IPv4_Opt::Loose_Source_Route: {
                lsr = std::make_shared<ipv4_opt_loose_source_route>(copy_on_frag, cls);
                if (!lsr)
                    return event_description::Evt_Unknown_Error;

                evt_desc = lsr->deserialize(p, log, debug);
            } break;
            default:
                return event_description::Evt_IPV4_Unknown_Opt;
        }
    }
    return evt_desc;
}

event_description ipv4_opt_comm_sec::deserialize(packet &p, logger *log, bool debug)
{
    p.deserialize(len);

    p.off += len - 2; // type = 1 byte len = 1 byte

    return event_description::Evt_Parse_Ok;
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
        if (flag == IPV4_OPT_FLAG_TS_ONLY) {
            ipv4_opt_ts_data ts_data;

            p.deserialize(ts_data.ts);
            ts_list.push_back(ts_data);
            len_parsed += 4;
        } else if (flag == IPV4_OPT_FLAG_TS_AND_ADDR) {
            ipv4_opt_ts_data ts_data;

            p.deserialize(ts_data.ipaddr);
            p.deserialize(ts_data.ts);
            ts_list.push_back(ts_data);
            len_parsed += 8;
        }
    }

    return event_description::Evt_Parse_Ok;
}

event_description ipv4_opt_router_alert::deserialize(packet &p, logger *log, bool debug)
{
    p.deserialize(len);
    p.deserialize(router_alert);

    return event_description::Evt_Parse_Ok;
}

event_description ipv4_opt_strict_source_route::deserialize(packet &p, logger *log, bool debug)
{
    //
    // truncated SSR length
    if (p.remaining_len() < len_)
        return event_description::Evt_IPv4_Strict_Source_Route_Len_Truncated;

    p.deserialize(len);
    p.deserialize(pointer);
    p.deserialize(dest_addr);

    return event_description::Evt_Parse_Ok;
}

event_description ipv4_opt_loose_source_route::deserialize(packet &p, logger *log, bool debug)
{
    p.deserialize(len);
    p.deserialize(pointer);
    p.deserialize(dest_addr);

    return event_description::Evt_Parse_Ok;
}

}

