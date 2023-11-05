/**
 * @brief - implements IPv6 serialize and deserialize.
 *
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
 */
#include <ipv6.h>

namespace firewall {

int ipv6_hdr::serialize(packet &p)
{
    return -1;
}

event_description ipv6_hdr::deserialize(packet &p, logger *log, bool debug)
{
    event_description evt_desc;

    //
    // check if the ipv6 frame is malformed / too short in length
    if (p.remaining_len() < hdrlen_) {
        return event_description::Evt_IPV6_Hdrlen_Too_Small;
    }

    version = (p.buf[p.off] & 0xF0) >> 4;
    //
    // check version not 6
    if (version != IPV6_VERSION) {
        return event_description::Evt_IPV6_Version_Invalid;
    }

    priority = ((p.buf[p.off] & 0x0F) << 4) | 
               ((p.buf[p.off + 1] & 0xF0) >> 4);
    p.off += 2;

    flow_label = ((p.buf[p.off] & 0xF0) >> 4) << 16;
    flow_label |= (p.buf[p.off + 1] << 8) |
                  (p.buf[p.off + 2]);
    p.off += 2;

    p.deserialize(payload_len);
    //
    // too short remaining payload compared to the ipv6->payload_len
    if (p.remaining_len() < payload_len) {
        return event_description::Evt_IPv6_Payload_Truncated;
    }

    p.deserialize(nh);
    p.deserialize(hop_limit);
    p.deserialize(src_addr, IPV6_ADDR_LEN);
    p.deserialize(dst_addr, IPV6_ADDR_LEN);

    opts = std::make_shared<ipv6_opts>();
    if (!opts)
        return event_description::Evt_Unknown_Error;

    //
    // we cannot use switch statement here because,
    // we can only parse certain nh options.
    if (static_cast<IPv6_NH_Type>(nh) == IPv6_NH_Type::AH) {
        opts->ah_hdr = std::make_shared<ipv6_ah_hdr>();
        if (!opts->ah_hdr)
            return event_description::Evt_Unknown_Error;

        evt_desc = opts->ah_hdr->deserialize(p, log, debug);
        if (evt_desc != event_description::Evt_Parse_Ok)
            return evt_desc;

        //
        // set nh to parse in the caller as IPv6_Encap.
        nh = opts->ah_hdr->nh;
    }

    if (debug) {
        print(log);
    }

    return event_description::Evt_Parse_Ok;
}

void ipv6_hdr::print(logger *log)
{
#if defined(FW_ENABLE_DEBUG)
    log->verbose("IPV6: {\n");
    log->verbose("\t version: %d\n", version);
    log->verbose("\t priority: %d\n", priority);
    log->verbose("\t flow_label: %d\n", flow_label);
    log->verbose("\t payload_len: %d\n", payload_len);
    log->verbose("\t nh: %d\n", nh);
    log->verbose("\t hop_limit: %d\n", hop_limit);
    log->verbose("\t src_addr: "
                 "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
                 "%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
                 src_addr[0], src_addr[1], src_addr[2], src_addr[3],
                 src_addr[4], src_addr[5], src_addr[6], src_addr[7],
                 src_addr[8], src_addr[9], src_addr[10], src_addr[11],
                 src_addr[12], src_addr[13], src_addr[14], src_addr[15]);
    log->verbose("\t dst_addr: "
                 "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
                 "%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
                 dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3],
                 dst_addr[4], dst_addr[5], dst_addr[6], dst_addr[7],
                 dst_addr[8], dst_addr[9], dst_addr[10], dst_addr[11],
                 dst_addr[12], dst_addr[13], dst_addr[14], dst_addr[15]);
    if (opts) {
        if (opts->ah_hdr)
            opts->ah_hdr->print(log);
    }
    log->verbose("}\n");
#endif
}

}
