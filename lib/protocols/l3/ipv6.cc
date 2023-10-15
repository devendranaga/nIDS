#include <ipv6.h>

namespace firewall {

int ipv6_hdr::serialize(packet &p)
{
    return -1;
}

event_description ipv6_hdr::deserialize(packet &p, logger *log, bool debug)
{
    version = (p.buf[p.off] & 0xF0) >> 4;
    priority = ((p.buf[p.off] & 0x0F) << 4) | 
               ((p.buf[p.off + 1] & 0xF0) >> 4);
    p.off += 2;

    flow_label = ((p.buf[p.off] & 0xF0) >> 4) << 16;
    flow_label |= (p.buf[p.off + 1] << 8) |
                  (p.buf[p.off + 2]);
    p.off += 2;

    p.deserialize(payload_len);
    p.deserialize(nh);
    p.deserialize(hop_limit);
    p.deserialize(src_addr, IPV6_ADDR_LEN);
    p.deserialize(dst_addr, IPV6_ADDR_LEN);
    if (debug) {
        print(log);
    }

    return event_description::Evt_Parse_Ok;
}

void ipv6_hdr::print(logger *log)
{
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
    log->verbose("}\n");
}

}
