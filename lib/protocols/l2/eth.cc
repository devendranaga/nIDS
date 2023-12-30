/**
 * @brief - implements ethernet serialize and deserialize.
 *
 * @copyright - 2023-present. All rights reserved. Devendra Naga.
*/
#include <eth.h>
#include <rule_parser.h>

namespace firewall {

void eth_hdr::serialize(packet &p)
{
    p.serialize(src_mac);
    p.serialize(dst_mac);
    p.serialize(ethertype);
}

event_description eth_hdr::deserialize(packet &p, logger *log, bool debug)
{
    //
    // if packet is truncated, flag it
    if (p.remaining_len() < eth_hdr_len_)
        return event_description::Evt_Eth_Hdrlen_Too_Small;

    p.deserialize(src_mac);
    p.deserialize(dst_mac);
    p.deserialize(ethertype);

    if (debug)
        print(log);

    return event_description::Evt_Parse_Ok;
}

void eth_hdr::print(logger *log)
{
#if defined(FW_ENABLE_DEBUG)
    log->verbose("eth_hdr: {\n");
    log->verbose("\tsrc_mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
                    src_mac[0], src_mac[1],
                    src_mac[2], src_mac[3],
                    src_mac[4], src_mac[5]);
    log->verbose("\tdst_mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
                    dst_mac[0], dst_mac[1],
                    dst_mac[2], dst_mac[3],
                    dst_mac[4], dst_mac[5]);
    log->verbose("\tethertype: %04x\n", ethertype);
    log->verbose("}\n");
#endif
}

}


