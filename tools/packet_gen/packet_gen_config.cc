/**
 * @brief - implements packet_gen configuration.
 * 
 * @copyright - 2023-present All rights reserved. Devendra Naga.
*/
#include <fstream>
#include <packet_gen_config.h>

namespace firewall {

int packet_gen_eth_config::parse(Json::Value &r)
{
    int ret;

    ret = parse_str_to_mac(r["src_mac"].asString(), src_mac);
    if (ret != 0)
        return -1;

    ret = parse_str_to_mac(r["dst_mac"].asString(), dst_mac);
    if (ret != 0)
        return -1;

    ret = parse_str_to_uint32_h(r["ethertype"].asString(), ethertype);
    if (ret != 0)
        return -1;

    pkt_len = r["pkt_len"].asUInt();
    repeat = r["repeat"].asBool();
    count = r["count"].asUInt();
    inter_pkt_gap_us = r["inter_pkt_gap_us"].asUInt();

    valid_ = true;

    return 0;
}

int packet_gen_arp_config::parse(Json::Value &r)
{
    int ret;

    spoof_mode = r["arp"]["spoof_mode"].asBool();
    arp_h.hw_type = r["arp"]["hwtype"].asUInt();
    ret = parse_str_to_uint16_h(r["arp"]["protocol_type"].asString(),
                                arp_h.proto_type);
    if (ret != 0)
        return -1;

    arp_h.hw_addr_len = r["arp"]["hw_size"].asUInt();
    arp_h.proto_addr_len = r["arp"]["protocol_size"].asUInt();
    arp_h.operation = r["arp"]["opcode"].asUInt();
    ret = parse_str_to_mac(r["arp"]["sender_mac"].asString(),
                           arp_h.sender_hw_addr);
    if (ret != 0)
        return -1;

    ret = parse_str_to_ipv4_addr(r["arp"]["sender_ipaddr"].asString(),
                                 arp_h.sender_proto_addr);
    if (ret != 0)
        return -1;

    ret = parse_str_to_mac(r["arp"]["target_mac"].asString(),
                           arp_h.target_hw_addr);
    if (ret != 0)
        return -1;

    ret = parse_str_to_ipv4_addr(r["arp"]["target_ipaddr"].asString(),
                                 arp_h.target_proto_addr);
    if (ret != 0)
        return -1;

    repeat = r["arp"]["repeat"].asBool();
    count = r["arp"]["count"].asUInt();
    inter_pkt_gap_us = r["arp"]["inter_pkt_gap_us"].asUInt();

    valid_ = true;

    return 0;
}

int packet_gen_ipv4_config::parse(Json::Value &r)
{
    int ret;

    ret = parse_str_to_mac(r["ipv4"]["src_mac"].asString(), src_mac);
    if (ret != 0)
        return -1;

    ret = parse_str_to_mac(r["ipv4"]["dest_mac"].asString(), dest_mac);
    if (ret != 0)
        return -1;

    ret = parse_str_to_uint32(r["ipv4"]["ttl"].asString(), ttl);
    if (ret != 0)
        return -1;

    ret = parse_str_to_ipv4_addr(r["ipv4"]["src_ipaddr"].asString(), src_ipaddr);
    if (ret != 0)
        return -1;

    ret = parse_str_to_ipv4_addr(r["ipv4"]["dst_ipaddr"].asString(), dest_ipaddr);
    if (ret != 0)
        return -1;

    ret = parse_str_to_uint16_h(r["ipv4"]["id"].asString(), id);
    if (ret != 0)
        return -1;

    ret = parse_str_to_uint16(r["ipv4"]["ipv4_len"].asString(), ipv4_len);
    if (ret != 0)
        return -1;

    return 0;
}

int packet_gen_pcap_replay_config::parse(Json::Value &r)
{
    filepath = r["filepath"].asString();
    intvl_us = r["intvl_us"].asUInt();
    repeat = r["repeat"].asBool();

    valid_ = true;

    return 0;
}

int packet_gen_config::parse(const std::string filepath)
{
    std::ifstream conf(filepath, std::ifstream::binary);
    Json::Value root;
 
    conf >> root;

    ifname = root["ifname"].asString();

    if (!root["eth"].isNull()) {
        eth_conf.parse(root["eth"]);
    }
    if (!root["pcap_replay"].isNull()) {
        pcap_conf.parse(root["pcap_replay"]);
    }
    if (!root["arp"].isNull()) {
        arp_conf.parse(root);
    }
    if (!root["ipv4"].isNull()) {
        ipv4_conf.parse(root);
    }

    return 0;
}

}
