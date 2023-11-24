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

    enable = r["enable"].asBool();

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

    enable = r["arp"]["enable"].asBool();
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

    enable = r["ipv4"]["enable"].asBool();
    ret = parse_str_to_mac(r["ipv4"]["src_mac"].asString(), src_mac);
    if (ret != 0)
        return -1;

    ret = parse_str_to_mac(r["ipv4"]["dest_mac"].asString(), dest_mac);
    if (ret != 0)
        return -1;

    ret = parse_str_to_uint32(r["ipv4"]["ttl"].asString(), ttl);
    if (ret != 0)
        return -1;

    auto_ttl = r["ipv4"]["auto_ttl"].asBool();

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

    ret = parse_str_to_uint16(r["ipv4"]["protocol"].asString(), protocol);
    if (ret != 0)
        return -1;

    ret = parse_str_to_uint32(r["ipv4"]["count"].asString(), count);
    if (ret != 0)
        return -1;

    ret = parse_str_to_uint32(r["ipv4"]["inter_pkt_gap_us"].asString(), inter_pkt_gap_us);
    if (ret != 0)
        return -1;

    valid_ = true;

    return 0;
}

int packet_gen_macsec_config::parse(Json::Value &r)
{
    uint32_t ver = 0;
    uint32_t es = 0;
    uint32_t sc = 0;
    uint32_t scb = 0;
    uint32_t e = 0;
    uint32_t c = 0;
    uint32_t an = 0;
    int ret;

    enable = r["macsec"]["enable"].asBool();

    ret = parse_str_to_uint32(r["macsec"]["tci"]["ver"].asString(), ver);
    if (ret != 0)
        return -1;

    macsec_h.tci.ver = ver;

    ret = parse_str_to_uint32(r["macsec"]["tci"]["es"].asString(), es);
    if (ret != 0)
        return -1;

    macsec_h.tci.es = es;

    ret = parse_str_to_uint32(r["macsec"]["tci"]["sc"].asString(), sc);
    if (ret != 0)
        return -1;

    macsec_h.tci.sc = sc;

    ret = parse_str_to_uint32(r["macsec"]["tci"]["scb"].asString(), scb);
    if (ret != 0)
        return -1;

    macsec_h.tci.scb = scb;

    ret = parse_str_to_uint32(r["macsec"]["tci"]["e"].asString(), e);
    if (ret != 0)
        return -1;

    macsec_h.tci.e = e;

    ret = parse_str_to_uint32(r["macsec"]["tci"]["c"].asString(), c);
    if (ret != 0)
        return -1;

    macsec_h.tci.c = c;

    ret = parse_str_to_uint32(r["macsec"]["tci"]["an"].asString(), an);
    if (ret != 0)
        return -1;

    macsec_h.tci.an = an;

    ret = parse_str_to_uint32(r["macsec"]["short_len"].asString(), (uint32_t &)(macsec_h.short_len));
    if (ret != 0)
        return -1;

    ret = parse_str_to_uint32(r["macsec"]["pkt_number"].asString(), macsec_h.pkt_number);
    if (ret != 0)
        return -1;

    ret = parse_str_to_mac(r["macsec"]["sci"]["mac"].asString(), macsec_h.sci.mac);
    if (ret != 0)
        return -1;

    ret = parse_str_to_uint32(r["macsec"]["sci"]["port_id"].asString(), (uint32_t &)(macsec_h.sci.port_id));
    if (ret != 0)
        return -1;

    ret = parse_str_to_uint16_h(r["macsec"]["macsec_ethertype"].asString(), macsec_h.ethertype);
    if (ret != 0)
        return -1;

    ret = parse_str_to_uint16(r["macsec"]["data_len"].asString(), macsec_h.data_len);
    if (ret != 0)
        return -1;

    ret = parse_str_to_uint32(r["macsec"]["count"].asString(), count);
    if (ret != 0)
        return -1;

    ret = parse_str_to_uint32(r["macsec"]["inter_pkt_gap_us"].asString(), inter_pkt_gap_us);
    if (ret != 0)
        return -1;

    ret = parse_str_to_mac(r["macsec"]["eth_src"].asString(), eth_src);
    if (ret != 0)
        return -1;

    ret = parse_str_to_mac(r["macsec"]["eth_dst"].asString(), eth_dst);
    if (ret != 0)
        return -1;

    ret = parse_str_to_uint16_h(r["macsec"]["ethertype"].asString(), ethertype);
    if (ret != 0)
        return -1;

    valid_ = true;

    return 0;
}

int packet_gen_pcap_replay_config::parse(Json::Value &r)
{
    enable = r["enable"].asBool();
    filepath = r["filepath"].asString();
    intvl_us = r["intvl_us"].asUInt();
    repeat = r["repeat"].asBool();
    use_pcap_timestamps = r["use_pcap_timediff"].asBool();

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
    if (!root["macsec"].isNull()) {
        macsec_conf.parse(root);
    }

    return 0;
}

}
