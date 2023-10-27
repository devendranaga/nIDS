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
    if (ret != 0) {
        return -1;
    }

    ret = parse_str_to_mac(r["dst_mac"].asString(), dst_mac);
    if (ret != 0) {
        return -1;
    }

    ret = parse_str_to_uint32_h(r["ethertype"].asString(), ethertype);
    if (ret != 0) {
        return -1;
    }

    pkt_len = r["pkt_len"].asUInt();
    repeat = r["repeat"].asBool();
    count = r["count"].asUInt();
    inter_pkt_gap_us = r["inter_pkt_gap_us"].asUInt();

    valid_ = true;

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

    return 0;
}

}
