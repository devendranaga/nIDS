/**
 * @brief - Implements tunables configuration parser.
 *
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
*/
#include <iostream>
#include <fstream>
#include <jsoncpp/json/json.h>
#include <tunables.h>

namespace firewall {

int tunables::parse(const std::string &config)
{
    Json::Value root;
    std::ifstream cfg_data(config, std::ifstream::binary);

    cfg_data >> root;

    ipv4_t.ip_blacklist_intvl_ms = root["ipv4"]["ip_blacklist_interval_ms"].asUInt();

    icmp_t.max_pkt_len_bytes = root["icmp"]["max_pkt_len_bytes"].asUInt();
    icmp_t.pkt_gap_two_echo_req_ms = root["icmp"]["packet_gap_two_echo_req_ms"].asUInt();
    icmp_t.icmp_entry_timeout_ms = root["icmp"]["icmp_entry_timeout_ms"].asUInt();

    mqtt_t.max_topic_name_len_allowed = root["mqtt"]["max_topic_name_len_allowed"].asUInt();

    return 0;
}

}
