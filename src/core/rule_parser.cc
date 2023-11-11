/**
 * @brief - implements rule parser.
 *
 * @copyright - 2023-present. All rights reserved. Devendra Naga.
*/
#include <iostream>
#include <fstream>
#include <jsoncpp/json/json.h>
#include <rule_parser.h>

namespace firewall {

void rule_config::parse_eth_rule(Json::Value &rule_cfg_data,
                                 rule_config_item &rule)
{
    int ret;

    //
    // check for validity and then only parse each below rule

    if (!rule_cfg_data["from_src"].isNull()) {
        ret = parse_str_to_mac(rule_cfg_data["from_src"].asString(),
                               rule.eth_rule.from_src);
        if (ret == 0) {
            rule.sig_mask.eth_sig.from_src = 1;
        }
    }

    if (!rule_cfg_data["to_dst"].isNull()) {
        ret = parse_str_to_mac(rule_cfg_data["to_dst"].asString(),
                               rule.eth_rule.to_dst);
        if (ret == 0) {
            rule.sig_mask.eth_sig.to_dst = 1;
        }
    }

    if (!rule_cfg_data["ethertype"].isNull()) {
        ret = parse_str_to_uint16_h(rule_cfg_data["ethertype"].asString(),
                                    rule.eth_rule.ethertype);
        if (ret == 0) {
            rule.sig_mask.eth_sig.ethertype = 1;
        }
    }
}

void eth_rule_config::print(logger *log)
{
#if defined(FW_ENABLE_DEBUG)
    log->verbose("\t eth_rules: {\n");
    log->verbose("\t\t from_src: %02x:%02x:%02x:%02x:%02x:%02x\n",
                    from_src[0], from_src[1],
                    from_src[2], from_src[3],
                    from_src[4], from_src[5]);
    log->verbose("\t\t to_dst: %02x:%02x:%02x:%02x:%02x:%02x\n",
                    to_dst[0], to_dst[1],
                    to_dst[2], to_dst[3],
                    to_dst[4], to_dst[5]);
    log->verbose("\t\t ethertype: %04x\n", ethertype);
    log->verbose("\t }\n");
#endif
}

void rule_config::parse_vlan_rule(Json::Value &rule_cfg_data,
                                  rule_config_item &rule)
{
    auto pri = rule_cfg_data["vlan"]["pri"];
    if (!pri.isNull()) {
        rule.vlan_rule.pri = pri.asUInt();
        rule.sig_mask.vlan_sig.vlan_pri = 1;
    }

    auto vid = rule_cfg_data["vlan"]["vid"];
    if (!vid.isNull()) {
        rule.vlan_rule.vid = rule_cfg_data["vlan"]["vid"].asUInt();
        rule.sig_mask.vlan_sig.vid = 1;
    }
}

void vlan_rule_config::print(logger *log)
{
#if defined(FW_ENABLE_DEBUG)
    log->verbose("\t vlan_rules: {\n");
    log->verbose("\t\t pri: %d\n", pri);
    log->verbose("\t\t vid: %d\n", vid);
    log->verbose("\t }\n");
#endif
}

void rule_config::parse_ipv4_rule(Json::Value &rule_cfg_data,
                                  rule_config_item &rule)
{
    auto chk_options = rule_cfg_data["ipv4"]["check_options"];
    if (!chk_options.isNull()) {
        rule.ipv4_rule.check_options = chk_options.asBool();
        rule.sig_mask.ipv4_sig.ipv4_check_options = 1;
    }

    auto protocol = rule_cfg_data["ipv4"]["protocol"];
    if (!protocol.isNull()) {
        if (protocol.asString() == "icmp") {
            rule.ipv4_rule.protocol = protocols_types::Protocol_Icmp;
            rule.sig_mask.ipv4_sig.ipv4_protocol = 1;
        }
    }
}

void ipv4_rule_config::print(logger *log)
{
#if defined(FW_ENABLE_DEBUG)
    log->verbose("\t ipv4_rules: {\n");
    log->verbose("\t\t check_options: %d\n", check_options);
    log->verbose("\t\t protocol: %d\n", static_cast<int>(protocol));
    log->verbose("\t }\n");
#endif
}

void rule_config::parse_icmp_rule(Json::Value &rule_cfg_data,
                                  rule_config_item &rule)
{
    auto non_zero_pl_str = rule_cfg_data["icmp"]["non_zero_payload"];
    if (!non_zero_pl_str.isNull()) {
        rule.icmp_rule.non_zero_payload = non_zero_pl_str.asBool();
        rule.sig_mask.icmp_sig.icmp_non_zero_payload = 1;
    }
}

void icmp_rule_config::print(logger *log)
{
#if defined(FW_ENABLE_DEBUG)
    log->verbose("\t icmp_rules: {\n");
    log->verbose("\t\t non_zero_payload: %d\n", non_zero_payload);
    log->verbose("\t }\n");
#endif
}

void rule_config::parse_udp_rule(Json::Value &rule_cfg_data,
                                 rule_config_item &rule)
{
    auto udp_rule_config_data = rule_cfg_data["udp"];
    if (udp_rule_config_data.isNull()) {
        return;
    }

    auto direction = rule_cfg_data["udp"]["direction"].asString();
    if (direction == "in") {
        rule.udp_rule.dir = Packet_Direction::In;
    } else if (direction == "out") {
        rule.udp_rule.dir = Packet_Direction::Out;
    } else {
        rule.udp_rule.dir = Packet_Direction::None;
    }

    rule.udp_rule.port = rule_cfg_data["udp"]["port"].asUInt();
    rule.sig_mask.udp_sig.port = 1;

    auto app_type = rule_cfg_data["udp"]["app_type"].asString();
    if (app_type == "someip") {
        rule.udp_rule.app_type = App_Type::SomeIP;
    }
}

void udp_rule_config::print(logger *log)
{
#if defined(FW_ENABLE_DEBUG)
    log->verbose("\tUDP_rules: {\n");
    log->verbose("\t\t dir: %d\n", (uint32_t)(dir));
    log->verbose("\t\t port: %d\n", port);
    log->verbose("\t\t app_type: %d\n", (uint32_t)(app_type));
    log->verbose("\t}\n");
#endif
}

void rule_config::parse_someip_rule(Json::Value &rule_cfg_data,
                                    rule_config_item &rule)
{
    int ret;

    auto someip_rule_config_data = rule_cfg_data["someip"];
    if (someip_rule_config_data.isNull()) {
        return;
    }

    ret = parse_str_to_uint16_h(rule_cfg_data["someip"]["service_id"].asString(),
                                rule.someip_rule.service_id);
    if (ret == 0) {
        rule.sig_mask.someip_sig.service_id = 1;
    }

    ret = parse_str_to_uint16(rule_cfg_data["someip"]["method_id"].asString(),
                              rule.someip_rule.method_id);
    if (ret == 0) {
        rule.sig_mask.someip_sig.method_id = 1;
    }
}

void someip_rule_config::print(logger *log)
{
#if defined(FW_ENABLE_DEBUG)
    log->verbose("\tSomeIP_rules: {\n");
    log->verbose("\t\t service_id: 0x%04x\n", service_id);
    log->verbose("\t\t method_id: 0x%04x\n", method_id);
    log->verbose("\t}\n");
#endif
}

void rule_config_item::print()
{
#if defined(FW_ENABLE_DEBUG)
    logger *log = logger::instance();

    log->verbose("Rule: {\n");
    log->verbose("\t rule_name: %s\n", rule_name.c_str());
    log->verbose("\t rule_id: %d\n", rule_id);
    log->verbose("\t type: %d\n", type);

    eth_rule.print(log);
    vlan_rule.print(log);
    ipv4_rule.print(log);
    icmp_rule.print(log);
    udp_rule.print(log);

    sig_mask.print(log);

    log->verbose("}\n");
#endif
}

fw_error_type rule_config::parse_rule(Json::Value &rule_cfg_data)
{
    rule_config_item rule;

    rule.rule_name = rule_cfg_data["rule_name"].asString();
    rule.rule_id = rule_cfg_data["rule_id"].asUInt();

    auto rule_type = rule_cfg_data["rule_type"].asString();
    if (rule_type == "allow") {
        rule.type = rule_type::Allow;
    } else if (rule_type == "deny") {
        rule.type = rule_type::Deny;
    } else if (rule_type == "event") {
        rule.type = rule_type::Event;
    } else {
        return fw_error_type::eInvalid;
    }

    parse_eth_rule(rule_cfg_data, rule);
    parse_vlan_rule(rule_cfg_data, rule);
    parse_ipv4_rule(rule_cfg_data, rule);
    parse_icmp_rule(rule_cfg_data, rule);
    parse_udp_rule(rule_cfg_data, rule);
    parse_someip_rule(rule_cfg_data, rule);

    rule.print();

    rules_cfg_.emplace_back(rule);

    return fw_error_type::eNo_Error;
}

fw_error_type rule_config::parse(const std::string rules_file)
{
    Json::Value root;
    std::ifstream conf(rules_file, std::ifstream::binary);

    conf >> root;

    for (auto it : root) {
        parse_rule(it);
    }

    return fw_error_type::eNo_Error;
}

void signature_id_bitmask::print(logger *log)
{
#if defined(FW_ENABLE_DEBUG)
    log->verbose("\t signature_mask: {\n");
    log->verbose("\t\t eth.from_src: %d\n", eth_sig.from_src);
    log->verbose("\t\t eth.to_dst: %d\n", eth_sig.to_dst);
    log->verbose("\t\t eth.ethertype: %d\n", eth_sig.ethertype);
    log->verbose("\t\t vlan.pri: %d\n", vlan_sig.vlan_pri);
    log->verbose("\t\t vlan.vid: %d\n", vlan_sig.vid);
    log->verbose("\t\t ipv4.ipv4_check_options: %d\n", ipv4_sig.ipv4_check_options);
    log->verbose("\t\t ipv4.ipv4_protocol: %d\n", ipv4_sig.ipv4_protocol);
    log->verbose("\t\t icmp.icmp_non_zero_payload: %d\n", icmp_sig.icmp_non_zero_payload);
    log->verbose("\t\t udp_sig.port: %d\n", udp_sig.port);
    log->verbose("\t\t someip.service_id: %d\n", someip_sig.service_id);
    log->verbose("\t\t someip.method_id: %d\n", someip_sig.method_id);
    log->verbose("\t }\n");
#endif
}

void signature_id_bitmask::init()
{
    eth_sig.init();
    vlan_sig.init();
    ipv4_sig.init();
    icmp_sig.init();
    udp_sig.init();
}

void eth_sig_bitmask::init()
{
    from_src = 0;
    to_dst = 0;
    ethertype = 0;
}

void vlan_sig_bitmask::init()
{
    vlan_pri = 0;
    vid = 0;
}

void ipv4_sig_bitmask::init()
{
    ipv4_check_options = 0;
    ipv4_protocol = 0;
}

void icmp_sig_bitmask::init()
{
    icmp_non_zero_payload = 0;
}

void udp_sig_bitmask::init()
{
    port = 0;
}

void someip_sig_bitmask::init()
{
    service_id = 0;
    method_id = 0;
}

}

