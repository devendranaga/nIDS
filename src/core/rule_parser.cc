#include <iostream>
#include <fstream>
#include <jsoncpp/json/json.h>
#include <rule_parser.h>

namespace firewall {

void rule_config::parse_eth_rule(Json::Value &rule_cfg_data,
                                 rule_config_item &rule)
{
    int ret;

    ret = parse_str_to_mac(rule_cfg_data["from_src"].asString(),
                     rule.eth_rule.from_src);
    if (ret == 0) {
        rule.sig_mask.from_src = 1;
    }

    ret = parse_str_to_mac(rule_cfg_data["to_dst"].asString(),
                     rule.eth_rule.to_dst);
    if (ret == 0) {
        rule.sig_mask.to_dst = 1;
    }

    ret = parse_str_to_uint16_h(rule_cfg_data["ethertype"].asString(),
                        rule.eth_rule.ethertype);
    if (ret == 0) {
        rule.sig_mask.ethertype = 1;
    }
}

void rule_config_item::print()
{
    logger *log = logger::instance();

    log->verbose("rule_name: %s\n", rule_name.c_str());
    log->verbose("rule_id: %d\n", rule_id);
    log->verbose("type: %d\n", type);

    eth_rule.print(log);
}

void eth_rule_config::print(logger *log)
{
    log->verbose("eth_rules: {\n");
    log->verbose("\tfrom_src: %02x:%02x:%02x:%02x:%02x:%02x\n",
                    from_src[0], from_src[1],
                    from_src[2], from_src[3],
                    from_src[4], from_src[5]);
    log->verbose("\tto_dst: %02x:%02x:%02x:%02x:%02x:%02x\n",
                    to_dst[0], to_dst[1],
                    to_dst[2], to_dst[3],
                    to_dst[4], to_dst[5]);
    log->verbose("\tethertype: %04x\n", ethertype);
    log->verbose("}\n");
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

}