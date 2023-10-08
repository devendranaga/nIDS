/**
 * @brief - Implements rule parser.
 * 
 * @copyright - 2023-present All rights reserved.
*/
#ifndef __FW_RULE_PARSER_H__
#define __FW_RULE_PARSER_H__

#include <string>
#include <jsoncpp/json/json.h>
#include <logger.h>
#include <common.h>

namespace firewall {

enum class rule_type {
    Allow,
    Deny,
    Event,
};

struct eth_rule_config {
#define ETH_RULE_FROM_SRC_AVAIL 0x80
#define ETH_RULE_TO_DST_AVAIL 0x40
#define ETH_RULE_ETHERTYPE_AVAIL 0x20
    uint8_t from_src[6];
    uint8_t to_dst[6];
    uint16_t ethertype;
    uint32_t avail_bits;

    eth_rule_config(): avail_bits(0)
    {
        std::memset(from_src, 0, sizeof(from_src));
        std::memset(to_dst, 0, sizeof(to_dst));
        ethertype = 0;
    }
    ~eth_rule_config() { }
    void print(logger *log);
};

struct rule_config_item {
    std::string rule_name;
    uint32_t rule_id;
    rule_type type;
    eth_rule_config eth_rule;

    void print();
};

struct rule_config {
    std::vector<rule_config_item> rules_;

    static rule_config *instance()
    {
        static rule_config conf;

        return &conf;
    }
    ~rule_config() { }
    explicit rule_config(const rule_config &) = delete;
    const rule_config &operator=(const rule_config &) = delete;
    explicit rule_config(const rule_config &&) = delete;
    const rule_config &&operator=(const rule_config &&) = delete;

    fw_error_type parse(const std::string rules_file);

    private:
        explicit rule_config() { }
        fw_error_type parse_rule(Json::Value &it);
        void parse_eth_rule(Json::Value &it, rule_config_item &item);
};

}

#endif

