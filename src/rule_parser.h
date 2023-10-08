/**
 * @brief - Implements rule parser.
 * 
 * @copyright - 2023-present All rights reserved.
*/
#ifndef __FW_RULE_PARSER_H__
#define __FW_RULE_PARSER_H__

#include <string>

namespace firewall {

enum class rule_type {
    Allow,
    Deny,
    Event,
};

struct eth_rule_config {
    uint8_t from_src[6];
    uint8_t to_dst[6];
    uint16_t ethertype;
};

struct rule_config {
    std::string rule_name;
    uint32_t rule_id;
    rule_type type;
    eth_rule_config eth_rule;

    static rule_config *instance()
    {
        static rule_config conf;

        return &conf;
    }
    ~rule_config() { }

    private:
        explicit rule_config() { }
};

}

#endif

