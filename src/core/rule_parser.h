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
#include <protocols_types.h>

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

    explicit eth_rule_config() noexcept
    {
        std::memset(from_src, 0, sizeof(from_src));
        std::memset(to_dst, 0, sizeof(to_dst));
        ethertype = 0;
    }
    ~eth_rule_config() { }
    void print(logger *log);
};

struct vlan_rule_config {
    uint8_t pri;
    uint16_t vid;

    explicit vlan_rule_config() noexcept :
                pri(0), vid(0)
    { }
    ~vlan_rule_config() { }
    void print(logger *log);
};

struct ipv4_rule_config {
    bool check_options;
    protocols_types protocol;

    explicit ipv4_rule_config() noexcept :
                check_options(false),
                protocol(protocols_types::Protocol_Max)
    { }
    ~ipv4_rule_config() { }
    void print(logger *log);
};

struct icmp_rule_config {
    bool non_zero_payload;

    explicit icmp_rule_config() noexcept :
                non_zero_payload(false)
    { }
    ~icmp_rule_config() { }
    void print(logger *log);
};

struct signature_id_bitmask {
    uint32_t from_src:1;
    uint32_t to_dst:1;
    uint32_t ethertype:1;
    uint8_t vlan_pri:1;
    uint8_t vid:1;
    uint8_t ipv4_check_options:1;
    uint8_t ipv4_protocol:1;
    uint8_t icmp_non_zero_payload:1;

    explicit signature_id_bitmask()
    {
        from_src = 0;
        to_dst = 0;
        ethertype = 0;
        vlan_pri = 0;
        vid = 0;
        ipv4_check_options = 0;
        ipv4_protocol = 0;
        icmp_non_zero_payload = 0;
    }

    ~signature_id_bitmask()
    { }

    bool operator==(const signature_id_bitmask &m)
    {
        return memcmp(this, &m, sizeof(*this));
    }
};

struct rule_config_item {
    std::string rule_name;
    uint32_t rule_id;
    rule_type type;
    eth_rule_config eth_rule;
    vlan_rule_config vlan_rule;
    ipv4_rule_config ipv4_rule;
    icmp_rule_config icmp_rule;
    signature_id_bitmask sig_mask;

    explicit rule_config_item() :
                rule_name(""),
                rule_id(0),
                type(rule_type::Deny)
    { }
    ~rule_config_item() { }

    void print();
};

struct signature_item {
    rule_config_item rule_item_;
    signature_id_bitmask matched_sig_bits_sofar_;

    explicit signature_item(rule_config_item &rule_item) :
                                    rule_item_(rule_item)
    { }
    ~signature_item() { }
};

/**
 * @brief - defines rule configuration.
*/
struct rule_config {
    std::vector<rule_config_item> rules_cfg_;

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

    /**
     * @brief - parse rules.
    */
    fw_error_type parse(const std::string rules_file);

    private:
        explicit rule_config() { }
        fw_error_type parse_rule(Json::Value &it);
        void parse_eth_rule(Json::Value &it, rule_config_item &item);
        void parse_vlan_rule(Json::Value &it, rule_config_item &item);
        void parse_ipv4_rule(Json::Value &it, rule_config_item &item);
        void parse_icmp_rule(Json::Value &it, rule_config_item &item);
};

struct signature_list {
    std::vector<signature_item> signatures_;

    explicit signature_list(rule_config *rule_cfg)
    {
        for (auto it : rule_cfg->instance()->rules_cfg_) {
            signature_item s(it);

            signatures_.push_back(s);
        }
    }

    ~signature_list() { }
};

}

#endif

