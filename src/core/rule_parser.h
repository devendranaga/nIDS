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

enum class Packet_Direction {
    None,
    In,
    Out,
};

enum class App_Type {
    None,
    SomeIP,
};

struct udp_rule_config {
    Packet_Direction dir;
    uint32_t port;
    App_Type app_type;

    explicit udp_rule_config() noexcept :
            dir(Packet_Direction::None),
            port(0),
            app_type(App_Type::None)
    { }
    ~udp_rule_config() { }
    void print(logger *log);
};

struct someip_rule_config {
    uint16_t service_id;
    uint16_t method_id;

    explicit someip_rule_config() noexcept :
            service_id(0),
            method_id(0)
    { }
    ~someip_rule_config() { }
    void print(logger *log);
};

struct port_rule_config {
    std::vector<uint16_t> port_list;
    uint32_t port_range_min;
    uint32_t port_range_max;

    explicit port_rule_config() { }
    ~port_rule_config() { }
    void print(logger *log);
};

struct protocol_rule_config {
    std::vector<uint16_t> protocol_list;

    explicit protocol_rule_config() { }
    ~protocol_rule_config() { }
    void print(logger *log);
};

struct eth_sig_bitmask {
    uint32_t from_src:1;
    uint32_t to_dst:1;
    uint32_t ethertype:1;

    explicit eth_sig_bitmask() :
                    from_src(0),
                    to_dst(0),
                    ethertype(0) { }
    ~eth_sig_bitmask() { }

    void init();
    bool active()
    {
        return from_src || to_dst || ethertype;
    }
};

struct vlan_sig_bitmask {
    uint32_t vlan_pri:1;
    uint32_t vid:1;

    explicit vlan_sig_bitmask() :
                    vlan_pri(0),
                    vid(0) { }
    ~vlan_sig_bitmask() { }

    void init();
};

struct ipv4_sig_bitmask {
    uint32_t ipv4_check_options:1;
    uint32_t ipv4_protocol:1;

    explicit ipv4_sig_bitmask() :
                    ipv4_check_options(0),
                    ipv4_protocol(0) { }
    ~ipv4_sig_bitmask() { }

    void init();
};

struct icmp_sig_bitmask {
    uint32_t icmp_non_zero_payload:1;

    explicit icmp_sig_bitmask() :
                    icmp_non_zero_payload(0) { }
    ~icmp_sig_bitmask() { }

    void init();
};

struct udp_sig_bitmask {
    uint32_t port:1;

    explicit udp_sig_bitmask() :
                    port(0) { }
    ~udp_sig_bitmask() { }

    void init();
};

struct someip_sig_bitmask {
    uint32_t service_id:1;
    uint32_t method_id:1;

    explicit someip_sig_bitmask() :
                    service_id(0),
                    method_id(0) { }
    ~someip_sig_bitmask() { }

    void init();
};

struct port_list_sig_bitmask {
    uint32_t port_list:1;
    uint32_t port_range:1;

    explicit port_list_sig_bitmask() :
                    port_list(0) { }
    ~port_list_sig_bitmask() { }

    void init();
};

struct protocol_list_sig_bitmask {
    uint32_t protocol_list:1;

    explicit protocol_list_sig_bitmask() :
                    protocol_list(0) { }
    ~protocol_list_sig_bitmask() { }

    void init();
};

struct signature_id_bitmask {
    eth_sig_bitmask eth_sig;
    vlan_sig_bitmask vlan_sig;
    ipv4_sig_bitmask ipv4_sig;
    icmp_sig_bitmask icmp_sig;
    udp_sig_bitmask udp_sig;
    someip_sig_bitmask someip_sig;
    port_list_sig_bitmask port_list_sig;
    protocol_list_sig_bitmask protocol_list_sig;

    explicit signature_id_bitmask() { }
    ~signature_id_bitmask() { }

    void init();

    bool operator==(const signature_id_bitmask &m)
    {
        return memcmp(this, &m, sizeof(*this));
    }

    void print(logger *log);
};

/**
 * @brief - defines an enclosed rule configuration structure holds
 *          information about each rule item.
*/
struct rule_config_item {
    std::string rule_name;
    uint32_t rule_id;
    rule_type type;
    eth_rule_config eth_rule;
    vlan_rule_config vlan_rule;
    ipv4_rule_config ipv4_rule;
    icmp_rule_config icmp_rule;
    udp_rule_config udp_rule;
    someip_rule_config someip_rule;
    port_rule_config port_rule;
    protocol_rule_config protocol_rule;
    signature_id_bitmask sig_mask;
    signature_id_bitmask sig_detected;

    explicit rule_config_item() :
                rule_name(""),
                rule_id(0),
                type(rule_type::Deny)
    {
        sig_mask.init();
    }
    ~rule_config_item() { }

    void print();
};

/**
 * @brief - defines rule configuration.
*/
struct rule_config {
    std::vector<rule_config_item> rules_cfg_;

    /**
     * @brief - get an instance of the rule_config.
    */
    static rule_config *instance() noexcept
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
        void parse_udp_rule(Json::Value &it, rule_config_item &item);
        void parse_someip_rule(Json::Value &it, rule_config_item &item);
        void parse_port_rule(Json::Value &it, rule_config_item &item);
        void parse_protocol_rule(Json::Value &it, rule_config_item &item);
};

}

#endif

