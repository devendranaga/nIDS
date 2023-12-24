/**
 * @brief - Implements Tunable configuration parser.
 *
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
*/
#ifndef __FW_SRC_CONFIG_TUNABLES_H__
#define __FW_SRC_CONFIG_TUNABLES_H__

#include <string>
#include <stdint.h>

namespace firewall {

#define IP_BLACKLIST_INTVL_MS_DEF 10000

struct ipv4_tunables {
    uint32_t ip_blacklist_intvl_ms;

    explicit ipv4_tunables() :
                ip_blacklist_intvl_ms(IP_BLACKLIST_INTVL_MS_DEF) { }
    ~ipv4_tunables() { }
};

#define ICMP_PKTGAP_TWO_ECHO_REQ_MS 5000
#define ICMP_ENTRY_TIMEO_MS 10000

struct icmp_tunables {
    uint32_t max_pkt_len_bytes;
    uint32_t pkt_gap_two_echo_req_ms;
    uint32_t icmp_entry_timeout_ms;

    explicit icmp_tunables() :
                pkt_gap_two_echo_req_ms(ICMP_PKTGAP_TWO_ECHO_REQ_MS),
                icmp_entry_timeout_ms(ICMP_ENTRY_TIMEO_MS) { }
    ~icmp_tunables() { }
};

#define MQTT_MAX_TOPICNAME_LEN_DEF 100

struct mqtt_tunables {
    uint32_t max_topic_name_len_allowed;

    explicit mqtt_tunables() :
                max_topic_name_len_allowed(MQTT_MAX_TOPICNAME_LEN_DEF) { }
    ~mqtt_tunables() { }
};

/**
 * @brief- tunable configuration.
 *
 * Tunables allow various filter parameter tuning to make it suitable for the
 * target environment where nIDS executes.
*/
struct tunables {
    public:
        ipv4_tunables ipv4_t;
        icmp_tunables icmp_t;
        mqtt_tunables mqtt_t;

        explicit tunables(const tunables &) = delete;
        const tunables &operator=(const tunables &) = delete;
        explicit tunables(const tunables &&) = delete;
        const tunables &&operator=(const tunables &&) = delete;
        ~tunables() { }

        static tunables *instance()
        {
            static tunables t;
            return &t;
        }

        int parse(const std::string &config);
    private:
        explicit tunables() { }
};

}

#endif
