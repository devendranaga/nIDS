/**
 * @brief - implements icmp6 serialize and deserialize.
 * 
 * @copyright - 2023-present. All rights reserved. Devendra Naga.
*/
#ifndef __FW_LIB_PROTOCOLS_ICMP6_H__
#define __FW_LIB_PROTOCOLS_ICMP6_H__

#include <packet.h>
#include <logger.h>
#include <event_def.h>

namespace firewall {

//
// list of icmp6 types
enum icmp6_types {
    Icmp6_Type_Router_Advertisement = 134,
    Icmp6_Type_Max = 255,
};

struct icmp6_flags {
    uint32_t managed_addr_conf:1;
    uint32_t other_conf:1;
    uint32_t home_agent:1;
    uint32_t prf:2;
    uint32_t proxy:1;
    uint32_t reserved:1;
};

struct icmp6_option_dns_search_list {
    uint8_t len;
    uint16_t reserved;
    uint32_t lifetime;
    uint8_t domain_name[128];
    uint32_t domain_name_len;
    uint8_t padding[128];
    uint32_t padding_len;

    int serialize(packet &p);
    event_description deserialize(packet &p, logger *log, bool debug = false);
    void print(logger *log);
};

struct icmp6_option_mtu {
    uint8_t len;
    uint16_t reserved;
    uint32_t mtu;

    int serialize(packet &p);
    event_description deserialize(packet &p, logger *log, bool debug = false);
    void print(logger *log);
};

struct icmp6_option_source_link_layer_addr {
    uint8_t len;
    uint8_t lladdr[FW_MACADDR_LEN];

    int serialize(packet &p);
    event_description deserialize(packet &p, logger *log, bool debug = false);
    void print(logger *log);    
};

struct icmp6_router_advertisement {
    icmp6_flags flags;
    uint16_t router_lifetime;
    uint32_t reachable_time;
    uint32_t retransmit_timer;

    int serialize(packet &p);
    event_description deserialize(packet &p, logger *log, bool debug = false);
    void print(logger *log);
};

struct icmp6_hdr {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint8_t cur_hoplimit;
    icmp6_router_advertisement radv;

    icmp6_option_dns_search_list *dns_search_list;
    icmp6_option_mtu *mtu;
    icmp6_option_source_link_layer_addr *s_lladdr;

    explicit icmp6_hdr() :
                    dns_search_list(nullptr),
                    mtu(nullptr),
                    s_lladdr(nullptr)
    { }
    ~icmp6_hdr() { }

    int serialize(packet &p);
    event_description deserialize(packet &p, logger *log, bool debug = false);
    void print(logger *log);
};

}

#endif

