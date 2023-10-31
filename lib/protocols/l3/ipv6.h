/**
 * @brief - implements ipv6 serialize and deserialize.
 * 
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
*/
#ifndef __FW_PROTOCOLS_IPV6_H__
#define __FW_PROTOCOLS_IPV6_H__

#include <memory>
#include <packet.h>
#include <logger.h>
#include <event_def.h>

namespace firewall {

#define IPV6_VERSION 6
#define IPV6_ADDR_LEN 16

enum class IPv6_NH_Type {
    Hop_By_Hop_Opt = 0,
};

enum class IPv6_Opt {
    Router_Alert = 0x05,
};

struct ipv6_opt_router_alert {
    uint8_t len;
    uint16_t router_alert;
};

struct ipv6_hop_by_hop_hdr {
    uint8_t nh;
    uint8_t len;
    std::shared_ptr<ipv6_opt_router_alert> ra;

    event_description deserialize(packet &p, logger *log, bool debug);
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("nh: %d\n", nh);
        log->verbose("len: %d\n", len);
    #endif
    }
};

struct ipv6_opts {
    std::shared_ptr<ipv6_hop_by_hop_hdr> hh;

    explicit ipv6_opts() :
                hh(nullptr) { }
    ~ipv6_opts() { }

    event_description deserialize(packet &p, logger *log, bool debug);
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        if (hh)
            hh->print(log);
    #endif
    }
};

/**
 * @brief - implements ipv6 header.
*/
struct ipv6_hdr {
    uint32_t version:4;
    uint8_t priority;
    uint32_t flow_label;
    uint16_t payload_len;
    uint8_t nh;
    uint8_t hop_limit;
    uint8_t src_addr[IPV6_ADDR_LEN];
    uint8_t dst_addr[IPV6_ADDR_LEN];

    std::shared_ptr<ipv6_opts> opts;

    int serialize(packet &p);
    event_description deserialize(packet &p, logger *log, bool debug = false);
    void print(logger *log);

    private:
        const int hdrlen_ = 40;
};

}

#endif
