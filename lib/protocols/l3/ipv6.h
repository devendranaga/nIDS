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
#include <ipsec_ah.h>

namespace firewall {

#define IPV6_VERSION 6
#define IPV6_ADDR_LEN 16

enum class IPv6_NH_Type {
    Hop_By_Hop_Opt = 0,
    IPv6 = 41,
    ESP = 50,
    AH = 51,
};

enum class IPv6_Opt {
    Router_Alert = 0x05,
    PadN = 0x01,
};

struct ipv6_opt_router_alert {
    uint8_t action;
    uint8_t may_change;
    uint8_t len;
    uint16_t router_alert;
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("\t\tRouter_Alert: {\n");
        log->verbose("\t\t\tlen: %d\n", len);
        log->verbose("\t\t\trouter_alert: %d\n", router_alert);
        log->verbose("\t\t}\n");
    #endif
    }
};

struct ipv6_hop_by_hop_hdr {
    uint8_t nh;
    uint8_t len;
    std::shared_ptr<ipv6_opt_router_alert> ra;

    event_description deserialize(packet &p, logger *log, bool debug);
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("\tHop By Hop: {\n");
        log->verbose("\t\tnh: %d\n", nh);
        log->verbose("\t\tlen: %d\n", len);

        if (ra)
            ra->print(log);

        log->verbose("\t}\n");
    #endif
    }
};

struct ipv6_opts {
    std::shared_ptr<ipv6_hop_by_hop_hdr> hh;
    std::shared_ptr<ipsec_ah_hdr> ah_hdr;

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
    uint8_t priority; // 4 bits
    uint32_t flow_label; // 24 bits
    uint16_t payload_len; // 16 bits
    uint8_t nh;
    uint8_t hop_limit;
    uint8_t src_addr[IPV6_ADDR_LEN];
    uint8_t dst_addr[IPV6_ADDR_LEN];

    std::shared_ptr<ipv6_opts> opts;

    int serialize(packet &p);
    event_description deserialize(packet &p, logger *log, bool debug = false);
    void print(logger *log);

    inline bool is_dst_zero()
    {
        return is_zero_addr(dst_addr);
    }

    private:
        const int hdrlen_ = 40;

        inline bool is_zero_addr(uint8_t *addr)
        {
            uint8_t z_addr[IPV6_ADDR_LEN] = {
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
            };
            return (std::memcmp(addr, z_addr, sizeof(z_addr)) == 0);
        }
};

}

#endif

