#ifndef __FW_PROTOCOLS_IPV6_H__
#define __FW_PROTOCOLS_IPV6_H__

#include <packet.h>
#include <logger.h>
#include <event_def.h>

namespace firewall {

#define IPV6_VERSION 6
#define IPV6_ADDR_LEN 16

struct ipv6_hdr {
    uint32_t version:4;
    uint8_t priority;
    uint32_t flow_label;
    uint16_t payload_len;
    uint8_t nh;
    uint8_t hop_limit;
    uint8_t src_addr[IPV6_ADDR_LEN];
    uint8_t dst_addr[IPV6_ADDR_LEN];

    int serialize(packet &p);
    event_description deserialize(packet &p, logger *log, bool debug = false);
    void print(logger *log);

    private:
        const int hdrlen_ = 40;
};

}

#endif
