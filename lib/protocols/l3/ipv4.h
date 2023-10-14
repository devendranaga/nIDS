/**
 * @brief - implements ipv4 protocol serialize and deserialize.
 * 
 * @copyright - 2023-present All rights reserved. Devendra Naga.
*/
#ifndef __FW_PROTOCOLS_IPV4_H__
#define __FW_PROTOCOLS_IPV4_H__

#include <stdint.h>
#include <logger.h>
#include <packet.h>
#include <protocols_types.h>
#include <event_def.h>
#include <logger.h>

namespace firewall {

#define IPV4_VERSION 4
#define IPV4_IHL_LEN 4
#define IPV4_HDR_NO_OPTIONS 20
#define IPV4_HDR_LEN_MAX 60

struct ipv4_hdr {
    uint8_t version;
    uint32_t hdr_len;
    uint32_t dscp;
    uint32_t ecn;
    uint16_t total_len;
    uint16_t identification;
    bool reserved;
    bool dont_frag;
    bool more_frag;
    uint32_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t hdr_chksum;
    uint32_t src_addr;
    uint32_t dst_addr;
    uint32_t start_off;
    uint32_t end_off;

    bool is_a_frag() { return frag_off > 0; }
    int serialize(packet &p);
    event_description deserialize(packet &p, logger *log, bool debug = false);
    void print(logger *log);
};

}

#endif
