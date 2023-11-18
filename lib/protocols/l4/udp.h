/**
 * @brief - implements udp serialize and deserialize.
 * 
 * @copyright - 2023-present. All rights reserved. Devendra Naga.
*/
#ifndef __FW_PROTOCOLS_UDP_H__
#define __FW_PROTOCOLS_UDP_H__

#include <packet.h>
#include <event_def.h>
#include <logger.h>

namespace firewall {

union ipv4_pseudo_hdr {
    uint32_t src_ipaddr;
    uint32_t dst_ipaddr;
    uint8_t zero;
    uint8_t protocol;
    uint16_t len;
    uint16_t arr[6];
};

/**
 * @brief - Implements udp serialize and deserialize.
*/
struct udp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;

    uint32_t start_off;
    uint32_t end_off;

    int serialize(packet &p);
    event_description deserialize(packet &p, logger *log, bool debug = false);
    int validate_checksum(packet &p,
                          uint32_t src_ipaddr, uint32_t dst_ipaddr,
                          uint16_t protocol);
    void print(logger *log);

    private:
        const uint16_t udp_hdrlen_ = 8;
};

}

#endif

