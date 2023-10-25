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

/**
 * @brief - Implements udp serialize and deserialize.
*/
struct udp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;

    int serialize(packet &p);
    event_description deserialize(packet &p, logger *log, bool debug = false);
    void print(logger *log);

    private:
        const uint16_t udp_hdrlen_ = 8;
};

}

#endif

