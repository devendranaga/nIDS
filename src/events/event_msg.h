#ifndef __FW_EVENT_MSG_H__
#define __FW_EVENT_MSG_H__

#include <stdint.h>
#include <event_def.h>

namespace firewall {

struct event_udp_info {
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t data[0];
} __attribute__ ((__packed__));

struct event_ipv4_info {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t ttl;
    uint32_t protocol;
    uint8_t data[0];
} __attribute__ ((__packed__));

struct event_msg {
    uint32_t rule_id;
    event_type evt_type;
    event_description evt_desc;
    uint32_t ethertype;
    uint8_t data[0];
} __attribute__ ((__packed__));

}

#endif

