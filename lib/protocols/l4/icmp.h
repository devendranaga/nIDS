/**
 * @brief - implements ICMP serialize and deserialize.
 * 
 * @copyright - 2023-present. All rights reserved. Devendra Naga.
*/
#ifndef __FW_LIB_PROTOCOLS_ICMP_H__
#define __FW_LIB_PROTOCOLS_ICMP_H__

#include <packet.h>
#include <event_def.h>
#include <logger.h>

namespace firewall {

enum Icmp_Type {
    Echo_Reply = 0,
    Echo_Req = 8,
};

struct icmp_echo_req {
    uint16_t id;
    uint16_t seq_no;
    uint16_t data_len;
    uint8_t *data;

    void print(logger *log);
};

struct icmp_echo_reply {
    uint16_t id;
    uint16_t seq_no;
    uint16_t data_len;
    uint8_t *data;

    void print(logger *log);
};

struct icmp_hdr {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    icmp_echo_req *echo_req;
    icmp_echo_reply *echo_reply;

    explicit icmp_hdr() :
                echo_req(nullptr),
                echo_reply(nullptr)
    { }
    ~icmp_hdr() { }

    int serialize(packet &p);
    event_description deserialize(packet &p, logger *log, bool debug = false);
    void print(logger *log);
};

}

#endif

