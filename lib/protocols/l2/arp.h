/**
 * @brief - Implements ARP serialize and deserialize.
 * 
 * @copyright - 2023-present All rights reserved. Devendra Naga.
*/
#ifndef __FW_PROTOCOLS_ARP_H__
#define __FW_PROTOCOLS_ARP_H__

#include <stdint.h>
#include <common.h>
#include <ether_types.h>
#include <logger.h>
#include <packet.h>
#include <event_def.h>

namespace firewall {

#define ARP_HW_ADDR_LEN 6
#define ARP_PROTO_ADDR_LEN 4

//
// ARP operation
enum class arp_operation {
    Request = 1,
    Reply,
    Rarp_Request,
    Rarp_Reply,
    Drarp_Req,
    Drarp_Reply,
    InArp_Request,
    InArp_Reply,
};

enum class arp_hw_type {
    Ethernet = 1,
};

//
// Parses ARP header
struct arp_hdr {
    uint16_t hw_type;
    uint16_t proto_type;
    uint8_t hw_addr_len;
    uint8_t proto_addr_len;
    uint16_t operation;
    uint8_t sender_hw_addr[FW_MACADDR_LEN];
    uint32_t sender_proto_addr;
    uint8_t target_hw_addr[FW_MACADDR_LEN];
    uint32_t target_proto_addr;

    int serialize(packet &p);
    /**
     * @brief - implements ARP deserialization.
     * 
     * @param [in] p packet frame.
     * @return returns event_description type.
    */
    event_description deserialize(packet &p, logger *log, bool debug = false);
    void print(logger *log);

    inline bool is_arp_req()
    { return operation == (uint32_t)arp_operation::Request; }

    inline bool is_arp_reply()
    { return operation == (uint32_t)arp_operation::Reply; }

    private:
        const int arp_hdr_len = 28;
};

}

#endif
