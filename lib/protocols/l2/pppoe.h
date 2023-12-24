/**
 * @brief - Implements PPPOE frame serialize and deserialize.
 *
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
 */
#ifndef __FW_LIBS_PROTOCOLS_L2_PPPOE_H__
#define __FW_LIBS_PROTOCOLS_L2_PPPOE_H__

#include <ether_types.h>
#include <logger.h>
#include <packet.h>
#include <event_def.h>

namespace firewall {

#define PPPOE_CODE_SESSION_DATA     0x00

#define PPPOE_PROTOCOL_IPV6         0x0057
#define PPPOE_IP_CONTROL_PROTOCOL   0x8021
#define PPPOE_LINK_CONTROL_PROTOCOL 0xc021

#define PPPOE_LCP_ECHO_REQ 9
#define PPPOE_LCP_ECHO_REPLY 10

struct pppoe_link_control_protocol {
    uint8_t code;
    uint8_t id;
    uint16_t len;
    uint32_t magic_no;
    uint8_t data[1500];

    int serialize(packet &p);
    event_description deserialize(packet &p, logger *log, bool debug = false);
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("\tLCP: {\n");
        log->verbose("\t\tcode: %d\n", code);
        log->verbose("\t\tid: %d\n", id);
        log->verbose("\t\tlen: %d\n", len);
        log->verbose("\t\tmagic_no: 0x%x\n", magic_no);
        log->verbose("\t}\n");
    #endif
    }
};

/**
 * @brief - Implements PPPOE header.
 */
struct pppoe_hdr {
    uint8_t version:4;
    uint8_t type:4;
    uint8_t code;
    uint16_t session_id;
    uint16_t payload_len;
    uint16_t protocol;

    union {
        pppoe_link_control_protocol lcp;
    } opt;

    int serialize(packet &p);
    /**
     * @brief - deserialize PPPOE frame.
     *
     * @param [in] p - packet.
     * @param [in] log - logger.
     * @param [in] debug - debug flag.
     *
     * @return event_description.
     */
    event_description deserialize(packet &p, logger *log, bool debug = false);

    Ether_Type get_ethertype();

    /**
     * @brief - print the PPPOE frame.
     *
     * @param [in] log - logger.
     */
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("PPPOE: {\n");
        log->verbose("\tversion: %d\n", version);
        log->verbose("\ttype: %d\n", type);
        log->verbose("\tcode: %d\n", code);
        log->verbose("\tsession_id: 0x%04x\n", session_id);
        log->verbose("\tpayload_len: 0x%04x\n", payload_len);
        log->verbose("\tprotocol: 0x%04x\n", protocol);
        log->verbose("}\n");
    #endif
    }
};

}

#endif

