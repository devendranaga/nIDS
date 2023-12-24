/**
 * @brief - Implements PPPOE frame serialize and deserialize.
 *
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
 */
#ifndef __FW_LIBS_PROTOCOLS_L2_PPPOE_H__
#define __FW_LIBS_PROTOCOLS_L2_PPPOE_H__

#include <logger.h>
#include <packet.h>
#include <event_def.h>

namespace firewall {

#define PPPOE_CODE_SESSION_DATA 0x00

#define PPPOE_PROTOCOL_IPV6 0x0057

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
};

}

#endif

