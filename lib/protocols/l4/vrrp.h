/**
 * @brief - Implements VRRP serialize and deserialize.
 *
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
*/
#ifndef __FW_LIB_PROTOCOLS_L4_VRRP_H__
#define __FW_LIB_PROTOCOLS_L4_VRRP_H__

#include <logger.h>
#include <event_def.h>
#include <packet.h>

namespace firewall {

/**
 * @brief - Implements VRRP V2 header.
 */
struct vrrp_v2_hdr {
    uint8_t virtual_router_id;
    uint8_t priority;
    uint8_t addr_count;
    uint8_t auth_type;
    uint8_t adver_int;
    uint16_t checksum;
    uint32_t ipaddr;

    int serialize(packet &p);

    /**
     * @brief - deserialize VRRP V2 header.
     *
     * @param [in] p - packet.
     * @param [in] log - logger.
     * @param [in] debug - debug.
     *
     * @return event_description.
    */
    event_description deserialize(packet &p, logger *log, bool debug = false);
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("\tV2_hdr: {\n");
        log->verbose("\t\tvirtual_router_id: %d\n", virtual_router_id);
        log->verbose("\t\tpriority: %d\n", priority);
        log->verbose("\t\taddr_count: %d\n", addr_count);
        log->verbose("\t\tauth_type: %d\n", auth_type);
        log->verbose("\t\tadver_int: %d\n", adver_int);
        log->verbose("\t\tchecksum: 0x%04x\n", checksum);
        log->verbose("\t\tipaddr: %u\n", ipaddr);
        log->verbose("\t}\n");
    #endif
    }
};

/**
 * @brief - Describes VRRP header serialization and deserialization.
*/
struct vrrp_hdr {
    uint8_t version;
    uint8_t pkt_type;

    union {
        vrrp_v2_hdr v2_hdr;
    } opt;

    int serialize(packet &p);
    /**
     * @brief - deserialize VRRP header.
     *
     * @param [in] p - packet.
     * @param [in] log - logger.
     * @param [in] debug - debug.
     *
     * @return event_description.
    */
    event_description deserialize(packet &p, logger *log, bool debug = false);
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("VRRP: {\n");
        log->verbose("\tversion: %d\n", version);
        log->verbose("\tpkt_type: %d\n", pkt_type);

        if (version == 2)
            opt.v2_hdr.print(log);

        log->verbose("}\n");
    #endif
    }

    private:
        const int min_hdr_len_ = 1;
        const int min_hdr_len_v2_ = 11;
};

}

#endif

