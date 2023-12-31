/**
 * @brief - Implements VLAN serialize and deserialize.
 *
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
 */
#ifndef __FW_PROTOCOLS_VLAN_H__
#define __FW_PROTOCOLS_VLAN_H__

#include <stdint.h>
#include <memory>
#include <common.h>
#include <ether_types.h>
#include <logger.h>
#include <packet.h>
#include <event_def.h>

namespace firewall {

/**
 * @brief - Implements VLAN header.
 */
struct vlan_hdr {
    uint8_t pri:3;
    uint8_t dei:1;
    uint16_t vid:12;
    uint16_t ethertype;

    explicit vlan_hdr();
    ~vlan_hdr();

    /**
     * @brief - implements VLAN serialization.
     *
     * @param [in] p - packet.
     * @return returns 0 on success.
    */
    int serialize(packet &p);
    /**
     * @brief - implements VLAN deserialization.
     *
     * @param [in] p packet frame.
     * @return returns event_description type.
    */
    event_description deserialize(packet &p, logger *log, bool debug = false);

    /**
     * @brief - return the ethertype
     *
     * @return returns ethertype.
    */
    Ether_Type get_ethertype();

    bool has_double_tagged();

    /**
     * @brief - print vlan header.
     *
     * @param [in] log - logger.
    */
    void print(logger *log);

    //
    // possiblity of a double tagged VLAN
    std::shared_ptr<vlan_hdr> next;

    private:
        uint16_t vlan_hdrlen_ = 4;
};

}

#endif

