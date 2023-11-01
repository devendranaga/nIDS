#ifndef __FW_PROTOCOLS_VLAN_H__
#define __FW_PROTOCOLS_VLAN_H__

#include <stdint.h>
#include <common.h>
#include <ether_types.h>
#include <logger.h>
#include <packet.h>
#include <event_def.h>

namespace firewall {

struct vlan_hdr {
    uint8_t pri:3;
    uint8_t dei:1;
    uint16_t vid:12;
    uint16_t ethertype;

    int serialize(packet &p);
    /**
     * @brief - implements VLAN deserialization.
     * 
     * @param [in] p packet frame.
     * @return returns event_description type.
    */
    event_description deserialize(packet &p, logger *log, bool debug = false);

    Ether_Type get_ethertype()
    { return static_cast<Ether_Type>(ethertype); }

    void print(logger *log);

    private:
        uint16_t vlan_hdrlen_ = 4;
};

}

#endif

