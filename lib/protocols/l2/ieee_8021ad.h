#ifndef __FW_LIB_L2_IEEE8021AD_H__
#define __FW_LIB_L2_IEEE8021AD_H__

#include <stdint.h>
#include <ether_types.h>
#include <packet.h>
#include <logger.h>
#include <event_def.h>

namespace firewall {

struct ieee8021ad_hdr {
    uint8_t pri:3;
    uint8_t dei:1;
    uint16_t vid;
    uint16_t ethertype;

    int serialize(packet &p);
    event_description deserialize(packet &p, logger *log, bool debug);
    inline Ether_Type get_ethertype()
    { return static_cast<Ether_Type>(ethertype); }
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("\t IEEE8021ad_hdr: {\n");
        log->verbose("\t\t pri: %d\n", pri);
        log->verbose("\t\t dei: %d\n", dei);
        log->verbose("\t\t vid: %d\n", vid);
        log->verbose("\t\t ethertype: 0x%04x\n", ethertype);
        log->verbose("\t }\n");
    #endif
    }
};

}

#endif


