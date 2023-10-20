#ifndef __FW_LIB_PROTOCOLS_APP_SNMP_H__
#define __FW_LIB_PROTOCOLS_APP_SNMP_H__

#include <packet.h>
#include <event_def.h>
#include <logger.h>

namespace firewall {

struct snmp_hdr {
    int serialize(packet &p);
    event_description deserialize(packet &p, logger *log, bool debug = false);
    void print(logger *log);
};

}

#endif

