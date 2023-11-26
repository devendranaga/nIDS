#ifndef __LIB_PROTOCOLS_L2_EAP_H__
#define __LIB_PROTOCOLS_L2_EAP_H__

#include <stdint.h>
#include <memory>
#include <packet.h>
#include <logger.h>
#include <event_def.h>

namespace firewall {

enum class IEEE8021x_Type : uint32_t {
    EAP = 0,
};

enum class Eap_Type : uint32_t {
    Identity = 1,
};

struct eap_hdr {
    uint8_t code;
    uint8_t id;
    uint16_t len;
    uint8_t type;

    int serialize(packet &p);
    event_description deserialize(packet &p, logger *log, bool debug);
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("\t EAP: {\n");
        log->verbose("\t\t code: %d\n", code);
        log->verbose("\t\t id: %d\n", id);
        log->verbose("\t\t len: %d\n", len);
        log->verbose("\t\t type: %d\n", type);
        log->verbose("\t }\n");
    #endif
    }
};

struct ieee8021x_hdr {
    uint8_t version;
    uint8_t type;
    uint16_t len;

    std::shared_ptr<eap_hdr> eap_h;

    int serialize(packet &p);
    event_description deserialize(packet &p, logger *log, bool debug);
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("IEEE8021.x_hdr: {\n");
        log->verbose("\t version: %d\n", version);
        log->verbose("\t type: %d\n", type);
        log->verbose("\t len: %d\n", len);
        if (eap_h)
            eap_h->print(log);
        log->verbose("}\n");
    #endif
    }
};

}

#endif

