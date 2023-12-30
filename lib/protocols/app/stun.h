#ifndef __FW_LIB_PROTOCOLS_APP_STUN_H__
#define __FW_LIB_PROTOCOLS_APP_STUN_H__

#include <logger.h>
#include <event_def.h>
#include <packet.h>

namespace firewall {

struct stun_hdr {
    uint16_t msg_type;
    uint16_t msg_len;
    uint32_t msg_cookie;
    uint8_t msg_transaction_id[12];

    int serialize(packet &p);
    event_description deserialize(packet &p, logger *log, bool debug = false);
};

}

#endif

