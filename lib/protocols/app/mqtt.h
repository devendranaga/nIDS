#ifndef __FW_LIB_APP_MQTT_H__
#define __FW_LIB_APP_MQTT_H__

#include <packet.h>
#include <event_def.h>
#include <logger.h>

namespace firewall {

enum Mqtt_Msg_Type {
    Connect = 0x1,
};

struct mqtt_hdr {
    uint8_t msg_type;
    uint8_t reserved;
    uint16_t msg_len;

    int serialize(packet &p);
    event_description deserialize(packet &p, logger *log, bool debug = false);
    void print(logger *log);
};

}

#endif
