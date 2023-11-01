#ifndef __FW_EVENT_EVENT_MQTT_H__
#define __FW_EVENT_EVENT_MQTT_H__

#include <string>
#include <common.h>
#include <MQTTClient.h>

namespace firewall {

class mqtt_publisher {
    public:
        explicit mqtt_publisher();
        ~mqtt_publisher();

        int init();
        int write(uint8_t *msg, uint32_t msg_len);

    private:
        MQTTClient client_;
        MQTTClient_connectOptions conn_opts_;
        bool init_ok_;
        uint32_t timeout_ms_ = 10000;
        uint32_t keepalive_intvl_s_ = 20;
        uint32_t qos_ = 1;
        std::string client_id_ = "nids_mqtt_event_messenger";
};

}

#endif

