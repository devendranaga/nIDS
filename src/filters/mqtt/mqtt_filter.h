#ifndef __FW_SRC_FILTER_MQTT_FILTER_H__
#define __FW_SRC_FILTER_MQTT_FILTER_H__

#include <logger.h>

namespace firewall {

struct parser;

enum class Mqtt_State {
    None,
    Connect_Req,
    Connect_Ack_Ok,
    Connect_Ack_Fail,
    Subscribe_Req,
    Subscribe_Ack_Ok,
    Subscribe_Ack_Fail,
    // This is where data transfers happen
    Publish,
    Ping_Req,
    Ping_Resp,
    Disconnect_Req,
};

struct mqtt_state_info {
    uint32_t sender_ip;
    uint32_t target_ip;
    uint16_t sender_port;
    uint16_t target_port;
    Mqtt_State state;

    explicit mqtt_state_info() :
                    sender_ip(0),
                    target_ip(0),
                    sender_port(0),
                    target_port(0),
                    state(Mqtt_State::None) { }
    ~mqtt_state_info() { }
};

class mqtt_filter {
    public:
        ~mqtt_filter() { }
        static mqtt_filter *instance()
        {
            static mqtt_filter f;
            return &f;
        }

        void run(parser &p, logger *log, bool debug);

    private:
        explicit mqtt_filter() { }
        std::vector<mqtt_state_info> mqtt_states_;
};

}


#endif

