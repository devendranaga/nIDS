/**
 * @brief - implements MQTT serialize and deserialize.
 * 
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
*/
#ifndef __FW_LIB_APP_MQTT_H__
#define __FW_LIB_APP_MQTT_H__

#include <memory>
#include <packet.h>
#include <event_def.h>
#include <logger.h>

namespace firewall {

enum class Mqtt_Msg_Type {
    Connect = 0x1,
    Connect_Ack = 0x02,
    Publish = 0x03,
    Subscribe_Req = 0x08,
    Subscribe_Ack = 0x09,
    Ping_Req = 0x0C,
    Ping_Response = 0x0D,
};

enum class Mqtt_Requested_QOS {
    At_Most_Once_Delivery, // Fire and Forget
};

struct mqtt_publish {
    uint16_t topic_len;
    uint8_t *topic;
    uint16_t msg_len;
    uint8_t *msg;

    explicit mqtt_publish() :
                topic_len(0),
                topic(nullptr),
                msg_len(0),
                msg(nullptr) { }
    ~mqtt_publish()
    {
        if (topic)
            free(topic);
        if (msg)
            free(msg);
    }

    event_description deserialize(uint32_t mqtt_pkt_len,
                                  uint32_t parse_off,
                                  packet &p, logger *log, bool debug);
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("\t Publish: {\n");
        log->verbose("\t\t topic_len: %d\n", topic_len);
        log->verbose("\t\t msg_len: %d\n", msg_len);
        log->verbose("\t }\n");
    #endif
    }
};

struct mqtt_subscribe_req {
    uint16_t msg_id;
    uint16_t topic_len;
    uint8_t *topic;
    uint8_t req_qos;

    explicit mqtt_subscribe_req() : topic_len(0), topic(nullptr) { }
    ~mqtt_subscribe_req()
    {
        if (topic)
            free(topic);
    }

    event_description deserialize(packet &p, logger *log, bool debug);
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("\t Subscribe_Req: {\n");
        log->verbose("\t\t msg_id: %d\n", msg_id);
        log->verbose("\t\t topic_len: %d\n", topic_len);
        log->verbose("\t\t req_qos: %d\n", req_qos);
        log->verbose("\t }\n");
    #endif
    }
};

struct mqtt_subscriber_ack {
    uint16_t msg_id;
    uint8_t granted_qos; // last 2 bits 0 and 1

    event_description deserialize(packet &p, logger *log, bool debug);
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("\t Subscriber_ack: {\n");
        log->verbose("\t\t msg_id: %d\n", msg_id);
        log->verbose("\t\t granted_qos: %d\n", granted_qos);
        log->verbose("\t }\n");
    #endif
    }
};

struct mqtt_connect {
    uint16_t proto_name_len;
    uint8_t *proto_name;
    uint8_t version;
    uint32_t user_name:1;
    uint32_t password:1;
    uint32_t will_retain:1;
    uint32_t qos_level:2;
    uint32_t will:1;
    uint32_t clean_session:1;
    uint32_t reserved:1;
    uint16_t keep_alive;
    uint16_t client_id_len;
    uint8_t *client_id;

    explicit mqtt_connect() :
                proto_name_len(0),
                proto_name(nullptr),
                user_name(0),
                password(0),
                will_retain(0),
                qos_level(0),
                will(0),
                clean_session(0),
                reserved(0),
                client_id_len(0),
                client_id(nullptr) { }
    ~mqtt_connect()
    {
        if (proto_name)
            free(proto_name);
        if (client_id)
            free(client_id);
    }
    event_description deserialize(packet &p, logger *log, bool debug);
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("\t Connect: {\n");
        log->verbose("\t\t proto_name_len: %d\n", proto_name_len);
        log->verbose("\t\t version: %d\n", version);
        log->verbose("\t\t flags: {\n");
        log->verbose("\t\t\t username: %d\n", user_name);
        log->verbose("\t\t\t password: %d\n", password);
        log->verbose("\t\t\t will_retain: %d\n", will_retain);
        log->verbose("\t\t\t qos_level: %d\n", qos_level);
        log->verbose("\t\t\t will: %d\n", will);
        log->verbose("\t\t\t clean_session: %d\n", clean_session);
        log->verbose("\t\t\t reserved: %d\n", reserved);
        log->verbose("\t\t }\n");
        log->verbose("\t\t keepalive: %d\n", keep_alive);
        log->verbose("\t\t client_id_len: %d\n", client_id_len);
        log->verbose("\t }\n");
    #endif
    }
};

struct mqtt_connect_ack {
    uint8_t return_code;
};

/**
 * @brief - implements an MQTT serialize and deserialize.
*/
struct mqtt_hdr {
    uint8_t msg_type; // 4 bits
    uint32_t dup:1; // 1 bit
    uint32_t qos_level:2; // 2 bits
    uint32_t retain:1; // 1 bit
    uint32_t msg_len; // variable length msg_len
    uint32_t parse_off;

    std::shared_ptr<mqtt_connect> conn;
    std::shared_ptr<mqtt_connect_ack> conn_ack;
    std::shared_ptr<mqtt_subscribe_req> sub_req;
    std::shared_ptr<mqtt_subscriber_ack> sub_ack;
    std::shared_ptr<mqtt_publish> pub;

    explicit mqtt_hdr() :
                conn(nullptr),
                conn_ack(nullptr),
                sub_req(nullptr) { }
    ~mqtt_hdr() { }

    int serialize(packet &p);
    event_description deserialize(packet &p, logger *log, bool debug = false);
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("MQTT: {\n");
        log->verbose("\t msg_type: %d\n", msg_type);
        log->verbose("\t dup: %d\n", dup);
        log->verbose("\t qos_level: %d\n", qos_level);
        log->verbose("\t retained: %d\n", retain);
        log->verbose("\t msg_len: %d\n", msg_len);

        if (conn)
            conn->print(log);

        if (conn_ack) {
            log->verbose("\t Connect_Ack: {\n");
            log->verbose("\t\t return_code: %d\n", conn_ack->return_code);
            log->verbose("\t }\n");
        }

        if (sub_req)
            sub_req->print(log);

        if (sub_ack)
            sub_ack->print(log);

        if (pub)
            pub->print(log);

        log->verbose("}\n");
    #endif
    }
};

}

#endif
