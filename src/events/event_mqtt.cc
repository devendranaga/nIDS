/**
 * @brief - implements MQTT publisher.
 *
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
*/
#include <config.h>
#include <event_mqtt.h>

namespace firewall {

#define MQTT_PUBLISHER_NAME "mqtt_pub: "

mqtt_publisher::mqtt_publisher() : init_ok_(false) { }

mqtt_publisher::~mqtt_publisher()
{
    if (init_ok_)
        MQTTClient_disconnect(client_, timeout_ms_);

    init_ok_ = false;
}

int mqtt_publisher::init(logger *log)
{
    firewall_config *conf = firewall_config::instance();
    std::string server_uri;
    int ret;

    log_ = log;

    conn_opts_ = MQTTClient_connectOptions_initializer;

    server_uri = conf->evt_config.mqtt.ipaddr + ":" +
                 std::to_string(conf->evt_config.mqtt.port);

    ret = MQTTClient_create(&client_,
                            server_uri.c_str(),
                            client_id_.c_str(),
                            MQTTCLIENT_PERSISTENCE_NONE,
                            nullptr);
    if (ret != MQTTCLIENT_SUCCESS) {
        log_->error("%s: failed to create "
                    "the MQTT client %s with client_id : %s\n",
                    MQTT_PUBLISHER_NAME, server_uri.c_str(), client_id_.c_str());
        return -1;
    }

    conn_opts_.keepAliveInterval = keepalive_intvl_s_;
    conn_opts_.cleansession = 1;
    ret = MQTTClient_connect(client_, &conn_opts_);
    if (ret != MQTTCLIENT_SUCCESS) {
        log_->error("%s: failed to connect with the broker\n", MQTT_PUBLISHER_NAME);
        return -1;
    }

    init_ok_ = true;

    return 0;
}

int mqtt_publisher::write(uint8_t *evt_msg, uint32_t evt_msg_len)
{
    MQTTClient_message msg = MQTTClient_message_initializer;
    MQTTClient_deliveryToken token;
    firewall_config *conf = firewall_config::instance();
    int ret;

    msg.payload = evt_msg;
    msg.payloadlen = evt_msg_len;
    msg.qos = qos_;
    msg.retained = 0;

    ret = MQTTClient_publishMessage(client_, conf->evt_config.mqtt.topic_name.c_str(), &msg, &token);
    if (ret != MQTTCLIENT_SUCCESS) {
        log_->error("%s: publishing message failed\n", MQTT_PUBLISHER_NAME);
        return -1;
    }

    ret = MQTTClient_waitForCompletion(client_, token, timeout_ms_);
    if (ret != MQTTCLIENT_SUCCESS) {
        log_->error("%s: failed to publish message. timeout.\n", MQTT_PUBLISHER_NAME);
        return -1;
    }

    return 0;
}

}
