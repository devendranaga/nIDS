/**
 * @brief - implements MQTT subscriber.
 * 
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
*/
#include <cstring>
#include <MQTTClient.h>
#include <fw_ctl_mqtt.h>

namespace firewall {

static int msg_rx(void *context, char *topicname, int topiclen, MQTTClient_message *msg)
{
    queue_msg m;

    std::memcpy(m.msg, msg->payload, msg->payloadlen);
    m.msg_len = msg->payloadlen;

    global_queue::instance()->push(m);

    MQTTClient_freeMessage(&msg);
    MQTTClient_free(topicname);

    return 1;
}

static void connection_lost(void *context, char *cause)
{
    printf("connection lost reason : %s\n", cause ? cause : "Unknown");
}

int mqtt_listen(const std::string &uri, const std::string &topic)
{
    MQTTClient client;
    MQTTClient_connectOptions conn_opt = MQTTClient_connectOptions_initializer;
    const std::string client_id = "FWCTL";
    const int qos = 1;
    int ret;

    ret = MQTTClient_create(&client,
                            uri.c_str(),
                            client_id.c_str(),
                            MQTTCLIENT_PERSISTENCE_NONE,
                            nullptr);
    if (ret != MQTTCLIENT_SUCCESS) {
        return -1;
    }

    ret = MQTTClient_setCallbacks(client, nullptr, connection_lost, msg_rx, nullptr);
    if (ret != MQTTCLIENT_SUCCESS) {
        return -1;
    }

    conn_opt.keepAliveInterval = 20;
    conn_opt.cleansession = 1;

    ret = MQTTClient_connect(client, &conn_opt);
    if (ret != MQTTCLIENT_SUCCESS) {
        return -1;
    }

    ret = MQTTClient_subscribe(client, topic.c_str(), qos);
    if (ret != MQTTCLIENT_SUCCESS) {
        return -1;
    }

    return 0;
}

}
