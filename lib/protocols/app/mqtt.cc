/**
 * @brief - implements MQTT serialize and deserialize.
 * 
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
*/
#include <mqtt.h>

namespace firewall {

event_description mqtt_hdr::deserialize(packet &p, logger *log, bool debug)
{
    event_description evt_desc = event_description::Evt_Unknown_Error;
    uint8_t byte;

    p.deserialize(byte);
    msg_type = (byte & 0xF0) >> 4;

    dup = !!(byte & 0x10);
    qos_level = (byte & 0x06);
    retain = !!(byte & 0x01);

    //
    // TODO: we need to fix the message length, its variable in length
    p.deserialize(byte);
    msg_len = byte;

    parse_off = p.off;

    switch (static_cast<Mqtt_Msg_Type>(msg_type)) {
        case Mqtt_Msg_Type::Connect: {
            conn = std::make_shared<mqtt_connect>();
            if (!conn)
                return event_description::Evt_Out_Of_Memory;

            evt_desc = conn->deserialize(p, log, debug);
        } break;
        case Mqtt_Msg_Type::Connect_Ack: {
            conn_ack = std::make_shared<mqtt_connect_ack>();
            if (!conn_ack)
                return event_description::Evt_Out_Of_Memory;

            p.deserialize(conn_ack->return_code);
            evt_desc = event_description::Evt_Parse_Ok;
        } break;
        case Mqtt_Msg_Type::Subscribe_Req: {
            sub_req = std::make_shared<mqtt_subscribe_req>();
            if (!sub_req)
                return event_description::Evt_Out_Of_Memory;

            evt_desc = sub_req->deserialize(p, log, debug);
        } break;
        case Mqtt_Msg_Type::Subscribe_Ack: {
            sub_ack = std::make_shared<mqtt_subscriber_ack>();
            if (!sub_ack)
                return event_description::Evt_Out_Of_Memory;

            evt_desc = sub_ack->deserialize(p, log, debug);
        } break;
        case Mqtt_Msg_Type::Publish: {
            pub = std::make_shared<mqtt_publish>();
            if (!pub)
                return event_description::Evt_Out_Of_Memory;

            evt_desc = pub->deserialize(msg_len, parse_off, p, log, debug);
        } break;
        case Mqtt_Msg_Type::Ping_Req:
        case Mqtt_Msg_Type::Ping_Response: {
            // 0 bytes length ping request and ping response.
        } break;
        default:
            evt_desc = event_description::Evt_MQTT_Inval_Msg_Type;
    }

    if (debug)
        print(log);

    return evt_desc;
}

event_description mqtt_connect::deserialize(packet &p, logger *log, bool debug)
{
    uint8_t connect_flags;

    p.deserialize(proto_name_len);
    proto_name = (uint8_t *)calloc(1, proto_name_len);
    if (!proto_name)
        return event_description::Evt_Out_Of_Memory;

    p.deserialize(proto_name, proto_name_len);

    p.deserialize(version);
    p.deserialize(connect_flags);

    if (connect_flags & 0x80)
        user_name = 1;

    if (connect_flags & 0x40)
        password = 1;

    if (connect_flags & 0x20)
        will_retain = 1;

    qos_level = (connect_flags & 0x18) >> 3;
    if (connect_flags & 0x04)
        will = 1;

    if (connect_flags & 0x02)
        clean_session = 1;

    if (connect_flags & 0x01)
        reserved = 1;

    p.deserialize(keep_alive);
    p.deserialize(client_id_len);

    client_id  = (uint8_t *)calloc(1, client_id_len);
    if (!client_id)
        return event_description::Evt_Out_Of_Memory;

    p.deserialize(client_id, client_id_len);

    return event_description::Evt_Parse_Ok;
}

event_description mqtt_subscribe_req::deserialize(packet &p, logger *log, bool debug)
{
    p.deserialize(msg_id);
    p.deserialize(topic_len);

    topic = (uint8_t *)calloc(1, topic_len);
    if (!topic)
        return event_description::Evt_Out_Of_Memory;

    p.deserialize(topic, topic_len);
    p.deserialize(req_qos);

    return event_description::Evt_Parse_Ok;
}

event_description mqtt_subscriber_ack::deserialize(packet &p, logger *log, bool debug)
{
    p.deserialize(msg_id);
    p.deserialize(granted_qos);
    granted_qos = granted_qos & 0x03;

    return event_description::Evt_Parse_Ok;
}

event_description mqtt_publish::deserialize(uint32_t mqtt_pkt_len,
                                            uint32_t parse_off,
                                            packet &p, logger *log, bool debug)
{
    p.deserialize(topic_len);

    topic = (uint8_t *)calloc(1, topic_len);
    if (!topic)
        return event_description::Evt_Out_Of_Memory;

    // may be bogus .. check against total length of MQTT frame.
    msg_len = mqtt_pkt_len - (p.off - parse_off);

    if (msg_len > 0) {
        msg = (uint8_t *)calloc(1, msg_len);
        if (!msg)
            return event_description::Evt_Out_Of_Memory;

        p.deserialize(msg, msg_len);
    }

    return event_description::Evt_Parse_Ok;
}

}
