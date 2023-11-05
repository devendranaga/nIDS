/**
 * @brief - implements icmp6 serialize and deserialize.
 * 
 * @copyright - 2023-present. All rights reserved. Devendra Naga.
*/
#include <icmp6.h>

namespace firewall {

int icmp6_hdr::serialize(packet &p)
{
    return -1;
}

event_description icmp6_hdr::deserialize(packet &p, logger *log, bool debug)
{
    event_description evt_desc = event_description::Evt_Unknown_Error;

    p.deserialize(type);
    if ((type < static_cast<uint8_t>(Icmp6_Types::Echo_Request)) ||
        (type >= static_cast<uint8_t>(Icmp6_Types::Icmp6_Type_Max))) {
        return event_description::Evt_Icmp6_Icmp6_Type_Unsupported;
    }

    p.deserialize(code);
    p.deserialize(checksum);

    switch (type) {
        case Icmp6_Types::Mcast_Listener_Report_Msg_V2: {
            mcast_listener_v2 = std::make_shared<icmp6_mcast_listener_report_msg_v2>();
            if (!mcast_listener_v2) {
                return event_description::Evt_Unknown_Error;
            }

            evt_desc = mcast_listener_v2->deserialize(p, log, debug);
        } break;
        case Icmp6_Types::Echo_Request: {
            echo_req = std::make_shared<icmp6_echo_req>();
            if (!echo_req)
                return event_description::Evt_Unknown_Error;

            evt_desc = echo_req->deserialize(p, log, debug);
        } break;
        case Icmp6_Types::Echo_Reply: {
            echo_reply = std::make_shared<icmp6_echo_reply>();
            if (!echo_reply)
                return event_description::Evt_Unknown_Error;

            evt_desc = echo_reply->deserialize(p, log, debug);
        } break;
        default:
            evt_desc = event_description::Evt_Unknown_Error;
        break;
    }

    if (debug) {
        print(log);
    }

    return evt_desc;
}

void icmp6_hdr::print(logger *log)
{
#if defined(FW_ENABLE_DEBUG)
    log->verbose("ICMP6: {\n");
    log->verbose("\t type: %d\n", type);
    log->verbose("\t code: %d\n", code);
    log->verbose("\t checksum: 0x%04x\n", checksum);
    if (echo_reply)
        echo_reply->print(log);
    if (echo_req)
        echo_req->print(log);
    log->verbose("}\n");
#endif
}

event_description icmp6_mcast_listener_report_msg_v2::deserialize(packet &p, logger *log, bool debug)
{
    event_description evt_desc;
    int i;

    p.deserialize(reserved);
    p.deserialize(n_mcast_rec);

    //
    // remaining len is smaller than the multicast list given
    if (p.remaining_len() < n_mcast_rec * len_) {
        return event_description::Evt_Icmp6_Mcast_Listener_Inval_Rec_Len;
    }

    for (i = 0; i < n_mcast_rec; i ++) {
        icmp6_mcast_record rec;

        evt_desc = rec.deserialize(p, log, debug);
        if (evt_desc != event_description::Evt_Parse_Ok)
            return evt_desc;

        recs_.push_back(rec);
    }

    return event_description::Evt_Parse_Ok;
}

event_description icmp6_mcast_record::deserialize(packet &p, logger *log, bool debug)
{
    //
    // Range check is already taken care in the caller
    p.deserialize(rec_type);
    p.deserialize(aux_data_len);
    p.deserialize(n_sources);
    p.deserialize(addr, sizeof(addr));

    return event_description::Evt_Parse_Ok;
}

event_description icmp6_echo_req::deserialize(packet &p, logger *log, bool debug)
{
    p.deserialize(id);
    p.deserialize(seq_no);
    data_len = p.remaining_len();
    data = (uint8_t *)calloc(1, data_len);
    if (!data)
        return event_description::Evt_Unknown_Error;

    p.deserialize(data, data_len);

    return event_description::Evt_Parse_Ok;
}

event_description icmp6_echo_reply::deserialize(packet &p, logger *log, bool debug)
{
    p.deserialize(id);
    p.deserialize(seq_no);
    data_len = p.remaining_len();
    data = (uint8_t *)calloc(1, data_len);
    if (!data)
        return event_description::Evt_Unknown_Error;

    p.deserialize(data, data_len);

    return event_description::Evt_Parse_Ok;
}

}
