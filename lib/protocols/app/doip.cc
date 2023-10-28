#include <doip.h>

namespace firewall {

int doip_hdr::serialize(packet &p)
{
    return -1;
}

event_description doip_hdr::deserialize(packet &p, logger *log, bool debug)
{
    event_description evt_desc = event_description::Evt_Unknown_Error;

    if (p.remaining_len() < min_hdr_len_) {
        return event_description::Evt_DoIP_Hdrlen_Too_Small;
    }

    p.deserialize(version);
    p.deserialize(inv_version);
    p.deserialize(type);
    p.deserialize(len);

    //
    // version and inv_version must match
    if (version != static_cast<uint8_t>(~inv_version)) {
        return event_description::Evt_DoIP_Version_Mismatch;
    }

    switch (static_cast<Doip_Msg_Type>(type)) {
        case Doip_Msg_Type::Veh_Announce: {
            veh_announce = std::make_shared<doip_veh_announce_msg>();
            if (!veh_announce) {
                return event_description::Evt_Unknown_Error;
            }

            evt_desc = veh_announce->deserialize(p, log, debug);
            if (evt_desc != event_description::Evt_Parse_Ok) {
                return evt_desc;
            }
        } break;
        case Doip_Msg_Type::DoIP_Entity_Status_Request: { // 0 length msg
        } break;
        case Doip_Msg_Type::DoIP_Entity_Status_Response: {
            status_resp = std::make_shared<doip_entity_status_resp>();
            if (!status_resp) {
                return event_description::Evt_Unknown_Error;
            }

            evt_desc = status_resp->deserialize(p, log, debug);
            if (evt_desc != event_description::Evt_Parse_Ok) {
                return evt_desc;
            }
        } break;
        case Doip_Msg_Type::Veh_Id_Req: {
        } break;
        case Doip_Msg_Type::Routing_Activation_Req: {
            route_req = std::make_shared<doip_routing_activation_req>();
            if (!route_req) {
                return event_description::Evt_Unknown_Error;
            }

            evt_desc = route_req->deserialize(p, log, debug);
            if (evt_desc != event_description::Evt_Parse_Ok) {
                return evt_desc;
            }
        } break;
        default:
            return event_description::Evt_DoIP_Unsupported_Msg_Type;
        break;
    }

    return event_description::Evt_Parse_Ok;
}

event_description doip_veh_announce_msg::deserialize(packet &p, logger *log, bool debug)
{
    if (p.remaining_len() < min_hdr_len_) {
        return event_description::Evt_DoIP_Veh_Announce_Too_Small;
    }

    p.deserialize(vin, VIN_LEN);
    p.deserialize(logical_addr);
    p.deserialize(eid, EID_LEN);
    p.deserialize(gid, GID_LEN);
    p.deserialize(further_action_required);

    return event_description::Evt_Parse_Ok;
}

event_description doip_entity_status_resp::deserialize(packet &p, logger *log, bool debug)
{
    if (p.remaining_len() < min_hdr_len_) {
        return event_description::Evt_DoIP_Entity_Status_Response_Too_Small;
    }

    p.deserialize(node_type);
    p.deserialize(max_concurrent_sockets);
    p.deserialize(currently_open_sockets);
    p.deserialize(max_data_size);

    return event_description::Evt_Parse_Ok;
}

event_description doip_routing_activation_req::deserialize(packet &p, logger *log, bool debug)
{
    if (p.remaining_len() < min_hdr_len_) {
        return event_description::Evt_DoIP_Route_Activation_Req_Too_Small;
    }

    p.deserialize(src_addr);
    p.deserialize(activation_type);
    p.deserialize(reserved_by_iso);
    p.deserialize(reserved_by_oem);

    return event_description::Evt_Parse_Ok;
}

}
