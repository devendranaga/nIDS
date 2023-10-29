/**
 * @brief - implements DoIP serialize and deserialize.
 *
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
*/
#if defined(FW_ENABLE_AUTOMOTIVE)

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
        } break;
        case Doip_Msg_Type::DoIP_Entity_Status_Response: {
            status_resp = std::make_shared<doip_entity_status_resp>();
            if (!status_resp) {
                return event_description::Evt_Unknown_Error;
            }

            evt_desc = status_resp->deserialize(p, log, debug);
        } break;
        case Doip_Msg_Type::Routing_Activation_Req: {
            route_req = std::make_shared<doip_routing_activation_req>();
            if (!route_req) {
                return event_description::Evt_Unknown_Error;
            }

            evt_desc = route_req->deserialize(p, log, debug);
        } break;
        case Doip_Msg_Type::DoIP_Entity_Status_Request:
        case Doip_Msg_Type::Veh_Id_Req:
        case Doip_Msg_Type::Alive_Check_Req:
        case Doip_Msg_Type::Diag_PowerMode_Info_Request: // 0 byte content
        break;
        case Doip_Msg_Type::Generic_NACK: {
            generic_nack = std::make_shared<doip_generic_nack>();
            if (!generic_nack) {
                return event_description::Evt_Unknown_Error;
            }

            p.deserialize(generic_nack->code);
            evt_desc = event_description::Evt_Parse_Ok;
        } break;
        case Doip_Msg_Type::Alive_Check_Resp: {
            alive_chk_resp = std::make_shared<doip_alive_check_resp>();
            if (!alive_chk_resp) {
                return event_description::Evt_Unknown_Error;
            }

            p.deserialize(alive_chk_resp->source_addr);
            evt_desc = event_description::Evt_Parse_Ok;
        } break;
        case Doip_Msg_Type::Diag_PowerMode_Info_Response: {
            powermode_info_resp = std::make_shared<doip_diag_powermode_info_resp>();
            if (!powermode_info_resp) {
                return event_description::Evt_Unknown_Error;
            }

            p.deserialize(powermode_info_resp->val);
            evt_desc = event_description::Evt_Parse_Ok;
        } break;
        case Doip_Msg_Type::Routing_Activation_Resp: {
            route_resp = std::make_shared<doip_routing_activation_resp>();
            if (!route_resp) {
                return event_description::Evt_Unknown_Error;
            }

            evt_desc = route_resp->deserialize(p, log, debug);
        } break;
        default:
            return event_description::Evt_DoIP_Unsupported_Msg_Type;
        break;
    }

    if (debug)
        print(log);

    return evt_desc;
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

event_description doip_routing_activation_resp::deserialize(packet &p, logger *log, bool debug)
{
    p.deserialize(tester_logical_addr);
    p.deserialize(src_addr);
    p.deserialize(resp_code);
    p.deserialize(reserved);

    return event_description::Evt_Parse_Ok;
}

event_description doip_diag_msg::deserialize(packet &p, logger *log, bool debug)
{
    event_description evt_desc;

    p.deserialize(src_addr);
    p.deserialize(target_addr);
    evt_desc = uds.deserialize(p, log, debug);

    return evt_desc;
}

event_description doip_diag_msg_ack::deserialize(packet &p, logger *log, bool debug)
{
    p.deserialize(src_addr);
    p.deserialize(target_addr);
    p.deserialize(ack_code);

    return event_description::Evt_Parse_Ok;
}

}

#endif
