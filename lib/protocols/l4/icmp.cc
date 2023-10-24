/**
 * @brief - implements ICMP serialize and deserialize.
 * 
 * @copyright - 2023-present. All rights reserved. Devendra Naga.
*/
#include <cstring>
#include <icmp.h>

namespace firewall {

int icmp_hdr::serialize(packet &p)
{
    return -1;
}

event_description icmp_dest_unreachable::parse(packet &p, logger *log, bool debug)
{
    event_description evt_desc;

    p.deserialize(reserved);
    ipv4_h = std::make_shared<ipv4_hdr>();
    if (!ipv4_h) {
        return event_description::Evt_Unknown_Error;
    }

    evt_desc = ipv4_h->deserialize(p, log, debug);
    if (evt_desc != event_description::Evt_Parse_Ok) {
        return evt_desc;
    }

    std::memcpy(original_datagram, &p.buf[p.off], p.remaining_len());

    return event_description::Evt_Parse_Ok;
}

event_description icmp_redir_msg::parse(packet &p, logger *log, bool debug)
{
    event_description evt_desc;

    p.deserialize(gateway_internet_addr);
    ipv4_h = std::make_shared<ipv4_hdr>();
    if (!ipv4_h) {
        return event_description::Evt_Unknown_Error;
    }

    evt_desc = ipv4_h->deserialize(p, log, debug);
    if (evt_desc != event_description::Evt_Parse_Ok) {
        return evt_desc;
    }

    std::memcpy(original_datagram, &p.buf[p.off], p.remaining_len());

    return event_description::Evt_Parse_Ok;
}

event_description icmp_hdr::deserialize(packet &p, logger *log, bool debug)
{
    p.deserialize(type);
    p.deserialize(code);
    p.deserialize(checksum);

    switch (static_cast<Icmp_Type>(type)) {
        case Icmp_Type::Echo_Req: {
            echo_req = std::make_shared<icmp_echo_req>();
            if (!echo_req) {
                return event_description::Evt_Unknown_Error;
            }
            p.deserialize(echo_req->id);
            p.deserialize(echo_req->seq_no);
            echo_req->data_len = p.remaining_len();
            echo_req->data = (uint8_t *)calloc(1, p.remaining_len());
            if (!echo_req->data) {
                return event_description::Evt_Unknown_Error;
            }
            std::memcpy(echo_req->data, &p.buf[p.off], p.remaining_len());
        } break;
        case Icmp_Type::Echo_Reply: {
            echo_reply = std::make_shared<icmp_echo_reply>();
            if (!echo_reply) {
                return event_description::Evt_Unknown_Error;
            }
            p.deserialize(echo_reply->id);
            p.deserialize(echo_reply->seq_no);
            echo_reply->data_len = p.remaining_len();
            echo_reply->data = (uint8_t *)calloc(1, p.remaining_len());
            if (!echo_reply->data) {
                return event_description::Evt_Unknown_Error;
            }
            std::memcpy(echo_reply->data, &p.buf[p.off], p.remaining_len());
        } break;
        case Icmp_Type::Dest_Unreachable: {
            //
            // valid destination unreachable code in range.
            if ((type < static_cast<int>(Icmp_Code_Dest_Unreachable::Net_Unreachable)) ||
                (type > static_cast<int>(Icmp_Code_Dest_Unreachable::Source_Route_Failed))) {
                return event_description::Evt_Icmp_Dest_Unreachable_Invalid_Code;
            }
            dest_unreachable = std::make_shared<icmp_dest_unreachable>();
            if (!dest_unreachable) {
                return event_description::Evt_Unknown_Error;
            }
            dest_unreachable->parse(p, log, debug);
        } break;
        case Icmp_Type::Source_Quench: {
            source_quench = std::make_shared<icmp_dest_unreachable>();
            if (!source_quench) {
                return event_description::Evt_Unknown_Error;
            }
            source_quench->parse(p, log, debug);
        } break;
        case Icmp_Type::Time_Exceeded: {
            //
            // validate time exceeded code in range.
            if ((type < static_cast<int>(Icmp_Code_Time_Exceeded::TTL_Exceeded_In_Transit)) ||
                (type > static_cast<int>(Icmp_Code_Time_Exceeded::Frag_Reassembly_Time_Exceeded))) {
                return event_description::Evt_Icmp_Time_Exceeded_Invalid_Code;
            }
            time_exceeded = std::make_shared<icmp_dest_unreachable>();
            if (!time_exceeded) {
                return event_description::Evt_Unknown_Error;
            }
            time_exceeded->parse(p, log, debug);
        } break;
        case Icmp_Type::Parameter_Problem: {
            param_problem = std::make_shared<icmp_param_problem>();
            if (!param_problem) {
                return event_description::Evt_Unknown_Error;
            }
            p.deserialize(param_problem->pointer);
            p.deserialize(param_problem->unused, sizeof(param_problem->unused));
            param_problem->ipv4_h = std::make_shared<ipv4_hdr>();
            if (!param_problem->ipv4_h) {
                return event_description::Evt_Unknown_Error;
            }
            param_problem->ipv4_h->deserialize(p, log, debug);
            std::memcpy(param_problem->original_datagram,
                        &p.buf[p.off], p.remaining_len());
        } break;
        case Icmp_Type::Redirect: {
        } break;
        case Icmp_Type::Ts: {
            
        } break;
        case Icmp_Type::Ts_Reply: {

        } break;
        case Icmp_Type::Info_Req: {

        } break;
        case Icmp_Type::Info_Reply: {

        } break;
        default:
            return event_description::Evt_Icmp_Invalid_Type;
        break;
    }

    if (debug) {
        print(log);
    }

    return event_description::Evt_Parse_Ok;
}

void icmp_hdr::print(logger *log)
{
    log->verbose("ICMP: {\n");
    log->verbose("\t type: %d\n", type);
    log->verbose("\t code: %d\n", code);
    log->verbose("\t checksum: 0x%04x\n", checksum);

    if (echo_req)
        echo_req->print(log);
    if (echo_reply)
        echo_reply->print(log);
    if (dest_unreachable)
        dest_unreachable->print(log);

    log->verbose("}\n");
}

void icmp_echo_req::print(logger *log)
{
    log->verbose("\t Echo_Req: {\n");
    log->verbose("\t\t id: 0x%04x\n", id);
    log->verbose("\t\t seq_no: 0x%04x\n", seq_no);
    log->verbose("\t\t data_len: %d\n", data_len);
    log->verbose("\t }\n");
}

void icmp_dest_unreachable::print(logger *log)
{
    log->verbose("\t Dest_Unrechable: {\n");
    log->verbose("\t reserved: %d\n", reserved);
    if (ipv4_h)
        ipv4_h->print(log);
    log->verbose("\t original datagram: "
                        "%02x %02x %02x %02x %02x %02x %02x %02x\n",
                        original_datagram[0],
                        original_datagram[1],
                        original_datagram[2],
                        original_datagram[3],
                        original_datagram[4],
                        original_datagram[5],
                        original_datagram[6],
                        original_datagram[7]);
    log->verbose("\t }\n");
}

void icmp_echo_reply::print(logger *log)
{
    log->verbose("\t Echo_Reply: {\n");
    log->verbose("\t\t id: 0x%04x\n", id);
    log->verbose("\t\t seq_no: 0x%04x\n", seq_no);
    log->verbose("\t\t data_len: %d\n", data_len);
    log->verbose("\t }\n");
}

}
