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

event_description icmp_hdr::deserialize(packet &p, logger *log, bool debug)
{
    p.deserialize(type);
    p.deserialize(code);
    p.deserialize(checksum);

    switch (static_cast<Icmp_Type>(type)) {
        case Icmp_Type::Echo_Req: {
            echo_req = (icmp_echo_req *)calloc(1, sizeof(icmp_echo_req));
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
            echo_reply = (icmp_echo_reply *)calloc(1, sizeof(icmp_echo_reply));
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

void icmp_echo_reply::print(logger *log)
{
    log->verbose("\t Echo_Reply: {\n");
    log->verbose("\t\t id: 0x%04x\n", id);
    log->verbose("\t\t seq_no: 0x%04x\n", seq_no);
    log->verbose("\t\t data_len: %d\n", data_len);
    log->verbose("\t }\n");
}

}
