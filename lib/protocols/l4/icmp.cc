/**
 * @brief - implements ICMP serialize and deserialize.
 * 
 * @copyright - 2023-present. All rights reserved. Devendra Naga.
*/
#include <cstring>
#include <icmp.h>

namespace firewall {

int icmp_echo_req::serialize(packet &p)
{
    p.serialize(id);
    p.serialize(seq_no);
    if (data_len != 0)
        p.serialize(data, data_len);

    return 0;
}

int icmp_hdr::serialize(packet &p)
{
    uint32_t checksum_off = 0;
    uint32_t off_cur = 0;
    int ret = 0;

    start_off = p.off;

    p.serialize(type);
    p.serialize(code);
    checksum = 0;
    checksum_off = p.off;
    p.serialize(checksum);

    if (echo_req) {
        ret = echo_req->serialize(p);
    }

    end_off = p.off;

    checksum = generate_checksum(p);

    // save the cur offset
    off_cur = p.off;

    // load the checksum offset into the off
    p.off = checksum_off;

    p.serialize(checksum);

    // restore the current offset back
    p.off = off_cur;

    return ret;
}

int icmp_hdr::validate_checksum(const packet &p)
{
    uint32_t i = 0;
    uint32_t csum = 0;
    uint32_t carry = 0;

    //
    // ICMP checksum is calculated from the header till the
    // end of the packet.
    for (i = start_off; i < end_off; i += 2) {
        csum += ((p.buf[i + 1] << 8) | p.buf[i]);
    }
    carry = (csum & 0XFF0000) >> 16;
    csum = csum & 0x00FFFF;

    if ((csum + carry) == 0xFFFF) {
        return 0;
    }

    return -1;
}

int icmp_hdr::generate_checksum(const packet &p)
{
    uint32_t i = 0;
    uint32_t csum = 0;
    uint32_t carry = 0;

    for (i = start_off; i < end_off; i += 2) {
        csum += ((p.buf[i] << 8) | p.buf[i + 1]);
    }
    carry = (csum & 0xFF0000) >> 16;
    csum = csum & 0x00FFFF;

    return ~(csum + carry);
}

event_description icmp_dest_unreachable::parse(packet &p, logger *log, bool debug)
{
    event_description evt_desc;

    p.deserialize(reserved);
    ipv4_h = std::make_shared<ipv4_hdr>();
    if (!ipv4_h)
        return event_description::Evt_Out_Of_Memory;

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

event_description icmp_param_problem::parse(packet &p, logger *log, bool debug)
{
    event_description evt_desc;

    p.deserialize(pointer);
    p.deserialize(unused, sizeof(unused));
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

event_description icmp_timestamp_msg::parse(packet &p, logger *log, bool debug)
{
    //
    // check if the timestamp message header length is too small
    if (p.remaining_len() < ts_len) {
        return event_description::Evt_Icmp_Ts_Msg_Hdr_Len_Too_Short;
    }

    p.deserialize(id);
    p.deserialize(seq_no);
    p.deserialize(orig_ts);
    p.deserialize(rx_ts);
    p.deserialize(tx_ts);

    return event_description::Evt_Parse_Ok;
}

event_description icmp_info_msg::parse(packet &p, logger *log, bool debug)
{
    //
    // check if info message header length is too small
    if (p.remaining_len() < info_len) {
        return event_description::Evt_Icmp_Info_Msg_Hdr_Len_Too_Short;
    }

    p.deserialize(id);
    p.deserialize(seq_no);

    return event_description::Evt_Parse_Ok;
}

event_description icmp_address_mask::parse(packet &p, logger *log, bool debug)
{
    if (p.remaining_len() < len_) {
        return event_description::Evt_Icmp_Addr_Mask_Len_Inval;
    }

    p.deserialize(id);
    p.deserialize(seq_no);
    p.deserialize(addres_mask);

    return event_description::Evt_Parse_Ok;
}

event_description icmp_hdr::deserialize(packet &p, logger *log, bool debug)
{
    //
    // drop if header length is too short
    if (p.remaining_len() <= icmp_hdr_len_) {
        return event_description::Evt_Icmp_Hdr_Len_Too_Short;
    }

    start_off = p.off;

    p.deserialize(type);
    p.deserialize(code);
    p.deserialize(checksum);

    switch (static_cast<Icmp_Type>(type)) {
        case Icmp_Type::Echo_Req: {
            //
            // check the icmp echo request header length
            if (p.remaining_len() < 4) {
                return event_description::Evt_Icmp_Echo_Req_Hdr_Len_Too_Short;
            }

            //
            // Echo Request code must be 0.
            if (code != 0) {
                return event_description::Evt_Icmp_Inval_Echo_Req_Code;
            }

            echo_req = std::make_shared<icmp_echo_req>();
            if (!echo_req)
                return event_description::Evt_Out_Of_Memory;

            p.deserialize(echo_req->id);
            p.deserialize(echo_req->seq_no);
            echo_req->data_len = p.remaining_len();
            //
            // windows might have 32 bytes of data length.
            // linux can go till 48 bytes in length.
            // so if over 48 bytes, generally mean someone is
            // transmitting data via the icmp echo-req and echo-reply
            // messages.
            if (echo_req->data_len > icmp_max_data_len_) {
                return event_description::Evt_Icmp_Covert_Channel_Maybe_Active;
            }

            echo_req->data = (uint8_t *)calloc(1, p.remaining_len());
            if (!echo_req->data)
                return event_description::Evt_Out_Of_Memory;

            std::memcpy(echo_req->data, &p.buf[p.off], p.remaining_len());
        } break;
        case Icmp_Type::Echo_Reply: {
            //
            // check the icmp echo request header length
            if (p.remaining_len() < 4) {
                return event_description::Evt_Icmp_Echo_Reply_Hdr_Len_Too_Short;
            }

            //
            // Echo Reply code must be 0.
            if (code != 0) {
                return event_description::Evt_Icmp_Inval_Echo_Reply_Code;
            }

            echo_reply = std::make_shared<icmp_echo_reply>();
            if (!echo_reply) {
                return event_description::Evt_Unknown_Error;
            }
            p.deserialize(echo_reply->id);
            p.deserialize(echo_reply->seq_no);
            echo_reply->data_len = p.remaining_len();
            //
            // windows might have 32 bytes of data length.
            // linux can go till 48 bytes in length.
            // so if over 48 bytes, generally mean someone is
            // transmitting data via the icmp echo-req and echo-reply
            // messages.
            if (echo_reply->data_len > icmp_max_data_len_) {
                return event_description::Evt_Icmp_Covert_Channel_Maybe_Active;
            }

            echo_reply->data = (uint8_t *)calloc(1, p.remaining_len());
            if (!echo_reply->data) {
                return event_description::Evt_Unknown_Error;
            }
            std::memcpy(echo_reply->data, &p.buf[p.off], p.remaining_len());
        } break;
        case Icmp_Type::Dest_Unreachable: {
            //
            // valid destination unreachable code in range.
            if ((code < static_cast<int>(Icmp_Code_Dest_Unreachable::Net_Unreachable)) ||
                (code > static_cast<int>(Icmp_Code_Dest_Unreachable::Source_Route_Failed))) {
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
            if ((code < static_cast<int>(Icmp_Code_Time_Exceeded::TTL_Exceeded_In_Transit)) ||
                (code > static_cast<int>(Icmp_Code_Time_Exceeded::Frag_Reassembly_Time_Exceeded))) {
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
            param_problem->parse(p, log, debug);
        } break;
        case Icmp_Type::Redirect: {
            //
            // check the code is in range
            if ((code < static_cast<int>(Icmp_Code_Redir_Msg::Redir_For_Host)) ||
                (code > static_cast<int>(Icmp_Code_Redir_Msg::Redir_For_Tos_Nw))) {
                return event_description::Evt_Icmp_Inval_Redir_Msg_Code;
            }
            redir_msg = std::make_shared<icmp_redir_msg>();
            if (!redir_msg) {
                return event_description::Evt_Unknown_Error;
            }
            redir_msg->parse(p, log, debug);
        } break;
        case Icmp_Type::Ts: {
            if (code != 0) {
                return event_description::Evt_Icmp_Inval_Ts_Code;
            }
            ts = std::make_shared<icmp_timestamp_msg>();
            if (!ts) {
                return event_description::Evt_Unknown_Error;
            }
            ts->parse(p, log, debug);
        } break;
        case Icmp_Type::Ts_Reply: {
            if (code != 0) {
                return event_description::Evt_Icmp_Inval_Ts_Code;
            }
            ts_reply = std::make_shared<icmp_timestamp_msg>();
            if (!ts_reply) {
                return event_description::Evt_Unknown_Error;
            }
            ts_reply->parse(p, log, debug);
        } break;
        case Icmp_Type::Info_Req: {
            if (code != 0) {
                return event_description::Evt_Icmp_Inval_Info_Code;
            }
            info_req = std::make_shared<icmp_info_msg>();
            if (!info_req) {
                return event_description::Evt_Unknown_Error;
            }
            info_req->parse(p, log, debug);
        } break;
        case Icmp_Type::Info_Reply: {
            if (code != 0) {
                return event_description::Evt_Icmp_Inval_Info_Code;
            }
            info_resp = std::make_shared<icmp_info_msg>();
            if (!info_resp) {
                return event_description::Evt_Unknown_Error;
            }
            info_resp->parse(p, log, debug);
        } break;
        case Icmp_Type::Address_Mask_Request: {
            addr_mask_req = std::make_shared<icmp_address_mask>();
            if (!addr_mask_req)
                return event_description::Evt_Unknown_Error;

            addr_mask_req->parse(p, log, debug);
        } break;
        case Icmp_Type::Address_Mask_Reply: {
            addr_mask_reply = std::make_shared<icmp_address_mask>();
            if (!addr_mask_reply)
                return event_description::Evt_Unknown_Error;

            addr_mask_reply->parse(p, log, debug);
        } break;
        default:
            return event_description::Evt_Icmp_Invalid_Type;
        break;
    }

    if (debug) {
        print(log);
    }

    end_off = p.off + p.remaining_len();

    if (validate_checksum(p)) {
        return event_description::Evt_Icmp_Inval_Chksum;
    }

    return event_description::Evt_Parse_Ok;
}

void icmp_hdr::print(logger *log)
{
#if defined(FW_ENABLE_DEBUG)
    log->verbose("ICMP: {\n");
    log->verbose("\t type: %d\n", type);
    log->verbose("\t code: %d\n", code);
    log->verbose("\t checksum: 0x%04x\n", checksum);

    if (echo_req)
        echo_req->print(log);
    if (echo_reply)
        echo_reply->print(log);
    if (dest_unreachable)
        dest_unreachable->print("Destination_Unreachable", log);
    if (info_req)
        info_req->print(log);
    if (info_resp)
        info_resp->print(log);
    if (ts)
        ts->print(log);
    if (ts_reply)
        ts_reply->print(log);
    if (redir_msg)
        redir_msg->print(log);
    if (param_problem)
        param_problem->print(log);
    if (time_exceeded)
        time_exceeded->print("Time_Exceeded", log);
    if (source_quench)
        source_quench->print("Source_Quench", log);
    if (addr_mask_req)
        addr_mask_req->print("Address_Mask_Request", log);
    if (addr_mask_reply)
        addr_mask_reply->print("Address_Mask_Reply", log);

    log->verbose("}\n");
#endif
}

void icmp_echo_req::print(logger *log)
{
#if defined(FW_ENABLE_DEBUG)
    log->verbose("\t Echo_Req: {\n");
    log->verbose("\t\t id: 0x%04x\n", id);
    log->verbose("\t\t seq_no: 0x%04x\n", seq_no);
    log->verbose("\t\t data_len: %d\n", data_len);
    log->verbose("\t }\n");
#endif
}

void icmp_dest_unreachable::print(const std::string str, logger *log)
{
#if defined(FW_ENABLE_DEBUG)
    log->verbose("\t %s: {\n", str.c_str());
    log->verbose("\t\t reserved: %d\n", reserved);
    if (ipv4_h)
        ipv4_h->print(log);
    log->verbose("\t\t original datagram: "
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
#endif
}

void icmp_echo_reply::print(logger *log)
{
#if defined(FW_ENABLE_DEBUG)
    log->verbose("\t Echo_Reply: {\n");
    log->verbose("\t\t id: 0x%04x\n", id);
    log->verbose("\t\t seq_no: 0x%04x\n", seq_no);
    log->verbose("\t\t data_len: %d\n", data_len);
    log->verbose("\t }\n");
#endif
}

void icmp_info_msg::print(logger *log)
{
#if defined(FW_ENABLE_DEBUG)
    log->verbose("\t Info: {\n");
    log->verbose("\t\t id: 0x%04x\n", id);
    log->verbose("\t\t seq_no: %d\n", seq_no);
    log->verbose("\t }\n");
#endif
}

void icmp_timestamp_msg::print(logger *log)
{
#if defined(FW_ENABLE_DEBUG)
    log->verbose("\t Timestamp: {\n");
    log->verbose("\t\t id: 0x%04x\n", id);
    log->verbose("\t\t seq_no: %d\n", seq_no);
    log->verbose("\t\t orig_ts: %u\n", orig_ts);
    log->verbose("\t\t rx_ts: %u\n", rx_ts);
    log->verbose("\t\t tx_ts: %u\n", tx_ts);
    log->verbose("\t }\n");
#endif
}

void icmp_param_problem::print(logger *log)
{
#if defined(FW_ENABLE_DEBUG)
    log->verbose("\t Parameter_Problem: {\n");
    log->verbose("\t\t pointer: %d\n", pointer);
    log->verbose("\t\t unused: %02d %02d %02d\n",
                    unused[0], unused[1], unused[2]);
    if (ipv4_h)
        ipv4_h->print(log);
    log->verbose("\t\t original_datagram: "
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
#endif
}

void icmp_redir_msg::print(logger *log)
{
#if defined(FW_ENABLE_DEBUG)
    log->verbose("\t Redirect_Msg: {\n");
    log->verbose("\t\t Gateway internet address: %u\n", gateway_internet_addr);
    if (ipv4_h)
        ipv4_h->print(log);
    log->verbose("\t\t original_datagram: "
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
#endif
}

void icmp_address_mask::print(const std::string str, logger *log)
{
#if defined(FW_ENABLE_DEBUG)
    log->verbose("\t %s: {\n", str.c_str());
    log->verbose("\t\t id: %04x\n", id);
    log->verbose("\t\t seq_no: %04x\n", seq_no);
    log->verbose("\t\t address_mask: %x\n", addres_mask);
    log->verbose("\t }\n");
#endif
}

}

