/**
 * @brief - Implements TCP serialize and deserialize.
 * 
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
*/

#include <tcp.h>

namespace firewall {

int tcp_hdr::serialize(packet &p)
{
    return -1;
}

event_description tcp_hdr::deserialize(packet &p, logger *log, bool debug)
{
    event_description evt_des;
    uint8_t byte_1 = 0;
    uint8_t flags = 0;

    //
    // check for short tcp header length
    if (p.remaining_len() < tcp_hdr_len_no_off_) {
        return event_description::Evt_Tcp_Hdrlen_Too_Short;
    }

    p.deserialize(src_port);
    p.deserialize(dst_port);

    //
    // src port cannot be zero
    if (src_port == 0) {
        return event_description::Evt_Tcp_Src_Port_Zero;
    }

    //
    // dst port cannot be zero
    if (dst_port == 0) {
        return event_description::Evt_Tcp_Dst_Port_Zero;
    }
    p.deserialize(seq_no);
    p.deserialize(ack_no);
    p.deserialize(byte_1);
    hdr_len = ((byte_1 & 0xF0) >> 4) * 4;
    p.deserialize(flags);

    reserved = (byte_1 & 0x0E) >> 1;
    ecn = (byte_1 & 0x01);
    cwr = !!(flags & 0x80);
    ecn_echo = !!(flags & 0x40);
    urg = !!(flags & 0x20);
    ack = !!(flags & 0x10);
    psh = !!(flags & 0x08);
    rst = !!(flags & 0x04);
    syn = !!(flags & 0x02);
    fin = !!(flags & 0x01);

    //
    // check for TCP invalid flag bits
    evt_des = check_flags();
    if (evt_des != event_description::Evt_Parse_Ok) {
        return evt_des;
    }

    p.deserialize(window);
    p.deserialize(checksum);
    p.deserialize(urg_ptr);

    // check for possible TCP options
    if (hdr_len > tcp_hdr_len_no_off_) {
        opts = std::make_shared<tcp_hdr_options>();
        if (!opts) {
            return event_description::Evt_Unknown_Error;
        }
        evt_des = opts->deserialize(p,
                                    hdr_len - tcp_hdr_len_no_off_,
                                    log,
                                    debug);
        if (evt_des != event_description::Evt_Parse_Ok) {
            return evt_des;
        }
    }

    debug = true;
    if (debug) {
        print(log);
    }

    return event_description::Evt_Parse_Ok;
}

void tcp_hdr::print(logger *log)
{
#if defined(FW_ENABLE_DEBUG)
    log->verbose("TCP: {\n");
    log->verbose("\tsrc_port: %u\n", src_port);
    log->verbose("\tdst_port: %u\n", dst_port);
    log->verbose("\tseq_no: %u\n", seq_no);
    log->verbose("\tack_no: %u\n", ack_no);
    log->verbose("\thdr_len: %u\n", hdr_len);
    log->verbose("\tflags: {\n");
    log->verbose("\t\tecn: %d\n", ecn);
    log->verbose("\t\tcwr: %d\n", cwr);
    log->verbose("\t\tecn_echo: %d\n", ecn_echo);
    log->verbose("\t\turg: %d\n", urg);
    log->verbose("\t\tack: %d\n", ack);
    log->verbose("\t\tpsh: %d\n", psh);
    log->verbose("\t\trst: %d\n", rst);
    log->verbose("\t\tsyn: %d\n", syn);
    log->verbose("\t\tfin: %d\n", fin);
    log->verbose("\t}\n");
    log->verbose("\twindow: %d\n", window);
    log->verbose("\tchecksum: 0x%04x\n", checksum);
    log->verbose("\turg_ptr: %d\n", urg_ptr);
    if (opts) {
        log->verbose("\tTCP_Options: {\n");
        if (opts->mss) {
            log->verbose("\t\tMSS: {\n");
            log->verbose("\t\t\t %d\n", opts->mss->val);
            log->verbose("\t\t}\n");
        }
        if (opts->sack_permitted) {
            log->verbose("\t\tSACK_Permitted: {\n");
            log->verbose("\t\t\t %d\n", opts->sack_permitted->len);
            log->verbose("\t\t}\n");
        }
        if (opts->ts) {
            log->verbose("\t\tTimestamp: {\n");
            log->verbose("\t\t\tlen: %d\n", opts->ts->len);
            log->verbose("\t\t\tts_val: %u\n", opts->ts->ts_val);
            log->verbose("\t\t\tts_echo_reply: %u\n", opts->ts->ts_echo_reply);
            log->verbose("\t\t}\n");
        }
        if (opts->win_scale) {
            log->verbose("\t\tWin_Scale: {\n");
            log->verbose("\t\t\tlen: %d\n", opts->win_scale->len);
            log->verbose("\t\t\tshift_count: %d\n", opts->win_scale->shift_count);
            log->verbose("\t\t}\n");
        }
        log->verbose("\t}\n");  
    }
    log->verbose("}\n");
#endif
}

event_description tcp_hdr::check_flags()
{
    if (ecn &&
        cwr &&
        ecn_echo &&
        urg &&
        ack &&
        psh &&
        rst &&
        syn &&
        fin) {
        return event_description::Evt_Tcp_Flags_All_Set;
    }
    if ((ecn == 0) &&
        (cwr == 0) &&
        (ecn_echo == 0) &&
        (urg == 0) &&
        (ack == 0) &&
        (psh == 0) &&
        (rst == 0) &&
        (syn == 0) &&
        (fin == 0)) {
        // NULL scan in progress
        return event_description::Evt_Tcp_Flags_None_Set;
    }

    if ((syn == 1) && (fin == 1)) {
        // Both SYN and FIN are set
        return event_description::Evt_Tcp_Flags_SYN_FIN_Set;
    }

    return event_description::Evt_Parse_Ok;
}

event_description tcp_hdr_options::deserialize(packet &p,
                                               uint32_t rem_len,
                                               logger *log,
                                               bool debug)
{
    uint32_t len = p.off + rem_len;

    end_of_opt = false;

    while (p.off < len) {
        if (end_of_opt)
            break;

        switch (static_cast<Tcp_Options_Type>(p.buf[p.off])) {
            case Tcp_Options_Type::Mss: {
                p.off ++;
                //
                // MSS cannot be repeated
                if (mss != nullptr) {
                    return event_description::Evt_Tcp_Opt_MSS_Repeated;
                }

                mss = std::make_shared<tcp_hdr_opt_mss>();
                if (!mss) {
                    return event_description::Evt_Unknown_Error;
                }
                p.deserialize(mss->len);
                p.deserialize(mss->val);
            } break;
            case Tcp_Options_Type::Nop: {
                p.off ++;
            } break;
            case Tcp_Options_Type::SACK_Permitted: {
                p.off ++;
                //
                // SACK cannot be repeated
                if (sack_permitted != nullptr) {
                    return event_description::Evt_Tcp_Opt_SACK_Permitted_Repeated;
                }

                sack_permitted = std::make_shared<tcp_hdr_opt_sack_permitted>();
                if (!sack_permitted)
                    return event_description::Evt_Out_Of_Memory;

                p.deserialize(sack_permitted->len);
            } break;
            case Tcp_Options_Type::Timestamp: {
                p.off ++;
                //
                // TS cannot be repeated
                if (ts != nullptr) {
                    return event_description::EvT_Tcp_Opt_Ts_Repeated;
                }

                ts = std::make_shared<tcp_hdr_opt_timestamp>();
                if (!ts)
                    return event_description::Evt_Out_Of_Memory;

                p.deserialize(ts->len);

                //
                // discard if length is not what expected
                // must be 10 including the header (type + len)
                if (!ts->len_in_range()) {
                    return event_description::Evt_Tcp_Opt_Ts_Inval_Len;
                }
                p.deserialize(ts->ts_val);
                p.deserialize(ts->ts_echo_reply);
            } break;
            case Tcp_Options_Type::Win_Scale: {
                p.off ++;
                //
                // WinScale cannot be repeated
                if (win_scale != nullptr) {
                    return event_description::Evt_Tcp_Opt_WinScale_Repeated;
                }

                win_scale = std::make_shared<tcp_hdr_opt_win_scale>();
                if (!win_scale)
                    return event_description::Evt_Out_Of_Memory;

                p.deserialize(win_scale->len);

                //
                // discard if the length is not what expected
                // must be 10 including the header (type + len)
                if (!win_scale->len_in_range()) {
                    return event_description::Evt_Tcp_Opt_Win_Scale_Inval_Len;
                }
                p.deserialize(win_scale->shift_count);
            } break;
            case Tcp_Options_Type::End_Of_Option_List: {
                //
                // break when the end of opts reached
                p.off ++;
                end_of_opt = true;
            } break;
            default:
                return event_description::Evt_Tcp_Invalid_Option;
        }
    }

    return event_description::Evt_Parse_Ok;
}

}
