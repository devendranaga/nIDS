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
    uint8_t flags = 0;

    //
    // check for short tcp header length
    if (p.remaining_len() < tcp_hdr_len_no_off_) {
        return event_description::Evt_Tcp_Hdrlen_Too_Short;
    }

    p.deserialize(src_port);
    p.deserialize(dst_port);
    p.deserialize(seq_no);
    p.deserialize(ack_no);
    p.deserialize(hdr_len);
    p.deserialize(flags);

    reserved = (hdr_len & 0x0E) >> 1;
    ecn = (hdr_len & 0x01);
    hdr_len = (hdr_len & 0x0F) >> 4;
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

    debug = true;
    if (debug) {
        print(log);
    }

    return event_description::Evt_Parse_Ok;
}

void tcp_hdr::print(logger *log)
{
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
    log->verbose("}\n");
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
        return event_description::Evt_Tcp_Flags_None_Set;
    }

    return event_description::Evt_Parse_Ok;
}

}
