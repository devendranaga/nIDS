#include <tftp.h>

namespace firewall {

static int get_value(packet &p, std::string &in_str)
{
    char buf[513];
    int len = 0;

    while (p.buf[p.off] != '0') {
        buf[len] = p.buf[p.off];
        len ++;
        p.off ++;

        if (len >= 512)
            return -1;
    }

    buf[len] = '\0';

    in_str = std::string(buf);

    return 0;
}

event_description tftp_option::deserialize(packet &p, logger *log, bool debug)
{
    int ret;

    ret = get_value(p, name);
    if (ret != 0)
        return event_description::Evt_Unknown_Error;

    ret = get_value(p, val);
    if (ret != 0)
        return event_description::Evt_Unknown_Error;

    return event_description::Evt_Parse_Ok;
}

event_description tftp_hdr::deserialize(packet &p, logger *log, bool debug)
{
    event_description evt_desc = event_description::Evt_Unknown_Error;
    uint16_t byte2;

    p.deserialize(byte2);
    opcode = static_cast<Tftp_Type>(byte2);

    if (opcode == Tftp_Type::Read_Req) {
        read_req = std::make_shared<tftp_read_req>();
        if (!read_req)
            return event_description::Evt_Out_Of_Memory;

        evt_desc = read_req->deserialize(p, log, debug);
    }

    return evt_desc;
}

event_description tftp_read_req::deserialize(packet &p, logger *log, bool debug)
{
    event_description evt_desc = event_description::Evt_Unknown_Error;
    int ret;

    ret = get_value(p, src_file);
    if (ret != 0)
        return event_description::Evt_Unknown_Error;

    ret = get_value(p, type_str);
    if (ret != 0)
        return event_description::Evt_Unknown_Error;

    while ((int)(p.off) < p.remaining_len()) {
        tftp_option opt;

        evt_desc = opt.deserialize(p, log, debug);
        if (evt_desc != event_description::Evt_Parse_Ok)
            return evt_desc;

        options.push_back(opt);
    }

    return evt_desc;
}

}
