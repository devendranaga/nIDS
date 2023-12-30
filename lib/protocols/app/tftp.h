#ifndef __FW_LIB_PROTOCOLS_APPS_TFTP_H__
#define __FW_LIB_PROTOCOLS_APPS_TFTP_H__

#include <vector>
#include <memory>
#include <logger.h>
#include <event_def.h>
#include <packet.h>

namespace firewall {

enum class Tftp_Type {
    Read_Req = 1,
    Data = 3,
    Ack = 4,
    Opt_Ack = 6,
};

struct tftp_option {
    std::string name;
    std::string val;

    int serialize(packet &p);
    event_description deserialize(packet &p, logger *log, bool debug = false);
};

struct tftp_read_req {
    std::string src_file;
    std::string type_str;

    std::vector<tftp_option> options;

    int serialize(packet &p);
    event_description deserialize(packet &p, logger *log, bool debug = false);
};

struct tftp_hdr {
    Tftp_Type opcode;

    std::shared_ptr<tftp_read_req> read_req;

    int serialize(packet &p);
    event_description deserialize(packet &p, logger *log, bool debug = false);
};

}

#endif
