/**
 * @brief - implements UDS serialize and deserialize.
 *
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
*/
#ifndef __FW_LIB_APP_UDS_H__
#define __FW_LIB_APP_UDS_H__

#if defined(FW_ENABLE_AUTOMOTIVE)

#include <packet.h>
#include <event_def.h>
#include <logger.h>

namespace firewall {

enum Diag_Service_Id {
    Diag_Sess_Control = 0x10,
    Error = 0x3F,
};

enum Diag_Sess_Control_Type {
    Extended_Diag_Session = 0x03,
    Programming = 0x02,
};

struct diag_sess_control {
    uint8_t type;
    uint32_t parameter_rec;
};

enum Diag_Error_Code {
    Request_Received_Resp_Pending = 0x78,
    Subfunction_Not_Supported_In_Active_Session = 0x7E,
};

struct uds_error {
    uint8_t service_id;
    uint8_t code;
};

struct uds_hdr {
    uint8_t service_id;
    bool is_reply;

    diag_sess_control sess_control;
    uds_error error;

    explicit uds_hdr() : service_id(0), is_reply(false) { }
    ~uds_hdr() { }

    int serialize(packet &p);
    event_description deserialize(packet &p, logger *log, bool debug);
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("UDS: {\n");
        log->verbose("\t service_id: %d\n", service_id);
        switch (static_cast<Diag_Service_Id>(service_id)) {
            case Diag_Service_Id::Diag_Sess_Control: {
                log->verbose("\t Diag_Sess_Control: {\n");
                log->verbose("\t\t type: %d\n", sess_control.type);
                log->verbose("\t }\n");
            } break;
            case Diag_Service_Id::Error: {
                log->verbose("\t Error: {\n");
                log->verbose("\t\t service_id: %d\n", error.service_id);
                log->verbose("\t\t code: %d\n", error.code);
                log->verbose("\t }");
            } break;
            default:
            break;
        }
        log->verbose("}\n");
    #endif
    }
};

}

#endif

#endif

