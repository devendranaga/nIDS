#ifndef __FW_LIB_PROTOCOLS_APP_SOMEIP_H__
#define __FW_LIB_PROTOCOLS_APP_SOMEIP_H__

#include <vector>
#include <packet.h>
#include <event_def.h>
#include <logger.h>

namespace firewall {

enum SomeIP_Msg_Type {
    Notification = 2,
};

enum Return_Code {
    Ok = 0,
};

struct someip_pdu {
    uint16_t service_id;
    uint16_t method_id;
    uint32_t length;
    uint16_t client_id;
    uint16_t session_id;
    uint8_t version;
    uint8_t interface_version;
    uint32_t msg_type_ack:1;
    uint32_t msg_type_tp:1;
    uint8_t msg_type;
    uint8_t return_code;
    uint8_t payload_len;
    uint8_t *payload;

    explicit someip_pdu() :
                service_id(0),
                method_id(0),
                length(0),
                client_id(0),
                session_id(0),
                version(0),
                interface_version(0),
                msg_type_ack(0),
                msg_type_tp(0),
                msg_type(0),
                return_code(0),
                payload_len(0),
                payload(nullptr) { }
    ~someip_pdu()
    {
        if (payload)
            free(payload);
    }

    inline int get_hdr_len() { return hdr_len_; }

    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("SOME/IP: {\n");
        log->verbose("\t service_id: %04x\n", service_id);
        log->verbose("\t method_id: %04x\n", method_id);
        log->verbose("\t length: %d\n", length);
        log->verbose("\t client_id: %04x\n", client_id);
        log->verbose("\t session_id: %04x\n", session_id);
        log->verbose("\t version: %d\n", version);
        log->verbose("\t interface_version: %d\n", interface_version);
        log->verbose("\t msg_type_ack: %d\n", msg_type_ack);
        log->verbose("\t msg_type_tp: %d\n", msg_type_tp);
        log->verbose("\t msg_type: %d\n", msg_type);
        log->verbose("\t return_code: %d\n", return_code);
        log->verbose("\t payload_len: %d\n", payload_len);
        log->verbose("}\n");
    #endif
    }

    private:
        int hdr_len_ = 16;
};

struct someip_hdr {
    std::vector<someip_pdu> someip_pdu_list_;

    int serialize(packet &p);
    event_description deserialize(packet &p, logger *log, bool debug = false);
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        for (auto it : someip_pdu_list_)
            it.print(log);
    #endif
    }
};

}

#endif
