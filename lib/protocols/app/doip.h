/**
 * @brief - implements DoIP serialize and deserialize.
 * 
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
*/
#ifndef __FW_LIB_APP_DOIP_H__
#define __FW_LIB_APP_DOIP_H__

#if defined(FW_ENABLE_AUTOMOTIVE)

#include <memory>
#include <packet.h>
#include <event_def.h>
#include <logger.h>
#include <uds.h>

namespace firewall {

#define VIN_LEN 17
#define EID_LEN 6
#define GID_LEN 6

enum class Doip_Msg_Type {
    Generic_NACK = 0x0000,
    Veh_Id_Req = 0x0001,
    Veh_Announce = 0x0004,
    Veh_Id_Resp = 0x0004,
    Routing_Activation_Req = 0x0005,
    Routing_Activation_Resp = 0x0006,
    Alive_Check_Req = 0x0007,
    Alive_Check_Resp = 0x0008,
    DoIP_Entity_Status_Request = 0x4001,
    DoIP_Entity_Status_Response = 0x4002,
    Diag_PowerMode_Info_Request = 0x4003,
    Diag_PowerMode_Info_Response = 0x4004,
    Diag_Msg = 0x8001,
};

struct doip_veh_announce_msg {
    uint8_t vin[VIN_LEN];
    uint16_t logical_addr;
    uint8_t eid[EID_LEN];
    uint8_t gid[GID_LEN];
    uint8_t further_action_required;

    event_description deserialize(packet &p, logger *log, bool debug);
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("\t Announce_Msg: {\n");
        log->verbose("\t\t VIN: ");
        for (auto i = 0; i < VIN_LEN; i ++) {
            fprintf(stderr, "%02x", vin[i]);
        }
        fprintf(stderr, "\n");
        log->verbose("\t\t logical_addr: %u\n", logical_addr);
        log->verbose("\t\t EID: %02x%02x%02x%02x%02x%02x\n",
                        eid[0], eid[1],
                        eid[2], eid[3],
                        eid[4], eid[5]);
        log->verbose("\t\t GID: %02x%02x%02x%02x%02x%02x\n",
                        gid[0], gid[1],
                        gid[2], gid[3],
                        gid[4], gid[5]);
        log->verbose("\t\t Futher_action_required: %d\n", further_action_required);
        log->verbose("\t }\n");
    #endif
    }

    private:
        int min_hdr_len_ = 32;
};

enum DoIP_Node_Type {
    DoIP_Gateway = 0,
};

struct doip_entity_status_resp {
    uint8_t node_type;
    uint8_t max_concurrent_sockets;
    uint8_t currently_open_sockets;
    uint32_t max_data_size;

    event_description deserialize(packet &p, logger *log, bool debug);
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("\t Status_Resp: {\n");
        log->verbose("\t\t node_type: %d\n", node_type);
        log->verbose("\t\t max_concurrent_sockets: %d\n", max_concurrent_sockets);
        log->verbose("\t\t currently_open_sockets: %d\n", currently_open_sockets);
        log->verbose("\t\t max_data_size: %d\n", max_data_size);
        log->verbose("\t }\n");
    #endif
    }

    private:
        int min_hdr_len_ = 7;
};

enum class DoIP_Routing_Activation_Type {
    Default = 0,
};

struct doip_routing_activation_req {
    uint16_t src_addr;
    uint8_t activation_type;
    uint32_t reserved_by_iso;
    uint32_t reserved_by_oem;

    event_description deserialize(packet &p, logger *log, bool debug);
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("\t Routing_Activation_Req: {\n");
        log->verbose("\t\t src_addr: %u\n", src_addr);
        log->verbose("\t\t activation_type: %d\n", activation_type);
        log->verbose("\t\t reserved_by_iso: %u\n", reserved_by_iso);
        log->verbose("\t\t reserved_by_oem: %u\n", reserved_by_oem);
        log->verbose("\t }\n");
    #endif
    }

    private:
        int min_hdr_len_ = 11;
};

enum class DoIP_Routing_Activation_Resp_Code {
    Success = 0x10,
};

struct doip_routing_activation_resp {
    uint16_t tester_logical_addr;
    uint16_t src_addr;
    uint8_t resp_code;
    uint32_t reserved;

    event_description deserialize(packet &p, logger *log, bool debug);
    void print(logger *log)
    {
        log->verbose("\t Routing_Activation_Resp: {\n");
        log->verbose("\t\t tester_logical_addr: %d\n", tester_logical_addr);
        log->verbose("\t\t src_addr: %d\n", src_addr);
        log->verbose("\t\t resp_code: %d\n", resp_code);
        log->verbose("\t\t reserved: %d\n", reserved);
        log->verbose("\t }\n");
    }
};

struct doip_generic_nack {
    uint8_t code;

    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("\t Generic_NACK: {\n");
        log->verbose("\t\t code: %d\n", code);
        log->verbose("\t }\n");
    #endif
    }
};

struct doip_alive_check_resp {
    uint16_t source_addr;

    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("\t Alive_Check_Response: {\n");
        log->verbose("\t source_addr: %04x\n", source_addr);
        log->verbose("\t }\n");
    #endif
    }
};

struct doip_diag_powermode_info_resp {
    uint8_t val;

    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("\t Power_Mode_Info_Resp: {\n");
        log->verbose("\t\t val: %d\n", val);
        log->verbose("\t }\n");
    #endif
    }
};

struct doip_diag_msg {
    uint16_t src_addr;
    uint16_t target_addr;

    uds_hdr uds;
    event_description deserialize(packet &p, logger *log, bool debug);
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("\t Diag_Msg: {\n");
        log->verbose("\t\t src_addr: %d\n", src_addr);
        log->verbose("\t\t target_addr: %d\n", target_addr);
        uds.print(log);
        log->verbose("\t }\n");
    #endif
    }
};

struct doip_diag_msg_ack {
    uint16_t src_addr;
    uint16_t target_addr;
    uint8_t ack_code;

    event_description deserialize(packet &p, logger *log, bool debug);
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("\t Diag_MSg_Ack: {\n");
        log->verbose("\t\t src_addr: %d\n", src_addr);
        log->verbose("\t\t target_addr: %d\n", target_addr);
        log->verbose("\t\t ack_code: %d\n",ack_code);
        log->verbose("\t }\n");
    #endif
    }
};

/**
 * @brief - implements DoIP serialize and deserialize.
*/
struct doip_hdr {
    uint8_t version;
    uint8_t inv_version;
    uint16_t type; // type of Doip_Msg_Type
    uint32_t len;

    std::shared_ptr<doip_veh_announce_msg> veh_announce;
    std::shared_ptr<doip_entity_status_resp> status_resp;
    std::shared_ptr<doip_routing_activation_req> route_req;
    std::shared_ptr<doip_generic_nack> generic_nack;
    std::shared_ptr<doip_alive_check_resp> alive_Chk_resp;
    std::shared_ptr<doip_diag_powermode_info_resp> powermode_info_resp;
    std::shared_ptr<doip_routing_activation_resp> route_resp;
    std::shared_ptr<doip_diag_msg> diag_msg;
    std::shared_ptr<doip_diag_msg_ack> diag_msg_ack;

    int serialize(packet &p);
    /**
     * @brief - implements ARP deserialization.
     * 
     * @param [in] p packet frame.
     * @return returns event_description type.
    */
    event_description deserialize(packet &p, logger *log, bool debug = false);
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("DoIP_Hdr: {\n");
        log->verbose("\t version: %02x\n", version);
        log->verbose("\t inv_version: %02x\n", inv_version);
        log->verbose("\t type: %04x\n", type);
        log->verbose("\t len: %d\n", len);

        if (veh_announce)
            veh_announce->print(log);

        if (status_resp)
            status_resp->print(log);

        if (route_req)
            route_req->print(log);

        if (generic_nack)
            generic_nack->print(log);

        if (alive_chk_resp)
            alive_Chk_resp->print(log);

        if (powermode_info_resp)
            powermode_info_resp->print(log);

        if (route_resp)
            route_resp->print(log);

        if (diag_msg)
            diag_msg->print(log);

        if (diag_msg_ack)
            diag_msg_ack->print(log);

        log->verbose("}\n");
    #endif
    }

    private:
        int min_hdr_len_ = 8;
};

}

#endif

#endif
