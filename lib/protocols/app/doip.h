/**
 * @brief - implements DoIP serialize and deserialize.
 * 
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
*/
#ifndef __FW_LIB_APP_DOIP_H__
#define __FW_LIB_APP_DOIP_H__

#if !defined(FW_ENABLE_AUTOMOTIVE)

#include <memory>
#include <packet.h>
#include <event_def.h>
#include <logger.h>

namespace firewall {

#define VIN_LEN 17
#define EID_LEN 6
#define GID_LEN 6

enum class Doip_Msg_Type {
    Veh_Id_Req = 0x0001,
    Veh_Announce = 0x0004,
    Veh_Id_Resp = 0x0004,
    Routing_Activation_Req = 0x0005,
    DoIP_Entity_Status_Request = 0x4001,
    DoIP_Entity_Status_Response = 0x4002,
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

enum class Doip_Routing_Activation_Type {
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

    int serialize(packet &p);
    /**
     * @brief - implements ARP deserialization.
     * 
     * @param [in] p packet frame.
     * @return returns event_description type.
    */
    event_description deserialize(packet &p, logger *log, bool debug = false);
    void print(logger *log);

    private:
        int min_hdr_len_ = 8;
};

}

#endif

#endif
