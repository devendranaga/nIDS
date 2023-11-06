/**
 * @brief - implements icmp6 serialize and deserialize.
 * 
 * @copyright - 2023-present. All rights reserved. Devendra Naga.
*/
#ifndef __FW_LIB_PROTOCOLS_ICMP6_H__
#define __FW_LIB_PROTOCOLS_ICMP6_H__

#include <vector>
#include <memory>
#include <packet.h>
#include <logger.h>
#include <event_def.h>

namespace firewall {

//
// list of icmp6 types
enum Icmp6_Types {
    Echo_Request = 128,
    Echo_Reply = 129,
    Icmp6_Type_Router_Advertisement = 134,
    Mcast_Listener_Report_Msg_V2 = 143,
    Icmp6_Type_Max = 255,
};

struct icmp6_flags {
    uint32_t managed_addr_conf:1;
    uint32_t other_conf:1;
    uint32_t home_agent:1;
    uint32_t prf:2;
    uint32_t proxy:1;
    uint32_t reserved:1;
};

struct icmp6_option_dns_search_list {
    uint8_t len;
    uint16_t reserved;
    uint32_t lifetime;
    uint8_t domain_name[128];
    uint32_t domain_name_len;
    uint8_t padding[128];
    uint32_t padding_len;

    int serialize(packet &p);
    event_description deserialize(packet &p, logger *log, bool debug = false);
    void print(logger *log);
};

struct icmp6_option_mtu {
    uint8_t len;
    uint16_t reserved;
    uint32_t mtu;

    int serialize(packet &p);
    event_description deserialize(packet &p, logger *log, bool debug = false);
    void print(logger *log);
};

struct icmp6_option_source_link_layer_addr {
    uint8_t len;
    uint8_t lladdr[FW_MACADDR_LEN];

    int serialize(packet &p);
    event_description deserialize(packet &p, logger *log, bool debug = false);
    void print(logger *log);    
};

struct icmp6_router_advertisement {
    uint8_t cur_hoplimit;
    icmp6_flags flags;
    uint16_t router_lifetime;
    uint32_t reachable_time;
    uint32_t retransmit_timer;

    int serialize(packet &p);
    event_description deserialize(packet &p, logger *log, bool debug = false);
    void print(logger *log);
};

struct icmp6_mcast_record {
    uint8_t rec_type;
    uint8_t aux_data_len;
    uint16_t n_sources;
    uint8_t addr[16];

    explicit icmp6_mcast_record() { }
    ~icmp6_mcast_record() { }

    event_description deserialize(packet &p, logger *log, bool debug);
    void print(logger *log)
    {
        log->verbose("\t\t\t McastRecord: {\n");
        log->verbose("\t\t\t\t rec_type: %d\n", rec_type);
        log->verbose("\t\t\t\t aux_data_len: %d\n", aux_data_len);
        log->verbose("\t\t\t\t n_sources: %d\n", n_sources);
        log->verbose("\t\t\t\t addr: "
                        "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
                        "%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
                        addr[0], addr[1], addr[2], addr[3],
                        addr[4], addr[5], addr[6], addr[7],
                        addr[8], addr[9], addr[10], addr[11],
                        addr[12], addr[13], addr[14], addr[15]);
        log->verbose("\t\t\t }\n");
    }

    private:
        const int len_ = 20;
};

struct icmp6_mcast_listener_report_msg_v2 {
    uint16_t reserved;
    uint16_t n_mcast_rec;

    std::vector<icmp6_mcast_record> recs_;

    event_description deserialize(packet &p, logger *log, bool debug);
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("\t\t Mcast_Listener_Report_Msg_V2: {\n");
        log->verbose("\t\t\t reserved: %d\n", reserved);
        log->verbose("\t\t\t n_mcast_rec: %d\n", n_mcast_rec);
        for (auto it : recs_) {
            it.print(log);
        }
        log->verbose("\t\t }\n");
    #endif
    }

    private:
        const int len_ = 20;
};

struct icmp6_echo_req {
    uint16_t id;
    uint16_t seq_no;
    uint16_t data_len;
    uint8_t *data;

    explicit icmp6_echo_req() : data(nullptr) { }
    ~icmp6_echo_req()
    {
        if (data)
            free(data);
    }

    event_description deserialize(packet &p, logger *log, bool debug);
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("\t Echo_Req: {\n");
        log->verbose("\t\t id: %04x\n", id);
        log->verbose("\t\t seq_no: %d\n", seq_no);
        log->verbose("\t\t data_len: %d\n", data_len);
        log->verbose("\t }\n");
    #endif
    }
};

struct icmp6_echo_reply {
    uint16_t id;
    uint16_t seq_no;
    uint16_t data_len;
    uint8_t *data;

    explicit icmp6_echo_reply() : data(nullptr) { }
    ~icmp6_echo_reply()
    {
        if (data)
            free(data);
    }

    event_description deserialize(packet &p, logger *log, bool debug);
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("\t Echo_Reply: {\n");
        log->verbose("\t\t id: %04x\n", id);
        log->verbose("\t\t seq_no: %d\n", seq_no);
        log->verbose("\t\t data_len: %d\n", data_len);
        log->verbose("\t }\n");
    #endif
    }
};

/**
 * @brief - implements ICMP6 serialize and deserialize.
*/
struct icmp6_hdr {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    std::shared_ptr<icmp6_router_advertisement> radv;
    std::shared_ptr<icmp6_mcast_listener_report_msg_v2> mcast_listener_v2;

    std::shared_ptr<icmp6_option_dns_search_list> dns_search_list;
    std::shared_ptr<icmp6_option_mtu> mtu;
    std::shared_ptr<icmp6_option_source_link_layer_addr> s_lladdr;
    std::shared_ptr<icmp6_echo_req> echo_req;
    std::shared_ptr<icmp6_echo_reply> echo_reply;

    explicit icmp6_hdr() :
                    dns_search_list(nullptr),
                    mtu(nullptr),
                    s_lladdr(nullptr),
                    echo_req(nullptr),
                    echo_reply(nullptr)
    { }
    ~icmp6_hdr() { }

    int serialize(packet &p);
    /**
     * @brief - deserialize ICMP6 header.
     *
     * @param [in] p - received packet
     * @param [in] log - logger
     * @param [in] debug - enable/ diable printing packet on console
    */
    event_description deserialize(packet &p, logger *log, bool debug = false);
    void print(logger *log);
};

}

#endif

