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
    Router_Solicitation = 133,
    Icmp6_Type_Router_Advertisement = 134,
    Neighbor_Solitication = 135,
    Neighbor_Advertisement = 136,
    Mcast_Listener_Report_Msg_V2 = 143,
    Icmp6_Type_Max = 255,
};

enum class Icmp6_Option_Types {
    Source_Link_Layer_Address = 0x1,
    Target_Link_Layer_Address = 0x2,
    Prefix_Information = 0x3,
    MTU = 0x5,
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

struct icmp6_option_prefix_information_flags {
    uint32_t onlink:1;
    uint32_t autonomous_addr_conf:1;
    uint32_t router_addr:1;
    uint32_t reserved:5;

    explicit icmp6_option_prefix_information_flags() :
                        onlink(0),
                        autonomous_addr_conf(0),
                        router_addr(0),
                        reserved(0) { }
    ~icmp6_option_prefix_information_flags() { }
};

struct icmp6_option_prefix_information {
    uint8_t len;
    uint8_t prefix_len;
    icmp6_option_prefix_information_flags flags;
    uint32_t valid_lifetime;
    uint32_t preferred_lifetime;
    uint32_t reserved;
    uint8_t prefix[16];

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
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("\t SourceLinkLayerAddr: {\n");
        log->verbose("\t\t len: %d\n", len);
        log->verbose("\t\t lladdr: %02x:%02x:%02x:%02x:%02x:%02x\n",
                        lladdr[0], lladdr[1], lladdr[2],
                        lladdr[3], lladdr[4], lladdr[5]);
        log->verbose("\t }\n");
    #endif
    }
};

struct icmp6_option_target_link_layer_addr {
    uint8_t len;
    uint8_t lladdr[FW_MACADDR_LEN];

    int serialize(packet &p);
    event_description deserialize(packet &p, logger *log, bool debug = false);
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("\t TargetLinkLayerAddr: {\n");
        log->verbose("\t\t len: %d\n", len);
        log->verbose("\t\t lladdr: %02x:%02x:%02x:%02x:%02x:%02x\n",
                        lladdr[0], lladdr[1], lladdr[2],
                        lladdr[3], lladdr[4], lladdr[5]);
        log->verbose("\t }\n");
    #endif
    }
};

struct icmp6_router_advertisement {
    uint8_t cur_hoplimit;
    icmp6_flags flags;
    uint16_t router_lifetime;
    uint32_t reachable_time;
    uint32_t retransmit_timer;

    int serialize(packet &p);
    event_description deserialize(packet &p, logger *log, bool debug = false);
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("\t\t\t RouterAdvertisement: {\n");
        log->verbose("\t\t\t\t cur_hoplimit: %d\n", cur_hoplimit);
        log->verbose("\t\t\t\t router_lifetie: %d\n", router_lifetime);
        log->verbose("\t\t\t\t reachable_time: %d\n", reachable_time);
        log->verbose("\t\t\t\t retransmit_timer: %d\n", retransmit_timer);
        log->verbose("\t\t\t }\n");
    #endif
    }
};

struct icmp6_router_solicitation {
    uint32_t reserved;

    int serialize(packet &p);
    event_description deserialize(packet &p, logger *log, bool debug = false);
    void print(logger *log);
};

struct icmp6_mcast_record {
#define MCAST_REC_TYPE_CHANGED_TO_EXCLUDE 4
    uint8_t rec_type;
    uint8_t aux_data_len;
    uint16_t n_sources;
    uint8_t addr[16];

    explicit icmp6_mcast_record() { }
    ~icmp6_mcast_record() { }

    event_description deserialize(packet &p, logger *log, bool debug);
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
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
    #endif
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

struct icmp6_neighbor_solicitation {
    uint32_t reserved;
    uint8_t target_addr[16];

    event_description deserialize(packet &p, logger *log, bool debug);
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("\t Neighbor_Solicitation: {\n");
        log->verbose("\t\t reserved: %d\n", reserved);
        log->verbose("\t }\n");
    #endif
    }
};

struct neighbor_advertisement_flags {
    uint32_t router:1;
    uint32_t solicited:1;
    uint32_t override_val:1;
    uint32_t reserved:29;

    explicit neighbor_advertisement_flags() :
                    router(0),
                    solicited(0),
                    override_val(0),
                    reserved(0) { }
    ~neighbor_advertisement_flags() { }
};

struct icmp6_neighbor_advertisement {
    neighbor_advertisement_flags flags;
    uint8_t target_addr[16];

    explicit icmp6_neighbor_advertisement() { }
    ~icmp6_neighbor_advertisement() { }

    event_description deserialize(packet &p, logger *log, bool debug);
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("\t NeighborAdvertisement: {\n");
        log->verbose("\t\t flags: {\n");
        log->verbose("\t\t\t router: %d\n", flags.router);
        log->verbose("\t\t\t solicited: %d\n", flags.solicited);
        log->verbose("\t\t\t override: %d\n", flags.override_val);
        log->verbose("\t\t\t reserved: %d\n", flags.reserved);
        log->verbose("\t\t }\n");
        log->verbose("\t }\n");
    #endif
    }
};

struct icmp6_options_bits {
    uint32_t dns_search_list:1;
    uint32_t mtu:1;
    uint32_t s_lladdr:1;
    uint32_t prefix_information:1;
    uint32_t t_lladdr:1;

    explicit icmp6_options_bits() :
                    dns_search_list(0),
                    mtu(0),
                    s_lladdr(0),
                    prefix_information(0),
                    t_lladdr(0) { }
    ~icmp6_options_bits() { }
};

/**
 * @brief - implements ICMP6 options.
*/
struct icmp6_options {
    icmp6_option_dns_search_list dns_search_list;
    icmp6_option_mtu mtu;
    icmp6_option_source_link_layer_addr s_lladdr;
    icmp6_option_prefix_information prefix_information;
    icmp6_option_target_link_layer_addr t_lladdr;

    icmp6_options_bits valid;

    event_description deserialize(packet &p, logger *log, bool debug);
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        if (valid.s_lladdr)
            s_lladdr.print(log);
        if (valid.t_lladdr)
            t_lladdr.print(log);
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
    std::shared_ptr<icmp6_router_solicitation> rsol;
    std::shared_ptr<icmp6_mcast_listener_report_msg_v2> mcast_listener_v2;
    std::shared_ptr<icmp6_echo_req> echo_req;
    std::shared_ptr<icmp6_echo_reply> echo_reply;
    std::shared_ptr<icmp6_neighbor_solicitation> ns;
    std::shared_ptr<icmp6_neighbor_advertisement> na;

    // options pointer
    std::shared_ptr<icmp6_options> opt;

    explicit icmp6_hdr() :
                    echo_req(nullptr),
                    echo_reply(nullptr),
                    ns(nullptr),
                    na(nullptr),
                    opt(nullptr)
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

