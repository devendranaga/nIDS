/**
 * @brief - implements dhcp serialize and deserialize.
 * 
 * @copyright - 2023-present. All rights reserved. Devendra Naga.
*/
#ifndef __FW_PROTOCOLS_APP_DHCP_H__
#define __FW_PROTOCOLS_APP_DHCP_H__

#include <stdlib.h>
#include <vector>
#include <packet.h>
#include <event_def.h>
#include <logger.h>

namespace firewall {

enum class dhcp_param_req_list {
    Subnet_Mask = 1,
    Time_Offset = 2,
    Router = 3,
    Domain_Name_Server = 6,
    Host_Name = 12,
    Domain_Name = 15,
    Root_Path = 17,
    Interface_MTU = 26,
    Broadcast_Address = 28,
    Static_Route = 33,
    NTP_Servers = 42,
    NetBIOS_over_TCP_IP_NameServer = 44,
    NetBIOS_over_TCP_IP_Scope = 47,
    Req_IPAddr = 50,
    DHCP_Msg_Type = 53,
    Parameter_Req_List = 55,
    Domain_Search = 119,
    Classless_Static_Route = 121,
    Private_Classless_Static_Route = 249,
    Private_Proxy_Auto_Discovery = 252,
    End = 255,
};

struct dhcp_opt_msg_type {
    uint8_t type;    
};

struct dhcp_opt_req_ipaddr {
    uint8_t len;
    uint32_t req_ipaddr;
};

struct dhcp_opt_hostname {
    uint8_t len;
    uint8_t *hostname;

    explicit dhcp_opt_hostname() : len(0), hostname(nullptr)
    { }

    ~dhcp_opt_hostname() {
        if (hostname) {
            free(hostname);
        }
    }
};

struct dhcp_opt_param_req_list {
    uint8_t len;
    std::vector<dhcp_param_req_list> list;
};

struct dhcp_opt_param_end {
    uint8_t val;

    explicit dhcp_opt_param_end() : val(0)
    { }
    ~dhcp_opt_param_end() { }
};

/**
 * @brief - implements DHCP header.
*/
struct dhcp_hdr {
    uint8_t msg_type;
    uint8_t hw_type;
    uint8_t hw_addr_len;
    uint8_t hops;
    uint32_t transaciton_id;
    uint16_t secs_elapsed;
    uint32_t broadcast:1;
    uint32_t reserved;
    uint32_t client_ipaddr;
    uint32_t your_ipaddr;
    uint32_t next_server_ipaddr;
    uint32_t relay_agent_ipaddr;
    uint8_t client_macaddr[FW_MACADDR_LEN];
    uint8_t client_hwaddr_pad[10];
    uint8_t server_hostname[64];
    uint8_t bootfilename[128];
    uint8_t dhcp_magic[4];

    dhcp_opt_msg_type *type;
    dhcp_opt_req_ipaddr *req_ipaddr;
    dhcp_opt_hostname *hostname;
    dhcp_opt_param_req_list *req_list;
    dhcp_opt_param_end end;

    explicit dhcp_hdr() :
                type(nullptr),
                req_ipaddr(nullptr),
                hostname(nullptr),
                req_list(nullptr)
    { }
    ~dhcp_hdr() { }

    int serialize(packet &p);

    /**
     * @brief - implements DHCP deserialization.
     * 
     * @param [in] p packet frame.
     * @return returns event_description type.
    */
    event_description deserialize(packet &p, logger *log, bool debug = false);
    void print(logger *log);
};

}

#endif
