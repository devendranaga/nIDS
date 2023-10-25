/**
 * @brief - implements dhcp serialize and deserialize.
 * 
 * @copyright - 2023-present. All rights reserved. Devendra Naga.
*/
#ifndef __FW_PROTOCOLS_APP_DHCP_H__
#define __FW_PROTOCOLS_APP_DHCP_H__

#include <stdlib.h>
#include <vector>
#include <memory>
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
    Ipaddr_Lease_Time = 51,
    DHCP_Msg_Type = 53,
    DHCP_Server_Id = 54,
    Parameter_Req_List = 55,
    Renewal_Time = 58,
    Rebinding_Time = 59,
    Client_Id = 61,
    Domain_Search = 119,
    Classless_Static_Route = 121,
    Private_Classless_Static_Route = 249,
    Private_Proxy_Auto_Discovery = 252,
    End = 255,
};

struct dhcp_opt_msg_type {
    uint8_t type;

	void print(logger *log)
	{
    #if defined(FW_ENABLE_DEBUG)
		log->verbose("\t\t msg_type: {\n");
		log->verbose("\t\t\t val: %d\n", type);
		log->verbose("\t\t }\n");
    #endif 
	}
};

struct dhcp_opt_req_ipaddr {
    uint8_t len;
    uint32_t req_ipaddr;

    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("\t\t req_ipaddr: {\n");
        log->verbose("\t\t\t len: %d\n", len);
        log->verbose("\t\t\t req_ipaddr: %u\n", req_ipaddr);
        log->verbose("\t\t }\n");
    #endif
    }
};

struct dhcp_opt_hostname {
    uint8_t len;
    uint8_t *hostname;

    explicit dhcp_opt_hostname() : len(0), hostname(nullptr)
    { }

    ~dhcp_opt_hostname() {
        if (hostname) {
            free(hostname);
            hostname = nullptr;
        }
    }

    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("\t\t hostname: {\n");
        log->verbose("\t\t\t len: %d\n", len);
        if (hostname)
            log->verbose("\t\t\t hostname: %s\n", (char *)hostname);
        log->verbose("\t\t }\n");
    #endif
    }
};

struct dhcp_opt_client_id {
    uint8_t len;
    uint8_t hw_type;
    uint8_t client_mac[6];

    event_description parse(packet &p, logger *log, bool debug);
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("\t\t client_id: {\n");
        log->verbose("\t\t\t len: %d\n", len);
        log->verbose("\t\t\t hw_type: %d\n", hw_type);
        log->verbose("\t\t\t mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
                        client_mac[0], client_mac[1],
                        client_mac[2], client_mac[3],
                        client_mac[4], client_mac[5]);
        log->verbose("\t\t }\n");
    #endif
    }

    private:
        const int len_ = 7;
};

struct dhcp_opt_param_req_list {
    uint8_t len;
    std::vector<dhcp_param_req_list> list;

    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("\t\t param_req_list: {\n");
        for (auto it : list) {
            log->verbose("\t\t\t %d\n", (int)it);
        }
        log->verbose("\t\t }\n");
    #endif
    }
};

struct dhcp_opt_param_end {
    uint8_t val;

    explicit dhcp_opt_param_end() : val(0)
    { }
    ~dhcp_opt_param_end() { }

    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("\t\t end: {\n");
        log->verbose("\t\t\t %d\n", val);
        log->verbose("\t\t }\n");
    #endif
    }
};

struct dhcp_opt_subnet_mask {
    uint8_t len;
    uint32_t subnet_mask;

    explicit dhcp_opt_subnet_mask() { }
    ~dhcp_opt_subnet_mask() { }

    event_description deserialize(packet &p, logger *log, bool debug)
    {
        p.deserialize(len);
        if (len != len_) {
            return event_description::Evt_DHCP_Opt_SubnetMask_Len_Inval;
        }
        p.deserialize(subnet_mask);

        return event_description::Evt_Parse_Ok;
    }

    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("\t\t subnet_mask: {\n");
        log->verbose("\t\t\t len: %d\n", len);
        log->verbose("\t\t\t subnet_mask: %u\n", subnet_mask);
        log->verbose("\t\t }\n");
    #endif
    }

    private:
        const int len_ = 4;
};

struct dhcp_opt_renewal_time {
    uint8_t len;
    uint32_t val;

    event_description deserialize(packet &p, logger *log, bool debug)
    {
        p.deserialize(len);
        if (len != len_) {
            return event_description::Evt_DHCP_Opt_Renewal_Time_Len_Inval;
        }
        p.deserialize(val);

        return event_description::Evt_Parse_Ok;
    }

    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("\t\t renewal_time: {\n");
        log->verbose("\t\t\t len: %d\n", len);
        log->verbose("\t\t\t val: %u\n", val);
        log->verbose("\t\t }\n");
    #endif
    }

    private:
        const int len_ = 4;
};

struct dhcp_opt_rebindig_time {
    uint8_t len;
    uint32_t val;

    event_description deserialize(packet &p, logger *log, bool debug)
    {
        p.deserialize(len);
        if (len != len_) {
            return event_description::Evt_DHCP_Opt_Renewal_Time_Len_Inval;
        }
        p.deserialize(val);

        return event_description::Evt_Parse_Ok;
    }

    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("\t\t rebinding_time: {\n");
        log->verbose("\t\t\t len: %d\n", len);
        log->verbose("\t\t\t val: %u\n", val);
        log->verbose("\t\t }\n");
    #endif
    }

    private:
        const int len_ = 4;
};

struct dhcp_opt_ipaddr_lease_time {
    uint8_t len;
    uint32_t val;

    event_description deserialize(packet &p, logger *log, bool debug)
    {
        p.deserialize(len);
        if (len != len_) {
            return event_description::Evt_DHCP_Opt_Ipaddr_Lease_Time_Len_Inval;
        }
        p.deserialize(val);

        return event_description::Evt_Parse_Ok;
    }

    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("\t\t ipaddr_lease_time: {\n");
        log->verbose("\t\t\t len: %d\n", len);
        log->verbose("\t\t\t val: %u\n", val);
        log->verbose("\t\t }\n");
    #endif
    }

    private:
        const int len_ = 4;
};

struct dhcp_opt_dhcp_server_id {
    uint8_t len;
    uint32_t val;

    event_description deserialize(packet &p, logger *log, bool debug)
    {
        p.deserialize(len);
        if (len != len_) {
            return event_description::Evt_DHCP_Opt_Server_Id_Len_Inval;
        }
        p.deserialize(val);

        return event_description::Evt_Parse_Ok;
    }

    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("\t\t dhcp_server_id: {\n");
        log->verbose("\t\t\t len: %d\n", len);
        log->verbose("\t\t\t val: %u\n", val);
        log->verbose("\t\t }\n");
    #endif
    }

    private:
        const int len_ = 4;
};

struct dhcp_opts {
    std::shared_ptr<dhcp_opt_msg_type> type;
    std::shared_ptr<dhcp_opt_req_ipaddr> req_ipaddr;
    std::shared_ptr<dhcp_opt_hostname> hostname;
    std::shared_ptr<dhcp_opt_param_req_list> req_list;
    std::shared_ptr<dhcp_opt_client_id> client_id;
    std::shared_ptr<dhcp_opt_subnet_mask> subnet_mask;
    std::shared_ptr<dhcp_opt_renewal_time> renewal_time;
    std::shared_ptr<dhcp_opt_rebindig_time> rebind_time;
    std::shared_ptr<dhcp_opt_ipaddr_lease_time> lease_time;
    std::shared_ptr<dhcp_opt_dhcp_server_id> dhcp_server_id;
    dhcp_opt_param_end end;

    explicit dhcp_opts() : 
                type(nullptr),
                req_ipaddr(nullptr),
                hostname(nullptr),
                req_list(nullptr),
                client_id(nullptr),
                subnet_mask(nullptr),
                renewal_time(nullptr),
                lease_time(nullptr),
                dhcp_server_id(nullptr) { }
    ~dhcp_opts() { }

    int serialize(packet &p);

    /**
     * @brief - implements DHCP options deserialization.
     * 
     * @param [in] p packet frame.
     * @return returns event_description type.
    */
    event_description deserialize(packet &p, logger *log, bool debug = false);
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        if (type)
            type->print(log);
        if (req_ipaddr)
            req_ipaddr->print(log);
        if (hostname)
            hostname->print(log);
        if (req_list)
            req_list->print(log);
        if (client_id)
            client_id->print(log);
        if (subnet_mask)
            subnet_mask->print(log);
        if (renewal_time)
            renewal_time->print(log);
        if (rebind_time)
            rebind_time->print(log);
        if (lease_time)
            lease_time->print(log);
        if (dhcp_server_id)
            dhcp_server_id->print(log);
    #endif
    }
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

    dhcp_opts opts;

    explicit dhcp_hdr() { }
    ~dhcp_hdr();

    int serialize(packet &p);

    /**
     * @brief - implements DHCP deserialization.
     * 
     * @param [in] p packet frame.
     * @return returns event_description type.
    */
    event_description deserialize(packet &p, logger *log, bool debug = false);
    void print(logger *log);

    private:
        const int dhcp_hdr_len_no_opt_ = 240;
};

}

#endif
