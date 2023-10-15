/**
 * @brief - implements DHCP serialize and deserialize.
 * 
 * @copyright - 2023-present. All rights reserved. Devendra Naga.
*/
#include <dhcp.h>

namespace firewall {

int dhcp_hdr::serialize(packet &p)
{
    return -1;
}

event_description dhcp_hdr::deserialize(packet &p, logger *log, bool debug)
{
    event_description evt_desc = event_description::Evt_Unknown_Error;
    uint32_t byte32;
    bool valid_dhcp_magic = false;

    p.deserialize(msg_type);
    p.deserialize(hw_type);
    p.deserialize(hw_addr_len);
    p.deserialize(hops);
    p.deserialize(transaciton_id);
    p.deserialize(secs_elapsed);
    p.deserialize(byte32);
    broadcast = !(byte32 & 0x80000000);
    reserved = byte32 & 0x7FFFFFFF;
    p.deserialize(client_ipaddr);
    p.deserialize(your_ipaddr);
    p.deserialize(next_server_ipaddr);
    p.deserialize(relay_agent_ipaddr);
    p.deserialize(client_macaddr, FW_MACADDR_LEN);
    p.deserialize(client_hwaddr_pad, sizeof(client_hwaddr_pad));
    p.deserialize(server_hostname, sizeof(server_hostname));
    p.deserialize(bootfilename, sizeof(bootfilename));
    p.deserialize(dhcp_magic, sizeof(dhcp_magic));

    if ((dhcp_magic[0] == 'D') &&
        (dhcp_magic[1] == 'H') &&
        (dhcp_magic[2] == 'C') &&
        (dhcp_magic[3] == 'P')) {
        valid_dhcp_magic = true;
    }

    if (!valid_dhcp_magic) {
        return event_description::Evt_DHCP_MAGIC_Invalid;
    }

    while (p.off < p.buf_len) {
        uint8_t byte = p.buf[p.off];

        p.off ++;

        if (end.val == static_cast<uint8_t>(dhcp_param_req_list::End)) {
            break;
        }

        switch (byte) {
            case static_cast<uint8_t>(dhcp_param_req_list::DHCP_Msg_Type): {
                type = (dhcp_opt_msg_type *)calloc(1, sizeof(dhcp_opt_msg_type));
                if (!type) {
                    return event_description::Evt_Unknown_Error;
                }
                p.deserialize(type->type);
            } break;
            case static_cast<uint8_t>(dhcp_param_req_list::Req_IPAddr): {
                req_ipaddr = (dhcp_opt_req_ipaddr *)calloc(1, sizeof(dhcp_opt_req_ipaddr));
                if (!req_ipaddr) {
                    return event_description::Evt_Unknown_Error;
                }
                p.deserialize(req_ipaddr->len);
                p.deserialize(req_ipaddr->req_ipaddr);
            } break;
            case static_cast<uint8_t>(dhcp_param_req_list::Host_Name): {
                hostname = (dhcp_opt_hostname *)calloc(1, sizeof(dhcp_opt_hostname));
                if (!hostname) {
                    return event_description::Evt_Unknown_Error;
                }
                p.deserialize(hostname->len);
                hostname->hostname = (uint8_t *)calloc(1, hostname->len);
                if (!hostname->hostname) {
                    return event_description::Evt_Unknown_Error;
                }
                p.deserialize(hostname->hostname, hostname->len);
            } break;
            case static_cast<uint8_t>(dhcp_param_req_list::Parameter_Req_List): {
                req_list = (dhcp_opt_param_req_list *)calloc(1, sizeof(dhcp_opt_param_req_list));
                if (!req_list) {
                    return event_description::Evt_Unknown_Error;
                }
                p.deserialize(req_list->len);
                for (auto i = 0; (i < req_list->len) &&
                                 (p.off < p.buf_len); i ++) {
                    uint8_t byte_1;

                    p.deserialize(byte_1);
                    req_list->list.emplace_back(byte_1);
                }
            } break;
            case static_cast<uint8_t>(dhcp_param_req_list::End): {
                p.deserialize(end.val);
            } break;
            default: {
                evt_desc = event_description::Evt_Unknown_Error;
            } break;
        }
    }

    if (debug) {
        print(log);
    }

    return evt_desc;
}

void dhcp_hdr::print(logger *log)
{

}

}
