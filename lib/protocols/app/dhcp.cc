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
                    req_list->list.push_back(static_cast<dhcp_param_req_list>(byte_1));
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
    log->verbose("DHCP: {\n");
    log->verbose("\t msg_type: %d\n", msg_type);
    log->verbose("\t hw_type: %d\n", hw_type);
    log->verbose("\t hw_addr_len: %d\n", hw_addr_len);
    log->verbose("\t hops: %d\n", hops);
    log->verbose("\t transaction_id: %u\n", transaciton_id);
    log->verbose("\t secs_elapsed: %d\n", secs_elapsed);
    log->verbose("\t broadcast: %d\n", broadcast);
    log->verbose("\t reserved: %d\n", reserved);
    log->verbose("\t client_ipaddr: %u\n", client_ipaddr);
    log->verbose("\t your_ipaddr: %u\n", your_ipaddr);
    log->verbose("\t next_server_ipaddr: %u\n", next_server_ipaddr);
    log->verbose("\t relay_agent_ipaddr: %u\n", relay_agent_ipaddr);
    log->verbose("\t client_mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
                            client_macaddr[0], client_macaddr[1],
                            client_macaddr[2], client_macaddr[3],
                            client_macaddr[4], client_macaddr[5]);
    log->verbose("\t server_hostname: %s\n", (char *)server_hostname);
    log->verbose("\t bootfilename: %s\n", (char *)bootfilename);
    log->verbose("\t dhcp_magic: %c%c%c%c\n",
                            dhcp_magic[0], dhcp_magic[1],
                            dhcp_magic[2], dhcp_magic[3]);
    log->verbose("}\n");
}

dhcp_hdr::~dhcp_hdr()
{
    if (type) {
        free(type);
    }
    if (req_ipaddr) {
        free(req_ipaddr);
    }
    if (hostname) {
        free(hostname);
    }
    if (req_list) {
        free(req_list);
    }
}

}
