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
    uint16_t byte16;
    bool valid_dhcp_magic = false;

    if (p.remaining_len() < dhcp_hdr_len_no_opt_) {
        return event_description::Evt_DHCP_Hdr_Len_Too_Short;
    }

    p.deserialize(msg_type);
    p.deserialize(hw_type);
    p.deserialize(hw_addr_len);
    p.deserialize(hops);
    p.deserialize(transaciton_id);
    p.deserialize(secs_elapsed);
    p.deserialize(byte16);
    broadcast = !(byte16 & 0x8000);
    reserved = byte16 & 0x7FFF;
    p.deserialize(client_ipaddr);
    p.deserialize(your_ipaddr);
    p.deserialize(next_server_ipaddr);
    p.deserialize(relay_agent_ipaddr);
    p.deserialize(client_macaddr, FW_MACADDR_LEN);
    p.deserialize(client_hwaddr_pad, sizeof(client_hwaddr_pad));
    p.deserialize(server_hostname, sizeof(server_hostname));
    p.deserialize(bootfilename, sizeof(bootfilename));
    p.deserialize(dhcp_magic, sizeof(dhcp_magic));

    if ((dhcp_magic[0] == 0x63) &&
        (dhcp_magic[1] == 0x82) &&
        (dhcp_magic[2] == 0x53) &&
        (dhcp_magic[3] == 0x63)) {
        valid_dhcp_magic = true;
    }

    if (!valid_dhcp_magic) {
        return event_description::Evt_DHCP_MAGIC_Invalid;
    }

    evt_desc = opts.deserialize(p, log, debug);
    if (evt_desc != event_description::Evt_Parse_Ok) {
        return evt_desc;
    }

    if (debug) {
        print(log);
    }

    return evt_desc;
}

void dhcp_hdr::print(logger *log)
{
#if defined(FW_ENABLE_DEBUG)
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
    log->verbose("\t dhcp_magic: %02x-%02x-%02x-%02x\n",
                            dhcp_magic[0], dhcp_magic[1],
                            dhcp_magic[2], dhcp_magic[3]);
    log->verbose("\t dhcp_options: {\n");
    opts.print(log);
    log->verbose("\t }\n");
    log->verbose("}\n");
#endif
}

dhcp_hdr::~dhcp_hdr()
{
}

event_description dhcp_opt_client_id::parse(packet &p, logger *log, bool debug)
{
    p.deserialize(len);
    if (len != len_) {
        return event_description::Evt_DHCP_Opt_Client_Id_Len_Inval;
    }
    p.deserialize(hw_type);
    p.deserialize(client_mac, sizeof(client_mac));

    return event_description::Evt_Parse_Ok;
}

event_description dhcp_opts::deserialize(packet &p, logger *log, bool debug)
{
    event_description evt_desc;

    end.val = 0;

    while (p.off < p.buf_len) {
        dhcp_param_req_list byte = static_cast<dhcp_param_req_list>(p.buf[p.off]);

        p.off ++;

        if (end.val == static_cast<uint8_t>(dhcp_param_req_list::End)) {
            break;
        }

        switch (byte) {
            case dhcp_param_req_list::DHCP_Msg_Type: {
                type = std::make_shared<dhcp_opt_msg_type>();
                if (!type) {
                    return event_description::Evt_Unknown_Error;
                }
                p.deserialize(type->len);
                p.deserialize(type->type);
            } break;
            case dhcp_param_req_list::Req_IPAddr: {
                req_ipaddr = std::make_shared<dhcp_opt_req_ipaddr>();
                if (!req_ipaddr) {
                    return event_description::Evt_Unknown_Error;
                }
                p.deserialize(req_ipaddr->len);
                p.deserialize(req_ipaddr->req_ipaddr);
            } break;
            case dhcp_param_req_list::Host_Name: {
                hostname = std::make_shared<dhcp_opt_hostname>();
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
            case dhcp_param_req_list::Parameter_Req_List: {
                req_list = std::make_shared<dhcp_opt_param_req_list>();
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
            case dhcp_param_req_list::End: {
                p.deserialize(end.val);
            } break;
            case dhcp_param_req_list::Client_Id: {
                client_id = std::make_shared<dhcp_opt_client_id>();
                if (!client_id) {
                    return event_description::Evt_Unknown_Error;
                }

                evt_desc = client_id->parse(p, log, debug);
                if (evt_desc != event_description::Evt_Parse_Ok) {
                    return evt_desc;
                }
            } break;
            case dhcp_param_req_list::Renewal_Time: {
                renewal_time = std::make_shared<dhcp_opt_renewal_time>();
                if (!renewal_time) {
                    return event_description::Evt_Unknown_Error;
                }

                evt_desc = renewal_time->deserialize(p, log, debug);
                if (evt_desc != event_description::Evt_Parse_Ok) {
                    return evt_desc;
                }
            } break;
            case dhcp_param_req_list::Rebinding_Time: {
                rebind_time = std::make_shared<dhcp_opt_rebindig_time>();
                if (!rebind_time) {
                    return event_description::Evt_Unknown_Error;
                }

                evt_desc = rebind_time->deserialize(p, log, debug);
                if (evt_desc != event_description::Evt_Parse_Ok) {
                    return evt_desc;
                }
            } break;
            case dhcp_param_req_list::Ipaddr_Lease_Time: {
                lease_time = std::make_shared<dhcp_opt_ipaddr_lease_time>();
                if (!lease_time) {
                    return event_description::Evt_Unknown_Error;
                }

                evt_desc = lease_time->deserialize(p, log, debug);
                if (evt_desc != event_description::Evt_Parse_Ok) {
                    return evt_desc;
                }
            } break;
            case dhcp_param_req_list::DHCP_Server_Id: {
                dhcp_server_id = std::make_shared<dhcp_opt_dhcp_server_id>();
                if (!dhcp_server_id) {
                    return event_description::Evt_Unknown_Error;
                }

                evt_desc = dhcp_server_id->deserialize(p, log, debug);
                if (evt_desc != event_description::Evt_Parse_Ok) {
                    return evt_desc;
                }
            } break;
            case dhcp_param_req_list::Subnet_Mask: {
                subnet_mask = std::make_shared<dhcp_opt_subnet_mask>();
                if (!subnet_mask) {
                    return event_description::Evt_Unknown_Error;
                }

                evt_desc = subnet_mask->deserialize(p, log, debug);
                if (evt_desc != event_description::Evt_Parse_Ok) {
                    return evt_desc;
                }
            } break;
            case dhcp_param_req_list::Domain_Name: {
                domain_name = std::make_shared<dhcp_opt_domain_name>();
                if (!domain_name) {
                    return event_description::Evt_Unknown_Error;
                }

                evt_desc = domain_name->deserialize(p, log, debug);
                if (evt_desc != event_description::Evt_Parse_Ok) {
                    return evt_desc;
                }
            } break;
            case dhcp_param_req_list::Router: {
                router = std::make_shared<dhcp_opt_router>();
                if (!router) {
                    return event_description::Evt_Unknown_Error;
                }

                evt_desc = router->deserialize(p, log, debug);
                if (evt_desc != event_description::Evt_Unknown_Error) {
                    return evt_desc;
                }
            } break;
            case dhcp_param_req_list::Domain_Name_Server: {
                dns = std::make_shared<dhcp_opt_dns>();
                if (!dns) {
                    return event_description::Evt_Unknown_Error;
                }

                evt_desc = dns->deserialize(p, log, debug);
                if (evt_desc != event_description::Evt_Parse_Ok) {
                    return evt_desc;
                }
            } break;
            case dhcp_param_req_list::Perform_Router_Discover: {
                perf_rdisc = std::make_shared<dhcp_opt_perform_router_discover>();
                if (!perf_rdisc) {
                    return event_description::Evt_Unknown_Error;
                }

                evt_desc = perf_rdisc->deserialize(p, log, debug);
                if (evt_desc != event_description::Evt_Parse_Ok) {
                    return evt_desc;
                }
            } break;
            case dhcp_param_req_list::Pad: {
            } break;
            default: {
                evt_desc = event_description::Evt_Unknown_Error;
            } break;
        }
    }

    return event_description::Evt_Parse_Ok;
}

}
