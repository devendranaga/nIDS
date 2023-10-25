/**
 * @brief - implements event manager interface.
 * 
 * @copyright - 2023-present All rights reserved. Devendra Naga.
*/
#include <event_mgr.h>

namespace firewall {

/**
 * @brief - describes a rulemap of auto detected rules.
*/
const static struct {
    event_description evt;
    rule_ids rule_id;
} auto_det_rule_id_list[ ] = {
    //
    // ethernet rules
    {
        event_description::Evt_Eth_Ethertype_Unknown,
        rule_ids::Rule_Id_Unsupported_Ethertype
    },
    {
        event_description::Evt_Eth_Hdrlen_Too_Small,
        rule_ids::Rule_Id_Eth_Hdrlen_Too_Small
    },

    //
    // arp rules
    {
        event_description::Evt_ARP_Hdrlen_Too_Small,
        rule_ids::Rule_Id_ARP_Hdrlen_Too_Small
    },
    {
        event_description::Evt_ARP_HW_Addr_Len_Inval,
        rule_ids::Rule_Id_ARP_HW_Addr_Len_Inval
    },
    {
        event_description::Evt_ARP_Protocol_Addr_Len_Inval,
        rule_ids::Rule_Id_ARP_Protocol_Addr_Len_Inval
    },
    {
        event_description::Evt_ARP_Inval_Operation,
        rule_ids::Rule_Id_ARP_Inval_Operation
    },

    //
    // vlan rules
    {
        event_description::Evt_VLAN_Hdrlen_Too_Short,
        rule_ids::Rule_Id_Vlan_Hdrlen_Too_Small,
    },
    {
        event_description::Evt_VLAN_Inval_VID,
        rule_ids::Rule_Id_Vlan_Id_Inval,
    },

    //
    // ipv4 rules
    {
        event_description::Evt_IPV4_Hdrlen_Too_Small,
        rule_ids::Rule_Id_IPV4_Hdrlen_Too_Small
    },
    {
        event_description::Evt_IPV4_Hdrlen_Too_Big,
        rule_ids::Rule_Id_IPV4_Hdrlen_Too_Big
    },
    {
        event_description::Evt_IPV4_Hdrlen_Inval,
        rule_ids::Rule_Id_IPV4_Hdrlen_Inval
    },
    {
        event_description::Evt_IPV4_Version_Invalid,
        rule_ids::Rule_Id_IPV4_Version_Invalid
    },
    {
        event_description::Evt_IPV4_Flags_Invalid,
        rule_ids::Rule_Id_IPV4_Flags_Invalid
    },
    {
        event_description::Evt_IPV4_Hdr_Chksum_Invalid,
        rule_ids::Rule_Id_IPV4_Hdr_Chksum_Invalid
    },
    {
        event_description::Evt_IPV4_Protocol_Unsupported,
        rule_ids::Rule_Id_IPV4_Protocol_Unsupported
    },

    //
    // TCP rules
    {
        event_description::Evt_Tcp_Hdrlen_Too_Short,
        rule_ids::Rule_Id_Tcp_Hdrlen_Too_Short,
    },
    {
        event_description::Evt_Tcp_Flags_All_Set,
        rule_ids::Rule_Id_Tcp_Flags_All_Set,
    },
    {
        event_description::Evt_Tcp_Flags_None_Set,
        rule_ids::Rule_Id_Tcp_Flags_None_Set,
    },
    {
        event_description::Evt_Tcp_Invalid_Option,
        rule_ids::Rule_Id_Tcp_Invalid_Option,
    },
    {
        event_description::Evt_Tcp_Opt_Ts_Inval_Len,
        rule_ids::Rule_Id_Tcp_Opt_Ts_Inval_Len,
    },
    {
        event_description::Evt_Tcp_Opt_Win_Scale_Inval_Len,
        rule_ids::Rule_Id_Tcp_Opt_Win_Scale_Inval_Len,
    },

    //
    // UDP rules
    {
        event_description::Evt_Udp_Src_Port_Invalid,
        rule_ids::Rule_Id_Udp_Src_Port_Invalid
    },
    {
        event_description::Evt_Udp_Dst_Port_Invalid,
        rule_ids::Rule_Id_Udp_Dst_Port_Invalid
    },
    {
        event_description::Evt_Udp_Len_Too_Short,
        rule_ids::Rule_Id_Udp_Len_Too_Short
    },
    {
        event_description::Evt_Udp_Chksum_Invalid,
        rule_ids::Rule_Id_Udp_Chksum_Invalid
    },

    //
    // ICMP rules
    {
        event_description::Evt_Icmp_Hdr_Len_Too_Short,
        rule_ids::Rule_Id_Icmp_Hdr_Len_Too_Short,
    },
    {
        event_description::Evt_Icmp_Echo_Req_Hdr_Len_Too_Short,
        rule_ids::Rule_Id_Icmp_Echo_Req_Hdr_Len_Too_Short,
    },
    {
        event_description::Evt_Icmp_Echo_Reply_Hdr_Len_Too_Short,
        rule_ids::Rule_Id_Icmp_Echo_Reply_Hdr_Len_Too_Short,
    },
    {
        event_description::Evt_Icmp_Ts_Msg_Hdr_Len_Too_Short,
        rule_ids::Rule_Id_Icmp_Ts_Msg_Hdr_Len_Too_Short,
    },
    {
        event_description::Evt_Icmp_Info_Msg_Hdr_Len_Too_Short,
        rule_ids::Rule_Id_Icmp_Info_Msg_Hdr_Len_Too_Short,
    },
    {
        event_description::Evt_Icmp_Invalid_Type,
        rule_ids::Rule_Id_Icmp_Invalid_Type,
    },
    {
        event_description::Evt_Icmp_Time_Exceeded_Invalid_Code,
        rule_ids::Rule_Id_Icmp_Time_Exceeded_Invalid_Code,
    },
    {
        event_description::Evt_Icmp_Dest_Unreachable_Invalid_Code,
        rule_ids::Rule_Id_Icmp_Dest_Unreachable_Invalid_Code,
    },
    {
        event_description::Evt_Icmp_Covert_Channel_Maybe_Active,
        rule_ids::Rule_Id_Icmp_Covert_Channel_Maybe_Active,
    },

    //
    // DHCP rules
    {
        event_description::Evt_DHCP_MAGIC_Invalid,
        rule_ids::Rule_Id_DHCP_MAGIC_Invalid
    },
    {
        event_description::Evt_DHCP_Opt_Client_Id_Len_Inval,
        rule_ids::Rule_Id_DHCP_Opt_Client_Id_Len_Inval,
    },
    {
        event_description::Evt_DHCP_Opt_SubnetMask_Len_Inval,
        rule_ids::Rule_Id_DHCP_Opt_SubnetMask_Len_Inval,
    },
    {
        event_description::Evt_DHCP_Opt_Renewal_Time_Len_Inval,
        rule_ids::Rule_Id_DHCP_Opt_Renewal_Time_Len_Inval,
    },
    {
        event_description::Evt_DHCP_Opt_Ipaddr_Lease_Time_Len_Inval,
        rule_ids::Rule_Id_DHCP_Opt_Ipaddr_Lease_Time_Len_Inval,
    },
    {
        event_description::Evt_DHCP_Opt_Server_Id_Len_Inval,
        rule_ids::Rule_Id_DHCP_Opt_Server_Id_Len_Inval,
    },
    {
        event_description::Evt_DHCP_Hdr_Len_Too_Short,
        rule_ids::Rule_Id_DHCP_Hdr_Len_Too_Short,
    },

    //
    // Rules matched by the Exploit filter
    {
        event_description::Evt_Known_Exploit_Win32_Blaster,
        rule_ids::Rule_Id_Known_Exploit_Win32_Blaster,
    },

    {
        event_description::Evt_Unknown_Error,
        rule_ids::Rule_Id_Unknown
    },
};

/**
 * @brief - create an event.
*/
void event_mgr::create_evt(event &evt,
                           uint32_t rule_id,
                           event_type evt_type,
                           event_description evt_details,
                           const parser &pkt)
{
    evt.evt_type = evt_type;
    evt.evt_details = evt_details;
    evt.rule_id = rule_id;

    std::memcpy(evt.src_mac, pkt.eh->src_mac, sizeof(pkt.eh->src_mac));
    std::memcpy(evt.dst_mac, pkt.eh->dst_mac, sizeof(pkt.eh->dst_mac));

    //
    // if vlan header is present, get ethertype from vlan header
    evt.ethertype = pkt.eh->ethertype;
    if (pkt.protocols_avail.has_vlan()) {
        evt.ethertype = pkt.vh->ethertype;
    }

    switch (evt.ethertype) {
        case static_cast<uint16_t>(ether_type::Ether_Type_IPv4):
            evt.protocol = pkt.ipv4_h->protocol;
        break;
    }
    evt.pkt_len = pkt.pkt_len;
}

fw_error_type event_mgr::init(logger *log)
{
    firewall_config *fw_conf = firewall_config::instance();
    fw_error_type ret;

    log_ = log;

    //
    // create storage thread
    storage_thr_id_ = std::make_shared<std::thread>(
                        &event_mgr::storage_thread, this);
    storage_thr_id_->detach();

    log_->info("evt_mgr::init: create storage thread ok\n");

    //
    // initialize event file writer
    ret = evt_file_w_.init(fw_conf->evt_config.event_file_path,
                           fw_conf->evt_config.event_file_size_bytes);
    if (ret != fw_error_type::eNo_Error) {
        return ret;
    }

    log_->info("evt_mgr::init: create log file writer ok\n");

    return fw_error_type::eNo_Error;
}

void event_mgr::store(event &evt)
{
    {
        std::unique_lock<std::mutex> lock(storage_thr_lock_);
        event_list_.push(evt);
    }
}

uint32_t event_mgr::get_matching_rule(event_description evt_desc)
{
    for (auto i : auto_det_rule_id_list) {
        if (i.evt == evt_desc) {
            return static_cast<uint32_t>(i.rule_id);
        }
    }

    return static_cast<uint32_t>(rule_ids::Rule_Id_Unknown);
}

/**
 * @brief - store the events into the buffer.
*/
void event_mgr::store(event_type evt_type,
                      event_description evt_desc, const parser &pkt)
{
    event evt;

    create_evt(evt, get_matching_rule(evt_desc), evt_type, evt_desc, pkt);
    store(evt);
}

/**
 * @brief - stores event logs to disk.
*/
void event_mgr::storage_thread()
{
    firewall_config *conf = firewall_config::instance();

    while (1) {
        // wake up every second and write the collected event logs
        // to disk.
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        {
            std::unique_lock<std::mutex> lock(storage_thr_lock_);
            int q_len = 0;

            for (q_len = event_list_.size(); q_len > 0; q_len = event_list_.size()) {
                event evt = event_list_.front();

                if (conf->evt_config.evt_file_format == event_file_format::Json) {
                    evt_file_w_.write_json(evt);
                } else if (conf->evt_config.evt_file_format == event_file_format::Binary) {
                    evt_file_w_.write(evt);
                } else {
                    // Discard the event frame.
                }
                event_list_.pop();
            }
        }
    }
}

}

