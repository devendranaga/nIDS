/**
 * @brief - implements event manager interface.
 * 
 * @copyright - 2023-present All rights reserved. Devendra Naga.
*/
#include <syslog.h>
#include <event_mgr.h>

namespace firewall {

/**
 * @brief - describes a rulemap of auto detected rules.
*/
const static struct {
    event_description evt;
    rule_ids rule_id;
    std::string desc;
} auto_det_rule_id_list[ ] = {
    //
    // ethernet rules
    {
        event_description::Evt_Eth_Ethertype_Unknown,
        rule_ids::Rule_Id_Unsupported_Ethertype,
        "Unsupported Ethertype"
    },
    {
        event_description::Evt_Eth_Hdrlen_Too_Small,
        rule_ids::Rule_Id_Eth_Hdrlen_Too_Small,
        "Ethernet Header Length too small"
    },

    //
    // macsec rules
    {
        event_description::Evt_MACsec_TCI_ES_SC_Set,
        rule_ids::Rule_Id_MACsec_TCI_ES_SC_Set,
        "MACsec TCI->ES TCI->SC cannot be set at the same time"
    },
    {
        event_description::Evt_MACsec_TCI_SC_SCB_Set,
        rule_ids::Rule_Id_MACsec_TCI_SC_SCB_Set,
        "MACsec TCI->SC and TCI->SCB cannot be set at the same time"
    },
    {
        event_description::Evt_MACsec_Hdr_Len_Too_Small,
        rule_ids::Rule_Id_MACsec_Hdr_Len_Too_Small,
        "MACsec Header length too small"
    },

    //
    // arp rules
    {
        event_description::Evt_ARP_Hdrlen_Too_Small,
        rule_ids::Rule_Id_ARP_Hdrlen_Too_Small,
        "ARP Header length too small",
    },
    {
        event_description::Evt_ARP_HWType_Inval,
        rule_ids::Rule_Id_ARP_HWType_Inval,
        "ARP HwType is invalid",
    },
    {
        event_description::Evt_ARP_HW_Addr_Len_Inval,
        rule_ids::Rule_Id_ARP_HW_Addr_Len_Inval,
        "ARP Header Length invalid"
    },
    {
        event_description::Evt_ARP_Protocol_Addr_Len_Inval,
        rule_ids::Rule_Id_ARP_Protocol_Addr_Len_Inval,
        "ARP protocol address length invalid"
    },
    {
        event_description::Evt_ARP_Inval_Operation,
        rule_ids::Rule_Id_ARP_Inval_Operation,
        "ARP invalid op"
    },
    {
        event_description::Evt_ARP_Info_Leak,
        rule_ids::Rule_Id_ARP_Info_Leak,
        "ARP Information leak",
    },

    //
    // vlan rules
    {
        event_description::Evt_VLAN_Hdrlen_Too_Short,
        rule_ids::Rule_Id_Vlan_Hdrlen_Too_Small,
        "VLAN header length too small"
    },
    {
        event_description::Evt_VLAN_Inval_VID,
        rule_ids::Rule_Id_Vlan_Id_Inval,
        "VLAN ID invalid"
    },

    //
    // ipv4 rules
    {
        event_description::Evt_IPV4_Hdrlen_Too_Small,
        rule_ids::Rule_Id_IPV4_Hdrlen_Too_Small,
        "IPv4 header length too small"
    },
    {
        event_description::Evt_IPV4_Hdrlen_Too_Big,
        rule_ids::Rule_Id_IPV4_Hdrlen_Too_Big,
        "IPv4 header length too big"
    },
    {
        event_description::Evt_IPV4_Hdrlen_Inval,
        rule_ids::Rule_Id_IPV4_Hdrlen_Inval,
        "IPv4 header length invalid"
    },
    {
        event_description::Evt_IPV4_Version_Invalid,
        rule_ids::Rule_Id_IPV4_Version_Invalid,
        "IPv4 version is invalid"
    },
    {
        event_description::Evt_IPV4_Flags_Invalid,
        rule_ids::Rule_Id_IPV4_Flags_Invalid,
        "IPv4 flags invalid"
    },
    {
        event_description::Evt_IPV4_Hdr_Chksum_Invalid,
        rule_ids::Rule_Id_IPV4_Hdr_Chksum_Invalid,
        "IPv4 header checksum invalid"
    },
    {
        event_description::Evt_IPV4_Protocol_Unsupported,
        rule_ids::Rule_Id_IPV4_Protocol_Unsupported,
        "IPv4 protocol unsupported"
    },
    {
        event_description::Evt_IPV4_Unknown_Opt,
        rule_ids::Rule_Id_IPV4_Unknown_Opt,
        "IPv4 unknown option"
    },
    {
        event_description::Evt_IPV4_Inval_Src_Addr,
        rule_ids::Rule_Id_IPV4_Inval_Src_Addr,
        "IPv4 invalid source address"
    },
    {
        event_description::Evt_IPv4_Zero_TTL,
        rule_ids::Rule_Id_IPv4_Zero_TTL,
        "IPv4 packet TTL is zero"
    },
    {
        event_description::Evt_IPv4_Reserved_Set,
        rule_ids::Rule_Id_IPv4_Reserved_Set,
        "IPv4 Reserved bit is set"
    },
    {
        event_description::Evt_IPv4_Src_And_Dst_Addr_Same,
        rule_ids::Rule_Id_IPv4_Src_And_Dst_Addr_Same,
        "IPv4 Src and Dst Addresses are same"
    },
    {
        event_description::Evt_IPv4_Src_Is_Broadcast,
        rule_ids::Rule_Id_IPv4_Src_Is_Broadcast,
        "IPv4 Src is a broadcast address"
    },
    {
        event_description::Evt_IPv4_Src_Is_Multicast,
        rule_ids::Rule_Id_IPv4_Src_Is_Multicast,
        "IPv4 Src is a multicast address"
    },
    {
        event_description::Evt_IPv4_Src_Is_Reserved,
        rule_ids::Rule_Id_IPv4_Src_Is_Reserved,
        "IPv4 Src is a reserved address"
    },
    {
        event_description::Evt_IPv4_Dst_Is_Reserved,
        rule_ids::Rule_Id_IPv4_Dst_Is_Reserved,
        "IPv4 Dst is a reserved address"
    },
    {
        event_description::Evt_IPv4_Strict_Source_Route_Len_Truncated,
        rule_ids::Rule_Id_IPv4_Strict_Source_Route_Len_Truncated,
        "IPv4 options: strict source route length is truncated"
    },
    {
        event_description::Evt_IPv4_Total_Len_Smaller_Than_Hdr_Len,
        rule_ids::Rule_Id_IPv4_Total_Len_Smaller_Than_Hdr_Len,
        "IPv4 total length is smaller than header length"
    },
    {
        event_description::Evt_IPSec_AH_Inval_Len,
        rule_ids::Rule_Id_IPSec_AH_Inval_Len,
        "IPSec AH length is invalid"
    },
    {
        event_description::Evt_IPSec_AH_Zero_ICV_Len,
        rule_ids::Rule_Id_IPSec_AH_Zero_ICV_Len,
        "IPSec AH ICV length is 0"
    },

    //
    // IPv6 rules
    {
        event_description::Evt_IPV6_Hdrlen_Too_Small,
        rule_ids::Rule_Id_IPv6_Hdrlen_Too_Small,
        "IPv6 header length too small"
    },
    {
        event_description::Evt_IPV6_Version_Invalid,
        rule_ids::Rule_Id_IPv6_Version_Inval,
        "IPv6 invalid version"
    },
    {
        event_description::Evt_IPv6_Payload_Truncated,
        rule_ids::Rule_Id_IPv6_Payload_Truncated,
        "IPv6 payload truncated"
    },
    {
        event_description::Evt_IPv6_Dst_Is_Zero,
        rule_ids::Rule_Id_IPv6_Dst_Is_Zero,
        "IPv6 Destination address is zero"
    },
    {
        event_description::Evt_IPv6_Unsupported_NH,
        rule_ids::Rule_Id_IPv6_Unsupported_NH,
        "IPv6 unsupported next header"
    },
    {
        event_description::Evt_IPv6_Zero_Hop_Limit,
        rule_ids::Rule_Id_IPv6_Zero_Hop_Limit,
        "IPv6 Hoplimit is zero"
    },

    //
    // TCP rules
    {
        event_description::Evt_Tcp_Hdrlen_Too_Short,
        rule_ids::Rule_Id_Tcp_Hdrlen_Too_Short,
        "TCP header length too short"
    },
    {
        event_description::Evt_Tcp_Flags_All_Set,
        rule_ids::Rule_Id_Tcp_Flags_All_Set,
        "TCP all flags are set"
    },
    {
        event_description::Evt_Tcp_Flags_None_Set,
        rule_ids::Rule_Id_Tcp_Flags_None_Set,
        "TCP no flags are set"
    },
    {
        event_description::Evt_Tcp_Invalid_Option,
        rule_ids::Rule_Id_Tcp_Invalid_Option,
        "TCP Invalid option"
    },
    {
        event_description::Evt_Tcp_Opt_Ts_Inval_Len,
        rule_ids::Rule_Id_Tcp_Opt_Ts_Inval_Len,
        "TCP option Timestamp has invalid length"
    },
    {
        event_description::Evt_Tcp_Opt_Win_Scale_Inval_Len,
        rule_ids::Rule_Id_Tcp_Opt_Win_Scale_Inval_Len,
        "TCP option window scale has invalid length"
    },
    {
        event_description::Evt_Tcp_Opt_MSS_Repeated,
        rule_ids::Rule_Id_Tcp_Opt_MSS_Repeated,
        "TCP option MSS is repeated in the packet"
    },
    {
        event_description::Evt_Tcp_Opt_SACK_Permitted_Repeated,
        rule_ids::Rule_Id_Tcp_Opt_SACK_Permitted_Repeated,
        "TCP option SACK_Permitted is repated in the packet"
    },
    {
        event_description::EvT_Tcp_Opt_Ts_Repeated,
        rule_ids::Rule_Id_Tcp_Opt_Ts_Repeated,
        "TCP option TS repeated in the packet"
    },
    {
        event_description::Evt_Tcp_Opt_WinScale_Repeated,
        rule_ids::Rule_Id_Tcp_Opt_WinScale_Repeated,
        "TCP option Window Scale is repeated in the packet"
    },
    {
        event_description::Evt_Tcp_Flags_SYN_FIN_Set,
        rule_ids::Rule_Id_Tcp_Flags_SYN_FIN_Set,
        "TCP Flags SYN + FIN is set"
    },
    {
        event_description::Evt_Tcp_Src_Port_Zero,
        rule_ids::Rule_Id_Tcp_Src_Port_Zero,
        "TCP source port is 0"
    },
    {
        event_description::Evt_Tcp_Dst_Port_Zero,
        rule_ids::Rule_Id_Tcp_Dst_Port_Zero,
        "TCP destination port is 0"
    },

    //
    // UDP rules
    {
        event_description::Evt_Udp_Src_Port_Invalid,
        rule_ids::Rule_Id_Udp_Src_Port_Invalid,
        "UDP source port invalid"
    },
    {
        event_description::Evt_Udp_Dst_Port_Invalid,
        rule_ids::Rule_Id_Udp_Dst_Port_Invalid,
        "UDP destination port invalid"
    },
    {
        event_description::Evt_Udp_Len_Too_Short,
        rule_ids::Rule_Id_Udp_Len_Too_Short,
        "UDP header length is too short"
    },
    {
        event_description::Evt_Udp_Chksum_Invalid,
        rule_ids::Rule_Id_Udp_Chksum_Invalid,
        "UDP checksum is invalid"
    },
    {
        event_description::Evt_Udp_Bogus_Msg_Len,
        rule_ids::Rule_Id_Udp_Bogus_Msg_Len,
        "UDP message length is bogus"
    },
    {
        event_description::Evt_Udp_Hdr_Msg_Len_Too_Big,
        rule_ids::Rule_Id_Udp_Hdr_Msg_Len_Too_Big,
        "UDP message length in header is too big against actual message length"
    },

    //
    // ICMP rules
    {
        event_description::Evt_Icmp_Hdr_Len_Too_Short,
        rule_ids::Rule_Id_Icmp_Hdr_Len_Too_Short,
        "ICMP header length is too small"
    },
    {
        event_description::Evt_Icmp_Echo_Req_Hdr_Len_Too_Short,
        rule_ids::Rule_Id_Icmp_Echo_Req_Hdr_Len_Too_Short,
        "ICMP echo request length is too small"
    },
    {
        event_description::Evt_Icmp_Echo_Reply_Hdr_Len_Too_Short,
        rule_ids::Rule_Id_Icmp_Echo_Reply_Hdr_Len_Too_Short,
        "ICMP echo reply length is too small"
    },
    {
        event_description::Evt_Icmp_Ts_Msg_Hdr_Len_Too_Short,
        rule_ids::Rule_Id_Icmp_Ts_Msg_Hdr_Len_Too_Short,
        "ICMP Timestamp message header length is too small"
    },
    {
        event_description::Evt_Icmp_Info_Msg_Hdr_Len_Too_Short,
        rule_ids::Rule_Id_Icmp_Info_Msg_Hdr_Len_Too_Short,
        "ICMP info message header length is too small"
    },
    {
        event_description::Evt_Icmp_Invalid_Type,
        rule_ids::Rule_Id_Icmp_Invalid_Type,
        "ICMP invalid type"
    },
    {
        event_description::Evt_Icmp_Time_Exceeded_Invalid_Code,
        rule_ids::Rule_Id_Icmp_Time_Exceeded_Invalid_Code,
        "ICMP timestamp exceeed has invalid code"
    },
    {
        event_description::Evt_Icmp_Dest_Unreachable_Invalid_Code,
        rule_ids::Rule_Id_Icmp_Dest_Unreachable_Invalid_Code,
        "ICMP destination unreachable has invalid code"
    },
    {
        //
        // attacker is using ICMP to pass the content in the echo-req and echo-reply frames.
        event_description::Evt_Icmp_Covert_Channel_Maybe_Active,
        rule_ids::Rule_Id_Icmp_Covert_Channel_Maybe_Active,
        "ICMP covert channel may be active"
    },
    {
        event_description::Evt_Icmp_Inval_Redir_Msg_Code,
        rule_ids::Rule_Id_Icmp_Inval_Redir_Msg_Code,
        "ICMP redirect type has invalid code"
    },
    {
        event_description::Evt_Icmp_Inval_Echo_Req_Code,
        rule_ids::Rule_Id_Icmp_Inval_Echo_Req_Code,
        "ICMP echo request type has invalid code"
    },
    {
        event_description::Evt_Icmp_Inval_Echo_Reply_Code,
        rule_ids::Rule_Id_Icmp_Inval_Echo_Reply_Code,
        "ICMP echo reply has invalid code"
    },
    {
        event_description::Evt_Icmp_Inval_Ts_Code,
        rule_ids::Rule_Id_Icmp_Inval_Ts_Code,
        "ICMP timestamp has invalid code"
    },
    {
        event_description::Evt_Icmp_Inval_Info_Code,
        rule_ids::Rule_Id_Icmp_Inval_Info_Code,
        "ICMP info has invalid code"
    },
    {
        event_description::Evt_Icmp_Inval_Chksum,
        rule_ids::Rule_Id_Icmp_Inval_Chksum,
        "ICMP checksum is invalid"
    },
    {
        event_description::Evt_Icmp_Pkt_Fragmented,
        rule_ids::Rule_Id_Icmp_Pkt_Fragmented,
        "ICMP packet is fragmented"
    },
    {
        event_description::Evt_Icmp_Dest_Addr_Multicast_In_IPv4,
        rule_ids::Rule_Id_Icmp_Dest_Addr_Multicast_In_IPv4,
        "ICMP destination address is Multicast in IPv4 Packet"
    },
    {
        event_description::Evt_Icmp_Dest_Addr_Broadcast_In_IPv4,
        rule_ids::Rule_Id_Icmp_Dest_Addr_Broadcast_In_IPv4,
        "ICMP destination address is Broadcast in IPv4 Packet"
    },
    {
        event_description::Evt_Icmp_Addr_Mask_Len_Inval,
        rule_ids::Rule_Id_Icmp_Addr_Mask_Len_Inval,
        "ICMP Address Mask length invalid"
    },
    {
        event_description::Evt_Icmp_Src_IPv4_Addr_Is_Direct_Broadcast,
        rule_ids::Rule_Id_Icmp_Src_IPv4_Addr_Is_Direct_Broadcast,
        "ICMP sender's address is a directed broadcast address"
    },

    //
    // DHCP rules
    {
        event_description::Evt_DHCP_MAGIC_Invalid,
        rule_ids::Rule_Id_DHCP_MAGIC_Invalid,
        "DHCP magic is invalid"
    },
    {
        event_description::Evt_DHCP_Opt_Client_Id_Len_Inval,
        rule_ids::Rule_Id_DHCP_Opt_Client_Id_Len_Inval,
        "DHCP options: client id length is invalid"
    },
    {
        event_description::Evt_DHCP_Opt_SubnetMask_Len_Inval,
        rule_ids::Rule_Id_DHCP_Opt_SubnetMask_Len_Inval,
        "DHCP options: subnet mask length is invalid"
    },
    {
        event_description::Evt_DHCP_Opt_Renewal_Time_Len_Inval,
        rule_ids::Rule_Id_DHCP_Opt_Renewal_Time_Len_Inval,
        "DHCP options: renewal time length is invalid"
    },
    {
        event_description::Evt_DHCP_Opt_Ipaddr_Lease_Time_Len_Inval,
        rule_ids::Rule_Id_DHCP_Opt_Ipaddr_Lease_Time_Len_Inval,
        "DHCP options: ipaddr lease time length is invalid"
    },
    {
        event_description::Evt_DHCP_Opt_Server_Id_Len_Inval,
        rule_ids::Rule_Id_DHCP_Opt_Server_Id_Len_Inval,
        "DHCP options: server_id length is invalid"
    },
    {
        event_description::Evt_DHCP_Hdr_Len_Too_Short,
        rule_ids::Rule_Id_DHCP_Hdr_Len_Too_Short,
        "DHCP default header length (no options) is too small"
    },

    //
    // ICMP6 rules
    {
        event_description::Evt_Icmp6_Icmp6_Type_Unsupported,
        rule_ids::Rule_Id_Icmp6_Icmp6_Type_Unsupported,
        "ICMP6 Type unsupported"
    },
    {
        event_description::Evt_Icmp6_Mcast_Listener_Inval_Rec_Len,
        rule_ids::Rule_Id_Icmp6_Mcast_Listener_Inval_Rec_Len,
        "ICMP6 Invalid Mcast Listener record length"
    },
    {
        event_description::Evt_Icmp6_Echo_Req_Hdr_Len_Too_Short,
        rule_ids::Rule_Id_Icmp6_Echo_Req_Hdr_Len_Too_Short,
        "ICMP6 echo request header length is too short"
    },

    //
    // DoIP rules
    {
        event_description::Evt_DoIP_Hdrlen_Too_Small,
        rule_ids::Rule_Id_DoIP_Hdrlen_Too_Small,
        "DoIP header length too small"
    },
    {
        event_description::Evt_DoIP_Unsupported_Msg_Type,
        rule_ids::Rule_Id_DoIP_Unsupported_Msg_Type,
        "DoIP unsupported message type"
    },
    {
        event_description::Evt_DoIP_Veh_Announce_Too_Small,
        rule_ids::Rule_Id_DoIP_Veh_Announce_Too_Small,
        "DoIP Veh Announcement length too small"
    },
    {
        event_description::Evt_DoIP_Version_Mismatch,
        rule_ids::Rule_Id_DoIP_Version_Mismatch,
        "DoIP version mismatched"
    },

    //
    // MQTT rules
    {
        event_description::Evt_MQTT_Inval_Msg_Type,
        rule_ids::Rule_Id_MQTT_Inval_Msg_Type,
        "MQTT invalid message type"
    },

    //
    // SOME/IP rules
    {
        event_description::Evt_SomeIP_Hdr_Len_Too_Small,
        rule_ids::Rule_Id_SomeIP_Hdr_Len_Too_Small,
        "SOME/IP header length is too small"
    },

    //
    // Port rules
    {
        event_description::Evt_Port_Matched,
        rule_ids::Rule_Id_Port_Matched,
        "Port Matched in the ruleset",
    },

    //
    // Rules matched by the Exploit filter
    {
        event_description::Evt_Known_Exploit_Win32_Blaster,
        rule_ids::Rule_Id_Known_Exploit_Win32_Blaster,
        "Suspected Win32.Blaster worm"
    },

    {
        event_description::Evt_Unknown_Error,
        rule_ids::Rule_Id_Unknown,
        "Unknown error"
    },
};

/**
 * @brief - event_type to string matching.
*/
const struct {
    event_type type;
    std::string str;
} evt_type_str_map[] = {
    {
        event_type::Evt_Allow, "Allow"
    },
    {
        event_type::Evt_Deny, "Deny",
    },
    {
        event_type::Evt_Alert, "Alert",
    }
};

const std::string event_mgr::evt_type_str(event_type type)
{
    for (auto it : evt_type_str_map) {
        if (it.type == type) {
            return it.str;
        }
    }

    return "Unknown";
}

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

    std::memcpy(evt.src_mac, pkt.eh.src_mac, sizeof(pkt.eh.src_mac));
    std::memcpy(evt.dst_mac, pkt.eh.dst_mac, sizeof(pkt.eh.dst_mac));

    //
    // if vlan header is present, get ethertype from vlan header
    evt.ethertype = pkt.eh.ethertype;
    if (pkt.protocols_avail.has_vlan()) {
        evt.ethertype = pkt.vh.ethertype;
    }

    switch (evt.ethertype) {
        case static_cast<uint16_t>(Ether_Type::Ether_Type_IPv4):
            evt.protocol = pkt.ipv4_h.protocol;
            evt.ttl = pkt.ipv4_h.ttl;
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

    if (fw_conf->evt_config.upload_method == Event_Upload_Method_Type::MQTT) {
        auto r = mqtt_uploader_.init(log_);
        if (r != 0) {
            return fw_error_type::eInvalid;
        }
        log_->info("evt_mgr::init: create MQTT uploader\n");
    }

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
 * @brief - Get the matching event description string
 */
static std::string get_matching_event_desc_str(event_description evt_desc)
{
    for (auto i : auto_det_rule_id_list) {
        if (i.evt == evt_desc) {
            return i.desc;
        }
    }

    return "Unknown";
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

void event_mgr::store(event_type evt_type,
                      event_description evt_desc,
                      uint32_t rule_id,
                      const parser &pkt)
{
    event evt;

    create_evt(evt, rule_id, evt_type, evt_desc, pkt);
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
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
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

                //
                // if enabled, write to syslog as well
                if (conf->evt_config.log_to_syslog) {
                    log_syslog(evt);
                }

                //
                // if enabled, write to console as well
                if (conf->evt_config.log_to_console) {
                    log_console(evt);
                }

                //
                // if enabled, write to MQTT connection
                if (conf->evt_config.upload_method == Event_Upload_Method_Type::MQTT) {
                    mqtt_upload(evt);
                }
                event_list_.pop();
            }
        }
    }
}

void event_mgr::make_evt_string(event &evt, std::string &fmt)
{
    char msg[1024];
    int len = 0;

    len += snprintf(msg + len, sizeof(msg) - len,
                    "[%s], Rule_Id: %u, Event_Desc: [%s](%u)  from ",
                    evt_type_str(evt.evt_type).c_str(),
                    evt.rule_id,
                    get_matching_event_desc_str(evt.evt_details).c_str(),
                    static_cast<uint32_t>(evt.evt_details));
    len += snprintf(msg + len, sizeof(msg) - len,
                    "src_mac [%02x:%02x:%02x:%02x:%02x:%02x] "
                    "dst_mac [%02x:%02x:%02x:%02x:%02x:%02x] "
                    "ethertype 0x%04x ",
                    evt.src_mac[0], evt.src_mac[1],
                    evt.src_mac[2], evt.src_mac[3],
                    evt.src_mac[4], evt.src_mac[5],
                    evt.dst_mac[0], evt.dst_mac[1],
                    evt.dst_mac[2], evt.dst_mac[3],
                    evt.dst_mac[4], evt.dst_mac[5],
                    evt.ethertype);
    switch (static_cast<Ether_Type>(evt.ethertype)) {
        case Ether_Type::Ether_Type_IPv4: {
            std::string src_ipaddr;
            std::string dst_ipaddr;

            get_ipaddr(evt.src_addr, src_ipaddr);
            get_ipaddr(evt.dst_addr, dst_ipaddr);
            len += snprintf(msg + len, sizeof(msg) - len,
                            "src_ip %s dst_ip %s ",
                            src_ipaddr.c_str(), dst_ipaddr.c_str());
            len += snprintf(msg + len, sizeof(msg) - len,
                            "protocol %d", evt.protocol);
        } break;
        default:
        break;
    }

    len += snprintf(msg + len, sizeof(msg) - len, "\n");

    fmt = msg;
}

void event_mgr::log_syslog(event &evt)
{
    std::string msg;

    make_evt_string(evt, msg);
    syslog(LOG_ALERT, "%s", msg.c_str());
}

void event_mgr::log_console(event &evt)
{
    std::string msg;

    make_evt_string(evt, msg);
    fprintf(stderr, "%s", msg.c_str());
}

void event_mgr::mqtt_upload(event &e)
{
    event_msg *evt_msg;
    uint8_t msg[4096];
    uint8_t enc_msg[4096];
    event_msg_codec codec;
    int total_len;

    evt_msg = (event_msg *)msg;

    total_len = codec.serialize(e, evt_msg);
    //
    // nothing to be sent.. drop this event.
    if (total_len <= 0) {
        return;
    }

    total_len = codec.hash_and_encrypt(msg, total_len, enc_msg);
    if (total_len > 0)
        mqtt_uploader_.write(enc_msg, total_len);
}

}

