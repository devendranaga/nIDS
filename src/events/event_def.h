/**
 * @brief - Defines event type and description.
 *
 * @copyright - 2023-present All rights reserved. Devendra Naga.
*/
#ifndef __FW_EVENT_DEF_H__
#define __FW_EVENT_DEF_H__

#include <stdint.h>

namespace firewall {

//
// constants set by the firewall.
// these are internally detected by the firewall without having to
// give any rules.
//
// if the firewall detects the corresponding events, it will simply
// block the frame and event with the below corresponding rule and the
// event description.
enum class rule_ids : uint32_t {
    //
    // Ethernet Rule Ids
    Rule_Id_Unsupported_Ethertype = 1,
    Rule_Id_Eth_Hdrlen_Too_Small,

    //
    // MACsec Rule Ids
    Rule_Id_MACsec_Hdr_Len_Too_Small = 101,
    Rule_Id_MACsec_TCI_SC_SCB_Set,
    Rule_Id_MACsec_TCI_ES_SC_Set,

    //
    // ARP Rule Ids
    Rule_Id_ARP_Hdrlen_Too_Small = 201,
    Rule_Id_ARP_HW_Addr_Len_Inval,
    Rule_Id_ARP_Protocol_Addr_Len_Inval,
    Rule_Id_ARP_Inval_Operation,
    Rule_Id_ARP_Flood_Maybe_In_Progress,

    //
    // VLAN Rule Ids
    Rule_Id_Vlan_Hdrlen_Too_Small = 301,
    Rule_Id_Vlan_Id_Inval,

    //
    // IPv4 Rule Ids
    Rule_Id_IPV4_Hdrlen_Too_Small = 401,
    Rule_Id_IPV4_Hdrlen_Too_Big,
    Rule_Id_IPV4_Hdrlen_Inval,
    Rule_Id_IPV4_Version_Invalid,
    Rule_Id_IPV4_Flags_Invalid,
    Rule_Id_IPV4_Hdr_Chksum_Invalid,
    Rule_Id_IPV4_Protocol_Unsupported,
    Rule_Id_IPV4_Unknown_Opt,
    Rule_Id_IPV4_Inval_Src_Addr,
    Rule_Id_IPv4_Zero_TTL,
    Rule_Id_IPv4_Reserved_Set,
    Rule_Id_IPv4_Src_And_Dst_Addr_Same,
    Rule_Id_IPv4_Src_Is_Broadcast,
    Rule_Id_IPv4_Src_Is_Multicast,
    Rule_Id_IPv4_Src_Is_Reserved,
    Rule_Id_IPv4_Dst_Is_Reserved,
    Rule_Id_IPv4_Strict_Source_Route_Len_Truncated,

    //
    // IPv6 Rule Ids
    Rule_Id_IPv6_Payload_Truncated = 501,
    Rule_Id_IPv6_Unsupported_NH,
    Rule_Id_IPv6_Dst_Is_Zero,
    Rule_Id_IPv6_Zero_Hop_Limit,

    //
    // ICMP6 Rule Ids
    Rule_Id_Icmp6_Icmp6_Type_Unsupported = 601,
    Rule_Id_Icmp6_Mcast_Listener_Inval_Rec_Len,

    //
    // TCP Rule Ids
    Rule_Id_Tcp_Hdrlen_Too_Short = 701,
    Rule_Id_Tcp_Flags_All_Set,
    Rule_Id_Tcp_Flags_None_Set,
    Rule_Id_Tcp_Invalid_Option,
    Rule_Id_Tcp_Opt_Ts_Inval_Len,
    Rule_Id_Tcp_Opt_Win_Scale_Inval_Len,
    Rule_Id_Tcp_Opt_MSS_Repeated,
    Rule_Id_Tcp_Opt_SACK_Permitted_Repeated,
    Rule_Id_Tcp_Opt_Ts_Repeated,
    Rule_Id_Tcp_Opt_WinScale_Repeated,
    Rule_Id_Tcp_Flags_SYN_FIN_Set,
    Rule_Id_Tcp_Src_Port_Zero,
    Rule_Id_Tcp_Dst_Port_Zero,

    //
    // UDP Rule Ids
    Rule_Id_Udp_Src_Port_Invalid = 901,
    Rule_Id_Udp_Dst_Port_Invalid,
    Rule_Id_Udp_Chksum_Invalid,
    Rule_Id_Udp_Len_Too_Short,
    Rule_Id_Udp_Bogus_Msg_Len,
    Rule_Id_Udp_Hdr_Msg_Len_Too_Big,

    //
    // ICMP Rule Ids
    Rule_Id_Icmp_Hdr_Len_Too_Short = 1001,
    Rule_Id_Icmp_Echo_Req_Hdr_Len_Too_Short,
    Rule_Id_Icmp_Echo_Reply_Hdr_Len_Too_Short,
    Rule_Id_Icmp_Ts_Msg_Hdr_Len_Too_Short,
    Rule_Id_Icmp_Info_Msg_Hdr_Len_Too_Short,
    Rule_Id_Icmp_Covert_Channel_Maybe_Active,
    Rule_Id_Icmp_Invalid_Type,
    Rule_Id_Icmp_Dest_Unreachable_Invalid_Code,
    Rule_Id_Icmp_Time_Exceeded_Invalid_Code,
    Rule_Id_Icmp_Inval_Redir_Msg_Code,
    Rule_Id_Icmp_Inval_Echo_Req_Code,
    Rule_Id_Icmp_Inval_Echo_Reply_Code,
    Rule_Id_Icmp_Inval_Ts_Code,
    Rule_Id_Icmp_Inval_Info_Code,
    Rule_Id_Icmp_Inval_Chksum,
    Rule_Id_Icmp_Pkt_Fragmented,
    Rule_Id_Icmp_Dest_Addr_Multicast_In_IPv4,
    Rule_Id_Icmp_Dest_Addr_Broadcast_In_IPv4,
    Rule_Id_Icmp_Addr_Mask_Len_Inval,

    //
    // DHCP Rule Ids
    Rule_Id_DHCP_MAGIC_Invalid = 1101,
    Rule_Id_DHCP_Opt_Client_Id_Len_Inval,
    Rule_Id_DHCP_Opt_SubnetMask_Len_Inval,
    Rule_Id_DHCP_Opt_Renewal_Time_Len_Inval,
    Rule_Id_DHCP_Opt_Rebinding_Time_Len_Inval,
    Rule_Id_DHCP_Opt_Ipaddr_Lease_Time_Len_Inval,
    Rule_Id_DHCP_Opt_Server_Id_Len_Inval,
    Rule_Id_DHCP_Hdr_Len_Too_Short,

    //
    // TLS Rule Ids
    Rule_Id_TLS_Version_Unsupported = 1201,

    //
    // DoIP Rule Ids
    Rule_Id_DoIP_Hdrlen_Too_Small = 1401,
    Rule_Id_DoIP_Version_Mismatch,
    Rule_Id_DoIP_Unsupported_Msg_Type,
    Rule_Id_DoIP_Veh_Announce_Too_Small,
    Rule_Id_DoIP_Entity_Status_Response_Too_Small,
    Rule_Id_DoIP_Route_Activation_Req_Too_Small,

    //
    // UDS Rule Ids
    Rule_Id_Uds_Unknown_Service_Id = 1501,

    //
    // MQTT Rule Ids
    Rule_Id_MQTT_Inval_Msg_Type = 1601,

    //
    // SOME/IP Rule Ids
    Rule_Id_SomeIP_Hdr_Len_Too_Small = 1701,

    //
    // Known Malware / Virus / Explit Rule Ids
    Rule_Id_Known_Exploit_Win32_Blaster = 1601,

    Rule_Id_Unknown,
};

//
// event description contains exactly what type of event has occured
enum class event_description : uint32_t {
    //
    // Ethernet events
    Evt_Eth_Src_Mac_Matched = 1,
    Evt_Eth_Dst_Mac_Matched,
    Evt_Eth_Ethertype_Matched,
    Evt_Eth_Ethertype_Unknown,
    Evt_Eth_Hdrlen_Too_Small,

    //
    // MACsec events
    Evt_MACsec_Hdr_Len_Too_Small = 101,
    Evt_MACsec_TCI_SC_SCB_Set,
    Evt_MACsec_TCI_ES_SC_Set,

    //
    // ARP events
    Evt_ARP_Hdrlen_Too_Small = 201,
    Evt_ARP_HW_Addr_Len_Inval,
    Evt_ARP_Protocol_Addr_Len_Inval,
    Evt_ARP_Inval_Operation,
    Evt_ARP_Flood_Maybe_In_Progress,

    //
    // VLAN events
    Evt_VLAN_Hdrlen_Too_Short = 301,
    Evt_VLAN_Inval_VID,

    //
    // IPv4 events
    Evt_IPV4_Hdrlen_Too_Small = 401,
    Evt_IPV4_Hdrlen_Too_Big,
    Evt_IPV4_Hdrlen_Inval,
    Evt_IPV4_Version_Invalid,
    Evt_IPV4_Flags_Invalid,
    Evt_IPV4_Hdr_Chksum_Invalid,
    Evt_IPV4_Protocol_Unsupported,
    Evt_IPV4_Unknown_Opt,
    Evt_IPV4_Inval_Src_Addr,
    Evt_IPv4_Zero_TTL,
    Evt_IPv4_Reserved_Set,
    Evt_IPv4_Src_And_Dst_Addr_Same,
    Evt_IPv4_Src_Is_Broadcast,
    Evt_IPv4_Src_Is_Multicast,
    Evt_IPv4_Src_Is_Reserved,
    Evt_IPv4_Dst_Is_Reserved,
    Evt_IPv4_Strict_Source_Route_Len_Truncated,

    //
    // IPv6 events
    Evt_IPV6_Hdrlen_Too_Small = 501,
    Evt_IPV6_Version_Invalid,
    Evt_IPv6_Payload_Truncated,
    Evt_IPv6_Unsupported_NH,
    Evt_IPv6_Dst_Is_Zero,
    Evt_IPv6_Zero_Hop_Limit,

    //
    // ICMP6 events
    Evt_Icmp6_Icmp6_Type_Unsupported = 601,
    Evt_Icmp6_Mcast_Listener_Inval_Rec_Len,

    //
    // TCP events
    Evt_Tcp_Hdrlen_Too_Short = 701,
    Evt_Tcp_Flags_All_Set,
    Evt_Tcp_Flags_None_Set,
    Evt_Tcp_Invalid_Option,
    Evt_Tcp_Opt_Ts_Inval_Len,
    Evt_Tcp_Opt_Win_Scale_Inval_Len,
    Evt_Tcp_Opt_MSS_Repeated,
    Evt_Tcp_Opt_SACK_Permitted_Repeated,
    EvT_Tcp_Opt_Ts_Repeated,
    Evt_Tcp_Opt_WinScale_Repeated,
    Evt_Tcp_Flags_SYN_FIN_Set,
    Evt_Tcp_Src_Port_Zero,
    Evt_Tcp_Dst_Port_Zero,

    //
    // UDP events
    Evt_Udp_Src_Port_Invalid = 901,
    Evt_Udp_Dst_Port_Invalid,
    Evt_Udp_Chksum_Invalid,
    Evt_Udp_Len_Too_Short,
    Evt_Udp_Bogus_Msg_Len,
    Evt_Udp_Hdr_Msg_Len_Too_Big,

    //
    // ICMP events
    Evt_Icmp_Hdr_Len_Too_Short = 1001,
    Evt_Icmp_Echo_Req_Hdr_Len_Too_Short,
    Evt_Icmp_Echo_Reply_Hdr_Len_Too_Short,
    Evt_Icmp_Ts_Msg_Hdr_Len_Too_Short,
    Evt_Icmp_Info_Msg_Hdr_Len_Too_Short,
    Evt_Icmp_Covert_Channel_Maybe_Active,
    Evt_Icmp_Invalid_Type,
    Evt_Icmp_Dest_Unreachable_Invalid_Code,
    Evt_Icmp_Time_Exceeded_Invalid_Code,
    Evt_Icmp_Inval_Redir_Msg_Code,
    Evt_Icmp_Inval_Echo_Req_Code,
    Evt_Icmp_Inval_Echo_Reply_Code,
    Evt_Icmp_Inval_Ts_Code,
    Evt_Icmp_Inval_Info_Code,
    Evt_Icmp_Pkt_Fragmented,
    Evt_Icmp_Dest_Addr_Multicast_In_IPv4,
    Evt_Icmp_Dest_Addr_Broadcast_In_IPv4,
    Evt_Icmp_Addr_Mask_Len_Inval,
    Evt_Icmp_Inval_Chksum,

    //
    // DHCP events
    Evt_DHCP_MAGIC_Invalid = 1101,
    Evt_DHCP_Opt_Client_Id_Len_Inval,
    Evt_DHCP_Opt_SubnetMask_Len_Inval,
    Evt_DHCP_Opt_Renewal_Time_Len_Inval,
    Evt_DHCP_Opt_Rebinding_Time_Len_Inval,
    Evt_DHCP_Opt_Ipaddr_Lease_Time_Len_Inval,
    Evt_DHCP_Opt_Server_Id_Len_Inval,
    Evt_DHCP_Hdr_Len_Too_Short,

    //
    // TLS events
    Evt_TLS_Version_Unsupported = 1201,

    //
    // DoIP events
    Evt_DoIP_Hdrlen_Too_Small = 1301,
    Evt_DoIP_Version_Mismatch,
    Evt_DoIP_Unsupported_Msg_Type,
    Evt_DoIP_Veh_Announce_Too_Small,
    Evt_DoIP_Entity_Status_Response_Too_Small,
    Evt_DoIP_Route_Activation_Req_Too_Small,

    //
    // UDS events
    Evt_Uds_Unknown_Service_Id = 1401,

    //
    // MQTT events
    Evt_MQTT_Inval_Msg_Type = 1501,

    //
    // SOMEIP events
    Evt_SomeIP_Hdr_Len_Too_Small = 1601,

    //
    // Known virus / exploit / worm / malware events
    Evt_Known_Exploit_Win32_Blaster = 10000,
    Evt_Unknown_Port,
    Evt_Unknown_Error,

    //
    // Device the firewall runs is out of memory
    Evt_Out_Of_Memory = 0x10101010,

    //
    // Parsed ok.. all good
    Evt_Parse_Ok = 0xA0B0C0D0,
};

//
// Type of event
enum class event_type {
    Evt_Allow,
    Evt_Deny,
    Evt_Alert,
};

}

#endif

