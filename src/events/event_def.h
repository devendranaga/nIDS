/**
 * @brief - Defines event type and description.
 *
 * @copyright - 2023-present All rights reserved. Devendra Naga.
*/
#ifndef __FW_EVENT_DEF_H__
#define __FW_EVENT_DEF_H__

namespace firewall {

//
// constants set by the firewall.
// these are internally detected by the firewall without having to
// give any rules.
//
// if the firewall detects the corresponding events, it will simply
// block the frame and event with the below corresponding rule and the
// event description.
enum class rule_ids {
    Rule_Id_Unsupported_Ethertype = 0x00000001,
    Rule_Id_Eth_Hdrlen_Too_Small,
    Rule_Id_ARP_Hdrlen_Too_Small,
    Rule_Id_ARP_HW_Addr_Len_Inval,
    Rule_Id_ARP_Protocol_Addr_Len_Inval,
    Rule_Id_ARP_Inval_Operation,
    Rule_Id_Vlan_Hdrlen_Too_Small,
    Rule_Id_Vlan_Id_Inval,
    Rule_Id_IPV4_Hdrlen_Too_Small,
    Rule_Id_IPV4_Hdrlen_Too_Big,
    Rule_Id_IPV4_Hdrlen_Inval,
    Rule_Id_IPV4_Version_Invalid,
    Rule_Id_IPV4_Flags_Invalid,
    Rule_Id_IPV4_Hdr_Chksum_Invalid,
    Rule_Id_IPV4_Protocol_Unsupported,
    Rule_Id_Udp_Src_Port_Invalid,
    Rule_Id_Udp_Dst_Port_Invalid,
    Rule_Id_Udp_Chksum_Invalid,
    Rule_Id_Udp_Len_Too_Short,
    Rule_Id_Icmp_Invalid_Type,
    Rule_Id_DHCP_MAGIC_Invalid,
    Rule_Id_Unknown,
};

//
// event description contains exactly what type of event has occured
enum class event_description {
    Evt_Eth_Src_Mac_Matched = 1,
    Evt_Eth_Dst_Mac_Matched,
    Evt_Eth_Ethertype_Matched,
    Evt_Eth_Ethertype_Unknown,
    Evt_Eth_Hdrlen_Too_Small,
    Evt_ARP_Hdrlen_Too_Small,
    Evt_ARP_HW_Addr_Len_Inval,
    Evt_ARP_Protocol_Addr_Len_Inval,
    Evt_ARP_Inval_Operation,
    Evt_VLAN_Hdrlen_Too_Short,
    Evt_VLAN_Inval_VID,
    Evt_IPV4_Hdrlen_Too_Small,
    Evt_IPV4_Hdrlen_Too_Big,
    Evt_IPV4_Hdrlen_Inval,
    Evt_IPV4_Version_Invalid,
    Evt_IPV4_Flags_Invalid,
    Evt_IPV4_Hdr_Chksum_Invalid,
    Evt_IPV4_Protocol_Unsupported,
    Evt_IPV6_Hdrlen_Too_Small,
    Evt_IPV6_Version_Invalid,
    Evt_Icmp6_Icmp6_Type_Unsupported,
    Evt_Udp_Src_Port_Invalid,
    Evt_Udp_Dst_Port_Invalid,
    Evt_Udp_Chksum_Invalid,
    Evt_Udp_Len_Too_Short,
    Evt_Icmp_Invalid_Type,
    Evt_DHCP_MAGIC_Invalid,
    Evt_Unknown_Error,
    Evt_Parse_Ok,
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

