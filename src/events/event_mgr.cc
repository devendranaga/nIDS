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
    {event_description::Evt_Eth_Ethertype_Unknown,
     rule_ids::Rule_Id_Unsupported_Ethertype},

    {event_description::Evt_ARP_Hdrlen_Too_Small,
     rule_ids::Rule_Id_ARP_Hdrlen_Too_Small},

    {event_description::Evt_ARP_HW_Addr_Len_Inval,
     rule_ids::Rule_Id_ARP_HW_Addr_Len_Inval},

    {event_description::Evt_ARP_Protocol_Addr_Len_Inval,
     rule_ids::Rule_Id_ARP_Protocol_Addr_Len_Inval},

    {event_description::Evt_ARP_Inval_Operation,
     rule_ids::Rule_Id_ARP_Inval_Operation},

    {event_description::Evt_IPV4_Hdrlen_Too_Small,
     rule_ids::Rule_Id_IPV4_Hdrlen_Too_Small},

    {event_description::Evt_IPV4_Hdrlen_Too_Big,
     rule_ids::Rule_Id_IPV4_Hdrlen_Too_Big},

    {event_description::Evt_IPV4_Hdrlen_Inval,
     rule_ids::Rule_Id_IPV4_Hdrlen_Inval},

    {event_description::Evt_IPV4_Version_Invalid,
     rule_ids::Rule_Id_IPV4_Version_Invalid},

    {event_description::Evt_IPV4_Flags_Invalid,
     rule_ids::Rule_Id_IPV4_Flags_Invalid},

    {event_description::Evt_IPV4_Hdr_Chksum_Invalid,
     rule_ids::Rule_Id_IPV4_Hdr_Chksum_Invalid},

    {event_description::Evt_IPV4_Protocol_Unsupported,
     rule_ids::Rule_Id_IPV4_Protocol_Unsupported},

    {event_description::Evt_Unknown_Error,
     rule_ids::Rule_Id_Unknown},
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

    std::memcpy(evt.src_mac, pkt.eh.src_mac, sizeof(pkt.eh.src_mac));
    std::memcpy(evt.dst_mac, pkt.eh.dst_mac, sizeof(pkt.eh.dst_mac));
    evt.ethertype = pkt.eh.ethertype;
    switch (pkt.eh.ethertype) {
        case static_cast<uint16_t>(ether_type::Ether_Type_IPv4):
            evt.protocol = pkt.ipv4_h.protocol;
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
    while (1) {
        // wake up every second and write the collected event logs
        // to disk.
        std::this_thread::sleep_for(std::chrono::seconds(1));
        {
            std::unique_lock<std::mutex> lock(storage_thr_lock_);
            int q_len = 0;

            for (q_len = event_list_.size(); q_len > 0; q_len = event_list_.size()) {
                event evt = event_list_.front();

                // write to the event log
                evt_file_w_.write(evt);
                event_list_.pop();
            }
        }
    }
}

}

