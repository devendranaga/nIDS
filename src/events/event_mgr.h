/**
 * @brief - implements event management.
 * 
 * @copyright - 2023-present All rights reserved. Devendra Naga.
*/
#ifndef __FW_EVENT_MGR_H__
#define __FW_EVENT_MGR_H__

#include <memory>
#include <thread>
#include <mutex>
#include <queue>
#include <event_def.h>
#include <logger.h>
#include <common.h>
#include <parser.h>

namespace firewall {

/**
 * @brief - a detailed event information.
 * 
 * This is further used in storing an event temporarily.
*/
struct event {
    event_type evt_type;
    event_description evt_details;
    // matched rule id
    uint32_t rule_id;
    uint8_t src_mac[6];
    uint8_t dst_mac[6];
    uint16_t ethertype;
    uint32_t protocol;
    uint32_t src_port;
    uint32_t dst_port;
    uint32_t pkt_len;

    explicit event() : evt_type(event_type::Evt_Deny),
                       evt_details(event_description::Evt_Unknown_Error),
                       rule_id(0),
                       ethertype(0),
                       protocol(0),
                       src_port(0),
                       dst_port(0),
                       pkt_len(0)
    {
        memset(src_mac, 0, sizeof(src_mac));
        memset(dst_mac, 0, sizeof(dst_mac));
    }
    ~event() { }

    void create(uint32_t rule_id,
                event_type evt_type,
                event_description evt_details,
                const parser &pkt);
};

/**
 * @brief - implements capture and store of firewall events into a file.
*/
class event_mgr {
    public:
        ~event_mgr() { }
        static event_mgr *instance()
        {
            static event_mgr mgr;
            return &mgr;
        }

        fw_error_type init(logger *log);
        void store(event &evt);
        uint32_t get_matching_rule(event_description evt_desc);
        void store(event_type evt_type,
                   event_description evt_desc, const parser &pkt);

    private:
        explicit event_mgr() { }
        void storage_thread();
 
        std::shared_ptr<std::thread> storage_thr_id_;
        std::mutex storage_thr_lock_;
        std::queue<event> event_list_;
        logger *log_;
};

}

#endif

