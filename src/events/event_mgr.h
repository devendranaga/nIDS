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
#include <common.h>
#include <event_def.h>
#include <config.h>
#include <logger.h>
#include <common.h>
#include <parser.h>
#include <event.h>
#include <event_file_writer.h>
#include <event_mqtt.h>
#include <event_msg_codec.h>

namespace firewall {

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

        /**
         * @brief - init the event manager.
         * 
         * @param [in] log - logger
         * 
         * @return fw_error_type.
        */
        fw_error_type init(logger *log);

        /**
         * @brief - store logs temporarily in the queue and pass it to the storage thread.
         *
         * Called by the parser or filter code.
         *
         * @param [in] evt - firewall event structure.
        */
        void store(event &evt);

        /**
         * @brief - get matching rule id for given event.
         *
         * This is Applicable only for auto detected events.
         *
         * @param [in] evt_desc - event description
         * @param [out] rule id match with the given event.
        */
        uint32_t get_matching_rule(event_description evt_desc);
        void store(event_type evt_type,
                   event_description evt_desc, const parser &pkt);
        void store(event_type evt_type,
                   event_description evt_desc,
                   uint32_t rule_id,
                   const parser &pkt);

    private:
        explicit event_mgr() { }
        void storage_thread();
        /**
         * @brief - creates an L4 event with tcp, udp and other protocols
         *
         * @param [inout] evt - event input
         * @param [in] pkt - parsed packet
        */
        void create_l4_evt(event &evt,
                           const parser &pkt);
        void create_evt(event &evt,
                        uint32_t rule_id,
                        event_type evt_type,
                        event_description evt_details,
                        const parser &pkt);
        /**
         * @brief - Log event to syslog.
         *
         * @param [in] evt - event
        */
        void log_syslog(event &evt);

        /**
         * @brief - Log event to console.
         *
         * @param [in] evt - event
        */
        void log_console(event &evt);
        /**
         * @brief - make L4 event string with TCP and UDP ports.
         *
         * @param [in] evt - event input
         * @param [inout] in - string buffer to write text event
         * @param [in] in_len - length of remaining in buffer
         *
         * @return return the number of written bytes
        */
        int make_evt_string_l4(event &evt, char *in, size_t in_len);
        void make_evt_string(event &evt, std::string &fmt);
        const std::string evt_type_str(event_type type);
        void mqtt_upload(event &evt);

        std::shared_ptr<std::thread> storage_thr_id_;
        event_file_writer evt_file_w_;
        std::mutex storage_thr_lock_;
        std::queue<event> event_list_;
        mqtt_publisher mqtt_uploader_;
        logger *log_;
};

}

#endif

