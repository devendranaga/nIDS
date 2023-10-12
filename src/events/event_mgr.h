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

        fw_error_type init(logger *log);
        void store(event &evt);

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

