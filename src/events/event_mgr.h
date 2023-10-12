#ifndef __FW_EVENT_MGR_H__
#define __FW_EVENT_MGR_H__

#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <event_def.h>
#include <logger.h>
#include <common.h>

namespace firewall {

class event_mgr {
    public:
        ~event_mgr();
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
        std::condition_variable storage_thr_cond_;
        std::queue<event> event_list_;
        logger *log_;
};

}

#endif

