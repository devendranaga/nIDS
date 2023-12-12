#ifndef __FW_WATCHDOG_MGR_H__
#define __FW_WATCHDOG_MGR_H__

#include <stdint.h>
#include <time.h>
#include <sys/time.h>
#include <string>
#include <vector>
#include <memory>
#include <thread>
#include <time_util.h>
#include <logger.h>

namespace firewall {

class watchdog_client_info {
    public:
        explicit watchdog_client_info();
        ~watchdog_client_info();

        int store(std::string thread_name);
        bool is_expired();

    private:
        std::string thread_name_;
        struct timespec last_reported_;
        int count_;
};

class watchdog_mgr {
    public:
        ~watchdog_mgr() { }
        static watchdog_mgr *instance()
        {
            static watchdog_mgr mgr;
            return &mgr;
        }

        void init(logger *log);

    private:
        explicit watchdog_mgr() { }
        void monitor_thread();

        logger *log_;
        std::vector<watchdog_client_info> clients_;
        std::unique_ptr<std::thread> monitor_thr_id_;
};

}

#endif
