#include <event_mgr.h>

namespace firewall {

fw_error_type event_mgr::init(logger *log)
{
    log_ = log;

    // create storage thread
    storage_thr_id_ = std::make_shared<std::thread>(
                        &event_mgr::storage_thread, this);
    storage_thr_id_->detach();

    log_->info("evt_mgr::init: create storage thread ok\n");

    return fw_error_type::eNo_Error;
}

void event_mgr::store(event &evt)
{
    {
        std::unique_lock<std::mutex> lock(storage_thr_lock_);
        event_list_.push(evt);
    }
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
    }
}

}

