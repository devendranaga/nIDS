#include <event_mgr.h>

namespace firewall {

fw_error_type event_mgr::init(logger *log)
{
    storage_thr_id_ = std::make_shared<std::thread>(
                        &event_mgr::storage_thread, this);
    return fw_error_type::eNo_Error;
}

void event_mgr::store(event &evt)
{
    {
        std::unique_lock<std::mutex> lock(storage_thr_lock_);
        event_list_.push(evt);
        storage_thr_cond_.notify_one();
    }
}

}

