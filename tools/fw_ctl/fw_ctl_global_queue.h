#ifndef __FW_CTL_GLOBAL_QUEUE_H__
#define __FW_CTL_GLOBAL_QUEUE_H__

#include <stdint.h>
#include <queue>
#include <mutex>
#include <condition_variable>

namespace firewall {

struct queue_msg {
    uint8_t msg[4096];
    uint32_t msg_len;

    explicit queue_msg() : msg_len(0) { }
    ~queue_msg() { }
};

class global_queue {
    public:
        static global_queue *instance()
        {
            static global_queue q;
            return &q;
        }
        void push(queue_msg &msg)
        {
            std::unique_lock<std::mutex> lock(lock_);
            q_list_.push(msg);
            cond_.notify_one();
        }
        bool new_msg_received(queue_msg &m)
        {
            std::unique_lock<std::mutex> lock(lock_);
            cond_.wait(lock);
            if (q_list_.size() > 0) {
                m = q_list_.front();
                q_list_.pop();
                return true;
            }

            return false;
        }
        ~global_queue() { }

    private:
        std::queue<queue_msg> q_list_;
        std::mutex lock_;
        std::condition_variable cond_;

        explicit global_queue() { }
};

}

#endif
