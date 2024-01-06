/**
 * @brief - implements ICMP filter.
 *
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
*/
#ifndef __FW_FILTERS_ICMP_FILTER_H__
#define __FW_FILTERS_ICMP_FILTER_H__

#include <memory>
#include <thread>
#include <mutex>
#include <parser.h>
#include <event_def.h>
#include <logger.h>
#include <time_util.h>
#include <tunables.h>

namespace firewall {

/**
 * @brief - state of ICMP echo-req and echo-reply.
*/
enum class Icmp_State {
    None,
    Echo_Req_Observed,
    Echo_Reply_Observed, // transaction complete
    Dest_Unreachable_Observed, // something fishy .. NMAP passive scan
};

/**
 * @brief - seq and state combination to track the icmp echo-req and echo-reply.
*/
struct icmp_seq_info {
    // Current state of the ICMP exchange
    Icmp_State state;
    uint16_t seq;

    // to manage the echo-req and echo-reply timeout
    struct timespec seq_ts;

    explicit icmp_seq_info()
    {
        state = Icmp_State::None;
        seq = 0;
    }
    ~icmp_seq_info() { }
};

/**
 * @brief - ICMP info to track echo-req and echo-reply.
*/
struct icmp_info {
    uint32_t sender_ip;
    uint32_t dest_ip;
    uint16_t id;
    uint64_t n_icmp;
    // matching echo-req and echo-reply with seq_no
    std::vector<icmp_seq_info> seq_info;
    struct timespec prev_echo_req_time;
    struct timespec cur_echo_req_time;
    struct timespec prev_echo_reply_time;
    struct timespec cur_echo_reply_time;

    explicit icmp_info()
    {
        sender_ip = 0;
        dest_ip = 0;
        id = 0;
        n_icmp = 0;
        prev_echo_req_time.tv_sec = 0;
        prev_echo_req_time.tv_nsec = 0;
        cur_echo_req_time.tv_sec = 0;
        cur_echo_req_time.tv_nsec = 0;
        prev_echo_reply_time.tv_sec = 0;
        prev_echo_reply_time.tv_nsec = 0;
        cur_echo_reply_time.tv_sec = 0;
        cur_echo_reply_time.tv_nsec = 0;
    }
    ~icmp_info() { }
};

/**
 * @brief - implements filter statistics.
*/
struct icmp_filter_stats {
    uint64_t n_pass;
    uint64_t n_fail;

    explicit icmp_filter_stats() :
                    n_pass(0),
                    n_fail(0)
    { }
    ~icmp_filter_stats() { }
};

/**
 * @brief - implements ICMP filter.
*/
class icmp_filter {
    public:
        static icmp_filter *instance()
        {
            static icmp_filter f;
            return &f;
        }
        ~icmp_filter() { }

        /**
         * @brief - initializes the ICMP filter.
        */
        void init()
        {
            list_mgr_thr_ = std::make_unique<std::thread>(&icmp_filter::list_mgr_thread, this);
            list_mgr_thr_->detach();
        }

        event_description run_auto_sig_checks(parser &p, logger *log, bool debug);

        /**
         * @brief - run ICMP filter.
        */
        void run_filter(parser &p,
                        std::vector<rule_config_item>::iterator &rule,
                        logger *log, bool debug);
    private:
        explicit icmp_filter() { }
        void check_nonzero_len_payloads(parser &p, uint32_t rule_id, rule_type type);
        void manage_icmp(parser &p);
        void list_mgr_thread();
        std::vector<icmp_info> icmp_list_;
        std::shared_ptr<std::thread> list_mgr_thr_;
        std::mutex table_lock_;
        icmp_filter_stats stats_;
};

}

#endif

