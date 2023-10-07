#ifndef __FW_CORE_H__
#define __FW_CORE_H__

#include <stdint.h>
#include <getopt.h>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <memory>
#include <config.h>
#include <logger.h>
#include <raw_socket.h>
#include <packet.h>

namespace firewall {

struct firewall_pkt_stats {
    uint64_t rx_count;
};

/**
 * @brief - Interface info
*/
class firewall_intf {
    public:
        explicit firewall_intf(logger *log);
        ~firewall_intf();

        // Initialize interface
        fw_error_type init(const std::string ifname,
                           const std::string rule_file);

    private:
        void rx_thread();
        void filter_thread();
        std::shared_ptr<std::thread> rx_thr_id_;
        std::condition_variable rx_thr_cond_;
        std::shared_ptr<raw_socket> raw_;
        std::queue<packet> pkt_q_;
        std::mutex rx_thr_lock_;
        logger *log_;
        firewall_pkt_stats stats_;
};

class fw_core {
    public:
        explicit fw_core();
        ~fw_core();

        fw_error_type init(int argc, char **argv);

    private:
        // List of firewall interface context
        std::vector<std::shared_ptr<firewall_intf>> intf_list_;
        logger *log_;
};

}

#endif

