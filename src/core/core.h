/**
 * @brief - Implements core packet receive and service
 *
 * @copyright - 2023-present All rights reserved. Devendra Naga.
*/
#ifndef __FW_CORE_H__
#define __FW_CORE_H__

#include <stdint.h>
#include <getopt.h>
#include <unistd.h>
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
#include <rule_parser.h>
#include <packet_stats.h>
#include <parser.h>
#include <event_mgr.h>
#include <perf.h>
#include <filter.h>
#include <pcap_intf.h>

namespace firewall {

/**
 * @brief - Interface info
*/
class firewall_intf {
    public:
        explicit firewall_intf(logger *log);
        ~firewall_intf();

        // Initialize interface
        fw_error_type init(const std::string ifname,
                           const std::string rule_file,
                           bool log_pcap);

    private:
        void rx_thread();
        void filter_thread();
        void run_filter(packet &pkt);
        void init_pcap_writer();
        void write_pcap();

        //
        // receive thread for each interface
        std::shared_ptr<std::thread> rx_thr_id_;
        std::condition_variable rx_thr_cond_;
        //
        // filter thread id for each interface
        std::shared_ptr<std::thread> filt_thr_id_;

        //
        // PCAP writer thread for each interface
        std::shared_ptr<std::thread> pcap_wr_thr_id_;
        std::mutex pcap_log_lock_;
        std::queue<packet> pcap_log_q_;

        //
        // raw socket interface
        std::shared_ptr<raw_socket> raw_;
        //
        // list of packet queues
        std::queue<packet> pkt_q_;
        std::mutex rx_thr_lock_;
        //
        // logger pointer
        logger *log_;
        //
        // list of rules applying to this interface
        rule_config *rule_data_;
        //
        // interface name
        std::string ifname_;
        bool log_pcap_;
        perf perf_ctx_;
        std::shared_ptr<perf_item> pkt_perf_;
        std::shared_ptr<pcap_writer> pcap_w_;
};

/**
 * @brief - Implements base service class
*/
class fw_core {
    public:
        explicit fw_core();
        ~fw_core();

        fw_error_type init(int argc, char **argv);

    private:
        // List of firewall interface context
        std::vector<std::shared_ptr<firewall_intf>> intf_list_;
        event_mgr *evt_mgr_;
        logger *log_;
};

}

#endif

