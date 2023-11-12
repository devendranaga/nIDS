/**
 * @brief - implements packet_gen core.
 * 
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
*/
#ifndef __TOOL_FW_PACKET_GEN_H__
#define __TOOL_FW_PACKET_GEN_H__

#include <iostream>
#include <memory>
#include <thread>
#include <getopt.h>
#include <logger.h>
#include <raw_socket.h>
#include <packet_gen_config.h>
#include <pcap_replay.h>
#include <eth.h>

namespace firewall {

class packet_gen {
    public:
        explicit packet_gen() { }
        ~packet_gen() { }

        int init(int argc, char **argv);
        void run();

    private:
        //
        // Runs pcap replay
        void run_pcap_replay();
        //
        // Runs Ethernet Replay
        void run_eth_replay();
        void run_arp_replay();
        void run_ipv4_replay();
        packet_gen_config *conf_;
        std::shared_ptr<raw_socket> raw_;
        std::string filename_;
        logger *log_;
};

}

#endif

