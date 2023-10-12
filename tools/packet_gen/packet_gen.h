#ifndef __TOOL_FW_PACKET_GEN_H__
#define __TOOL_FW_PACKET_GEN_H__

#include <iostream>
#include <memory>
#include <getopt.h>
#include <logger.h>
#include <raw_socket.h>
#include <packet_gen_config.h>
#include <pcap_replay.h>

namespace firewall {

class packet_gen {
    public:
        explicit packet_gen() { }
        ~packet_gen() { }

        int init(int argc, char **argv);
        void run();

    private:
        packet_gen_config *conf_;
        std::shared_ptr<raw_socket> raw_;
        std::string filename_;
        logger *log_;
};

}

#endif

