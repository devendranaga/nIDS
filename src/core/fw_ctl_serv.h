/**
 * @brief - Implements a fwctl server front end for IDS.
 *
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
*/
#ifndef __FW_CORE_CONTROL_SERVER_H__
#define __FW_CORE_CONTROL_SERVER_H__

#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <iostream>
#include <memory>
#include <thread>

#include <logger.h>
#include <fw_ctl_msg.h>
#include <lang_hints.h>

namespace firewall {

/**
 * @brief - implements the front end class that interfaces with the fwctl client.
*/
class fwctl_server {
    public:
        explicit fwctl_server(logger *log); THROWS
        ~fwctl_server();

    private:
        /**
         * @brief - handle incoming connection and provide response.
        */
        void fwctl_rx_pkt();

        /**
         * @brief - write stats back to the client
         *
         * @param [in] sender - sender address
         * @param [in] sender_len - sender address length
        */
        void fwctl_write_stats(struct sockaddr_un *sender, socklen_t sender_len);

        logger *log_;
        int sock_;
        struct sockaddr_un addr_;
        std::unique_ptr<std::thread> rx_thr_;
};

}

#endif


