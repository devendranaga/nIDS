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

namespace firewall {

class fwctl_server {
    public:
        explicit fwctl_server(logger *log);
        ~fwctl_server();

    private:
        void fwctl_rx_pkt();
        void fwctl_write_stats(struct sockaddr_un *sender, socklen_t sender_len);

        logger *log_;
        int sock_;
        struct sockaddr_un addr_;
        std::unique_ptr<std::thread> rx_thr_;
};

}

#endif


