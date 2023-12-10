#ifndef __FW_CTL_H__
#define __FW_CTL_H__

#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <iostream>
#include <memory>
#include <thread>
#include <event_msg_codec.h>

#include <fw_ctl_msg.h>

namespace firewall {

class fw_ctl {
    public:
        explicit fw_ctl() { }
        ~fw_ctl() { }

        int init(int argc, char **argv);
        void run();

    private:
        void listen_for_mqtt_msgs();
        int local_sock_init(const std::string &path);
        void local_sock_get_stats();
        void local_sock_rx();

        std::shared_ptr<std::thread> mqtt_thr_;
        std::unique_ptr<std::thread> lsock_thr_;
        int sock_;
        struct sockaddr_un addr_;
        struct sockaddr_un server_addr_;
};

}

#endif
