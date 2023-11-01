#ifndef __FW_CTL_H__
#define __FW_CTL_H__

#include <iostream>
#include <memory>
#include <thread>
#include <event_msg_codec.h>

namespace firewall {

class fw_ctl {
    public:
        explicit fw_ctl() { }
        ~fw_ctl() { }

        int init(int argc, char **argv);
        void run();
    private:
        std::shared_ptr<std::thread> mqtt_thr_;

        void listen_for_mqtt_msgs();
};

}

#endif
