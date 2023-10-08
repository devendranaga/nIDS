#ifndef __NOS_PCAP_OP_H__
#define __NOS_PCAP_IO_H__

#include <stdint.h>
#include <memory>
#include <raw_socket.h>

namespace firewall {

class pcap_replay {
    public:
        explicit pcap_replay(std::shared_ptr<raw_socket> &raw,
                             const std::string &replay_file,
                             uint32_t replay_intvl,
                             bool pcap_repeat);
        ~pcap_replay() { }

        void replay();

    private:
        std::shared_ptr<raw_socket> raw_;
        std::string replay_filename_;
        uint32_t replay_intvl_;
        bool pcap_repeat_;
};

}

#endif
