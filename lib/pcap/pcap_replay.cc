/**
 * @brief - implements pcap replay.
 * 
 * @copyright - 2023-present. All rights reserved. Devendra Naga.
*/
#include <iostream>
#include <cstdint>
#include <cstring>
#include <thread>
#include <pcap_replay.h>
#include <pcap_intf.h>

namespace firewall {

pcap_replay::pcap_replay(std::shared_ptr<raw_socket> &raw,
                         const std::string &replay_file,
                         uint32_t replay_intvl,
                         bool pcap_repeat) :
                         raw_(raw),
                         replay_filename_(replay_file),
                         replay_intvl_(replay_intvl),
                         pcap_repeat_(pcap_repeat)
{
}

void pcap_replay::replay()
{
    pcap_reader rd(replay_filename_);
    uint8_t dummy_mac[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xBE, 0xEF};
    int ret;

    while (1) {
        pcaprec_hdr_t hdr;
        uint8_t pkt[2400];

        std::this_thread::sleep_for(std::chrono::milliseconds(replay_intvl_));

        std::memset(pkt, 0, sizeof(pkt));
        std::memset(&hdr, 0, sizeof(hdr));

        // read the frame from the pcap
        ret = rd.read_packet(&hdr, pkt, sizeof(pkt));
        if (ret < 0) {
            return;
        }

        // write it on the interface
        raw_->send_msg(dummy_mac, pkt, hdr.incl_len);
    }
}

}
