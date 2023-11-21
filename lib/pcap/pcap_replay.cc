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
                         bool use_pcap_timediffs,
                         bool pcap_repeat) :
                         raw_(raw),
                         replay_filename_(replay_file),
                         replay_intvl_(replay_intvl),
                         use_pcap_timediffs_(use_pcap_timediffs),
                         pcap_repeat_(pcap_repeat)
{
    int ret;

    rd_ = std::make_shared<pcap_reader>(replay_filename_);
    if (!rd_)
        throw std::runtime_error("Failed to read a pcap file " + replay_filename_);

    //
    // keep the first packet in the context for using later for subtraction
    ret = rd_->read_packet(&rec_hdr_, pkt_, sizeof(pkt_));
    if (ret < 0)
        return;
}

void pcap_replay::replay()
{
    uint8_t dummy_mac[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xBE, 0xEF};
    int ret;

    while (1) {
        pcaprec_hdr_t hdr;
        uint32_t delta_usec;

        // write it on the interface
        raw_->send_msg(dummy_mac, pkt_, rec_hdr_.incl_len);

        // read the frame from the pcap
        ret = rd_->read_packet(&hdr, pkt_, sizeof(pkt_));
        if (ret < 0) {
            return;
        }

        //
        // if we are using difference between the each pcap record, then
        // the replay is exact replica of the packets that are captured.
        if (use_pcap_timediffs_) {
            delta_usec = (hdr.ts_sec - rec_hdr_.ts_sec) * 1000000.0;
            if (rec_hdr_.ts_usec > hdr.ts_usec)
                delta_usec -= (rec_hdr_.ts_usec - hdr.ts_usec);
            else
                delta_usec += (hdr.ts_usec - rec_hdr_.ts_usec);
        } else {
            //
            // to test quickly or bruteforce sometimes..
            delta_usec = replay_intvl_;
        }

        rec_hdr_ = hdr;
        std::this_thread::sleep_for(std::chrono::microseconds(delta_usec));
    }
}

}
