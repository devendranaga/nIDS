/**
 * @brief - Implements TCP serialize and deserialize.
 * 
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
*/
#ifndef __FW_LIB_PROTOCOLS_L4_TCP_H__
#define __FW_LIB_PROTOCOLS_L4_TCP_H__

#include <memory>
#include <packet.h>
#include <event_def.h>
#include <logger.h>

namespace firewall {

enum class Tcp_Options_Type : uint32_t {
    Nop = 1,
    Mss = 2,
    Win_Scale = 3,
    SACK_Permitted = 4,
    Timestamp = 8,
};

struct tcp_hdr_opt_mss {
    uint16_t val;
};

struct tcp_hdr_opt_sack_permitted {
    uint8_t len;
};

struct tcp_hdr_opt_timestamp {
    uint8_t len;
    uint32_t ts_val;
    uint32_t ts_echo_reply;
};

struct tcp_hdr_opt_win_scale {
    uint8_t len;
    uint8_t shift_count;
};

struct tcp_hdr_options {
    std::shared_ptr<tcp_hdr_opt_mss> mss;
    std::shared_ptr<tcp_hdr_opt_sack_permitted> sack_permitted;
    std::shared_ptr<tcp_hdr_opt_timestamp> ts;
    std::shared_ptr<tcp_hdr_opt_win_scale> win_scale;

    int serialize(packet &p);
    event_description deserialize(packet &p, logger *log, bool debug = false);
    void print(logger *log);
};

struct tcp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_no;
    uint32_t ack_no;
    uint8_t hdr_len;
    uint32_t reserved:3;
    uint32_t ecn:1;
    uint32_t cwr:1;
    uint32_t ecn_echo:1;
    uint32_t urg:1;
    uint32_t ack:1;
    uint32_t psh:1;
    uint32_t rst:1;
    uint32_t syn:1;
    uint32_t fin:1;
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_ptr;

    // if options are set, this pointer is valid
    std::shared_ptr<tcp_hdr_options> opts;

    explicit tcp_hdr() noexcept
    {
        opts = nullptr;
    }
    ~tcp_hdr() { }

    int serialize(packet &p);
    event_description deserialize(packet &p, logger *log, bool debug = false);
    void print(logger *log);

    private:
        event_description check_flags();
        const int tcp_hdr_len_no_off_ = 20;
};

}

#endif

