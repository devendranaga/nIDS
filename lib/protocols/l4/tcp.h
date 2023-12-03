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
    End_Of_Option_List = 0,
    Nop = 1,
    Mss = 2,
    Win_Scale = 3,
    SACK_Permitted = 4,
    Timestamp = 8,
};

struct tcp_hdr_opt_mss {
    uint8_t len;
    uint16_t val;
};

struct tcp_hdr_opt_sack_permitted {
    uint8_t len;
};

struct tcp_hdr_opt_timestamp {
    uint8_t len;
    uint32_t ts_val;
    uint32_t ts_echo_reply;

    bool len_in_range() { return len == len_; }
    private:
        const int len_ = 10;
};

struct tcp_hdr_opt_win_scale {
    uint8_t len;
    uint8_t shift_count;

    /**
     * @brief - check if the length is in range.
     * 
     * this length including the header and the value (TLV).
    */
    bool len_in_range() { return len == len_; }
    private:
        const int len_ = 3;
};

struct tcp_hdr_options {
    std::shared_ptr<tcp_hdr_opt_mss> mss;
    std::shared_ptr<tcp_hdr_opt_sack_permitted> sack_permitted;
    std::shared_ptr<tcp_hdr_opt_timestamp> ts;
    std::shared_ptr<tcp_hdr_opt_win_scale> win_scale;
    bool end_of_opt;

    explicit tcp_hdr_options() :
                    mss(nullptr),
                    sack_permitted(nullptr),
                    ts(nullptr),
                    win_scale(nullptr),
                    end_of_opt(false) { }
    ~tcp_hdr_options() { }

    int serialize(packet &p);
    /**
     * @brief - deserialize TCP header options.
     *
     * @param [inout] p - pkt
     * @param [in] rem_len - remaining length
     * @param [in] log - logger
     * @param [in] debug - debug enable
     * 
     * @return returns event_description after the parsing.
    */
    event_description deserialize(packet &p,
                                  uint32_t rem_len,
                                  logger *log,
                                  bool debug = false);
    void print(logger *log);
};

/**
 * @brief - Implements TCP header serialize and deserialize.
*/
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

    explicit tcp_hdr() noexcept :
            opts(nullptr) { }
    ~tcp_hdr() { }

    int serialize(packet &p);
    bool has_opts() { return opts != nullptr; }
    /**
     * @brief - deserialize TCP header.
     *
     * @param [in] p - packet
     * @param [in] log - logger
     * @param [in] debug - debug
     *
     * @return event_description.
    */
    event_description deserialize(packet &p, logger *log, bool debug = false);

    /**
     * @brief - print the TCP header.
     *
     * @param [in] log - logger
    */
    void print(logger *log);

    private:
        event_description check_flags();
        const int tcp_hdr_len_no_off_ = 20;
};

}

#endif

