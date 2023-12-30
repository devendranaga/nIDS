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

    uint8_t hdr_len() { return len_; }

    private:
        const uint8_t len_ = 4;
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

struct tcp_hdr_options_flags {
    uint32_t mss:1;
    uint32_t sack_permitted:1;
    uint32_t ts:1;
    uint32_t win_scale:1;

    explicit tcp_hdr_options_flags() :
                    mss(0),
                    sack_permitted(0),
                    ts(0),
                    win_scale(0) { }
    ~tcp_hdr_options_flags() { }
};

/**
 * @brief - Implements TCP options.
 */
struct tcp_hdr_options {
    tcp_hdr_opt_mss mss;
    tcp_hdr_opt_sack_permitted sack_permitted;
    tcp_hdr_opt_timestamp ts;
    tcp_hdr_opt_win_scale win_scale;
    bool end_of_opt;

    tcp_hdr_options_flags flags;

    explicit tcp_hdr_options() :
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
    std::vector<char> rst_reason;

    // if options are set, this pointer is valid
    std::shared_ptr<tcp_hdr_options> opts;

    explicit tcp_hdr() noexcept :
            opts(nullptr) { }
    ~tcp_hdr() { }

    int serialize(packet &p);

    /**
     * @brief - returns if tcp has options.
     * 
     * @return true if tcp has options.
     *         false if tcp does not have options.
    */
    bool has_opts() const noexcept { return opts != nullptr; }
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
    void print(logger *log) const noexcept;

    private:
        event_description check_flags();
        const int tcp_hdr_len_no_off_ = 20;
};

}

#endif

