/**
 * @brief - implements ICMP serialize and deserialize.
 * 
 * @copyright - 2023-present. All rights reserved. Devendra Naga.
*/
#ifndef __FW_LIB_PROTOCOLS_ICMP_H__
#define __FW_LIB_PROTOCOLS_ICMP_H__

#include <stdlib.h>
#include <memory>
#include <ipv4.h>
#include <packet.h>
#include <event_def.h>
#include <logger.h>

namespace firewall {

/**
 * @brief - list of ICMP type.
 * 
 * See: https://datatracker.ietf.org/doc/html/rfc792.
*/
enum class Icmp_Type : uint32_t {
    Echo_Reply = 0,
    Dest_Unreachable = 3,
    Source_Quench = 4,
    Redirect = 5,
    Echo_Req = 8,
    Time_Exceeded = 11,
    Parameter_Problem = 12,
    Ts = 13,
    Ts_Reply = 14,
    Info_Req = 15,
    Info_Reply = 16,
    Address_Mask_Request = 17,
    Address_Mask_Reply = 18,
};

enum class Icmp_Code_Dest_Unreachable :  uint32_t {
    Net_Unreachable = 0,
    Host_Unrechable = 1,
    Protocol_Unreachable = 2,
    Port_Unrechable = 3,
    Fragmentation_Needed_And_DF_Set = 4,
    Source_Route_Failed = 5,
};

enum class Icmp_Code_Time_Exceeded : uint32_t {
    TTL_Exceeded_In_Transit = 0,
    Frag_Reassembly_Time_Exceeded = 1,
};

enum class Icmp_Code_Redir_Msg : uint32_t {
    Redir_For_Nw = 0,
    Redir_For_Host = 1,
    Redir_For_Tos_Nw = 2,
    Redir_For_Tos_Host = 3,
};

struct icmp_echo_req {
    uint16_t id;
    uint16_t seq_no;

    // below items are not part of the protocol
    uint16_t data_len;
    uint8_t *data;

    explicit icmp_echo_req() : data_len(0), data(nullptr) { }
    ~icmp_echo_req()
    {
        if (data) {
            free(data);
        }
    }
    void print(logger *log);
};

struct icmp_echo_reply {
    uint16_t id;
    uint16_t seq_no;
    uint16_t data_len;
    uint8_t *data;

    explicit icmp_echo_reply() : data_len(0), data(nullptr) { }
    ~icmp_echo_reply()
    {
        if (data) {
            free(data);
        }
    }

    void print(logger *log);
};

struct icmp_dest_unreachable {
    uint32_t reserved;
    std::shared_ptr<ipv4_hdr> ipv4_h; // IPv4 header
    uint8_t original_datagram[8]; // 8 bytes of the datagram of ip->protocol

    event_description parse(packet &p, logger *log, bool debug);
    void print(const std::string str, logger *log);
};

struct icmp_param_problem {
    uint8_t pointer;
    uint8_t unused[3];
    std::shared_ptr<ipv4_hdr> ipv4_h; // IPv4 header
    uint8_t original_datagram[8]; // 8 bytes of the datagram of ip->protocol;

    event_description parse(packet &p, logger *log, bool debug);
    void print(logger *log);
};

struct icmp_redir_msg {
    uint32_t gateway_internet_addr;
    std::shared_ptr<ipv4_hdr> ipv4_h; // IPv4 header
    uint8_t original_datagram[8]; // 8 bytes of the datagram of ip->protocol;

    event_description parse(packet &p, logger *log, bool debug);
    void print(logger *log);
};

struct icmp_timestamp_msg {
    uint16_t id;
    uint16_t seq_no;
    uint32_t orig_ts;
    uint32_t rx_ts;
    uint32_t tx_ts;

    event_description parse(packet &p, logger *log, bool debug);
    void print(logger *log);

    private:
        const int ts_len = 16;
};

struct icmp_info_msg {
    uint16_t id;
    uint16_t seq_no;

    event_description parse(packet &p, logger *log, bool debug);
    void print(logger *log);

    private:
        const int info_len = 4;
};

struct icmp_address_mask {
    uint16_t id;
    uint16_t seq_no;
    uint32_t addres_mask;

    event_description parse(packet &p, logger *log, bool debug);
    void print(const std::string str, logger *log);

    private:
        const int len_ = 8;
};

/**
 * @brief - Implements icmp header serialize and deserialize.
*/
struct icmp_hdr {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;

    uint32_t start_off;
    uint32_t end_off;

    // one or more of these are valid pointers upon parsing an icmp packet.
    std::shared_ptr<icmp_echo_req> echo_req;
    std::shared_ptr<icmp_echo_reply> echo_reply;
    std::shared_ptr<icmp_dest_unreachable> dest_unreachable;
    std::shared_ptr<icmp_dest_unreachable> time_exceeded;
    std::shared_ptr<icmp_param_problem> param_problem;
    std::shared_ptr<icmp_dest_unreachable> source_quench;
    std::shared_ptr<icmp_redir_msg> redir_msg;
    std::shared_ptr<icmp_timestamp_msg> ts;
    std::shared_ptr<icmp_timestamp_msg> ts_reply;
    std::shared_ptr<icmp_info_msg> info_req;
    std::shared_ptr<icmp_info_msg> info_resp;
    std::shared_ptr<icmp_address_mask> addr_mask_req;
    std::shared_ptr<icmp_address_mask> addr_mask_reply;

    explicit icmp_hdr() :
                start_off(0),
                end_off(0),
                echo_req(nullptr),
                echo_reply(nullptr),
                dest_unreachable(nullptr),
                time_exceeded(nullptr),
                param_problem(nullptr),
                source_quench(nullptr),
                redir_msg(nullptr),
                ts(nullptr),
                ts_reply(nullptr),
                info_req(nullptr),
                info_resp(nullptr)
    { }
    ~icmp_hdr() { }

    int serialize(packet &p);
    /**
     * @brief - deserialize icmp packet.
     * 
     * @param [inout] p - packet
     * @param [in] log - logger
     * @param [in] debug - debug print
     * 
     * @return returns the event description of parsed packet.
    */
    event_description deserialize(packet &p, logger *log, bool debug = false);
    void print(logger *log);
    int validate_checksum(const packet &p);

    private:
        const int icmp_hdr_len_ = 4;
        //
        // this is the default value because on Linux, this is 64 bytes.
        // on Windows and Mac this may change.
        const int icmp_max_data_len_ = 64;
};

}

#endif

