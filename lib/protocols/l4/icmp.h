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
    uint16_t data_len;
    uint8_t *data;

    void print(logger *log);
};

struct icmp_echo_reply {
    uint16_t id;
    uint16_t seq_no;
    uint16_t data_len;
    uint8_t *data;

    void print(logger *log);
};

struct icmp_dest_unreachable {
    uint32_t reserved;
    std::shared_ptr<ipv4_hdr> ipv4_h; // IPv4 header
    uint8_t original_datagram[8]; // 8 bytes of the datagram of ip->protocol

    event_description parse(packet &p, logger *log, bool debug);
    void print(logger *log);
};

struct icmp_param_problem {
    uint8_t pointer;
    uint8_t unused[3];
    std::shared_ptr<ipv4_hdr> ipv4_h; // IPv4 header
    uint8_t original_datagram[8]; // 8 bytes of the datagram of ip->protocol;

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
};

struct icmp_info_msg {
    uint16_t id;
    uint16_t seq_no;

    event_description parse(packet &p, logger *log, bool debug);
    void print(logger *log);
};

/**
 * @brief - Implements icmp header serialize and deserialize.
*/
struct icmp_hdr {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    std::shared_ptr<icmp_echo_req> echo_req;
    std::shared_ptr<icmp_echo_reply> echo_reply;
    std::shared_ptr<icmp_dest_unreachable> dest_unreachable;
    std::shared_ptr<icmp_dest_unreachable> time_exceeded;
    std::shared_ptr<icmp_param_problem> param_problem;
    std::shared_ptr<icmp_dest_unreachable> source_quench;
    std::shared_ptr<icmp_param_problem> redir_msg;
    std::shared_ptr<icmp_timestamp_msg> ts;
    std::shared_ptr<icmp_timestamp_msg> ts_reply;
    std::shared_ptr<icmp_info_msg> info_req;
    std::shared_ptr<icmp_info_msg> info_resp;

    explicit icmp_hdr() :
                echo_req(nullptr),
                echo_reply(nullptr)
    { }
    ~icmp_hdr() { }

    int serialize(packet &p);
    event_description deserialize(packet &p, logger *log, bool debug = false);
    void print(logger *log);
};

}

#endif

