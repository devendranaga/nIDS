/**
 * @brief - Implements packet generator configuration.
 * 
 * @copyright - 2023-present All rights reserved. Devendra Naga.
*/
#ifndef __FW_PACKET_GEN_CONFIG_H__
#define __FW_PACKET_GEN_CONFIG_H__

#include <stdint.h>
#include <string>
#include <common.h>
#include <arp.h>
#include <jsoncpp/json/json.h>

namespace firewall {

/**
 * @brief - defines ethernet configuration.
*/
struct packet_gen_eth_config {
    uint8_t src_mac[FW_MACADDR_LEN];
    uint8_t dst_mac[FW_MACADDR_LEN];
    uint32_t ethertype;
    uint32_t pkt_len;
    bool repeat;
    uint32_t count;
    uint32_t inter_pkt_gap_us;

    explicit packet_gen_eth_config() :
                    ethertype(0),
                    pkt_len(0),
                    repeat(false),
                    count(0),
                    valid_(false)
    { }
    ~packet_gen_eth_config() { }

    int parse(Json::Value &r);
    bool is_valid() { return valid_; }

    private:
        bool valid_;
};

/**
 * @brief - defines pcap replay configuration.
*/
struct packet_gen_pcap_replay_config {
    std::string filepath;
    uint32_t intvl_us;
    bool repeat;

    explicit packet_gen_pcap_replay_config() :
                        filepath(""),
                        intvl_us(1),
                        repeat(false),
                        valid_(false)
    { }
    ~packet_gen_pcap_replay_config() { }

    int parse(Json::Value &r);
    bool is_valid() { return valid_; }

    private:
        bool valid_;
};

struct packet_gen_arp_config {
    bool spoof_mode;
    arp_hdr arp_h;
    bool repeat;
    uint32_t count;
    uint32_t inter_pkt_gap_us;

    int parse(Json::Value &r);
    bool is_valid() { return valid_; }

    private:
        bool valid_;
};

/**
 * @brief - defines packet gen configuration.
*/
struct packet_gen_config {
    std::string ifname;
    packet_gen_eth_config eth_conf;
    packet_gen_pcap_replay_config pcap_conf;
    packet_gen_arp_config arp_conf;

    static packet_gen_config *instance()
    {
        static packet_gen_config conf;
        return &conf;
    }

    int parse(const std::string filepath);

    private:
        explicit packet_gen_config() { }
};

}

#endif
