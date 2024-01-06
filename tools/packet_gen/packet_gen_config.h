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
#include <macsec.h>
#include <jsoncpp/json/json.h>

namespace firewall {

/**
 * @brief - defines ethernet configuration.
*/
struct packet_gen_eth_config {
    bool enable;
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
    bool enable;
    std::string filepath;
    uint32_t intvl_us;
    bool repeat;
    bool use_pcap_timestamps;

    explicit packet_gen_pcap_replay_config() :
                        filepath(""),
                        intvl_us(1),
                        repeat(false),
                        use_pcap_timestamps(false),
                        valid_(false)
    { }
    ~packet_gen_pcap_replay_config() { }

    int parse(Json::Value &r);
    bool is_valid() { return valid_; }

    private:
        bool valid_;
};

/**
 * @brief - defines packet gen arp configuration.
*/
struct packet_gen_arp_config {
    bool enable;
    bool spoof_mode;
    arp_hdr arp_h;
    bool repeat;
    uint32_t count;
    uint32_t inter_pkt_gap_us;

    int parse(Json::Value &r);
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("spoof_mode: %d\n", spoof_mode);
        arp_h.print(log);
        log->verbose("repeat: %d\n", repeat);
        log->verbose("count: %d\n", count);
        log->verbose("inter_pkt_gap_us: %d\n", inter_pkt_gap_us);
    #endif
    }
    bool is_valid() { return valid_; }

    private:
        bool valid_;
};

struct packet_gen_ipv4_config {
    bool enable;
    uint8_t src_mac[6];
    uint8_t dest_mac[6];
    uint32_t ttl;
    bool auto_ttl;
    uint32_t src_ipaddr;
    uint32_t dest_ipaddr;
    uint16_t id;
    uint16_t ipv4_len;
    uint16_t protocol;
    uint32_t count;
    uint32_t inter_pkt_gap_us;

    explicit packet_gen_ipv4_config() : valid_(false) { }
    ~packet_gen_ipv4_config() { }

    int parse(Json::Value &r);
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("src_mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
                                    src_mac[0], src_mac[1],
                                    src_mac[2], src_mac[3],
                                    src_mac[4], src_mac[5]);
        log->verbose("dest_mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
                                    dest_mac[0], dest_mac[1],
                                    dest_mac[2], dest_mac[3],
                                    dest_mac[4], dest_mac[5]);
        log->verbose("ttl: %d\n", ttl);
        log->verbose("src_ipaddr: %u\n", src_ipaddr);
        log->verbose("dest_ipaddr: %u\n", dest_ipaddr);
        log->verbose("id: 0x%04x\n", id);
        log->verbose("ipv4_len: %d\n", ipv4_len);
    #endif
    }
    bool is_valid() { return valid_; }

    private:
        bool valid_;
};

struct packet_gen_macsec_config {
    bool enable;
    ieee8021ae_hdr macsec_h;
    uint32_t count;
    uint32_t inter_pkt_gap_us;
    uint8_t eth_src[6];
    uint8_t eth_dst[6];
    uint16_t ethertype;

    explicit packet_gen_macsec_config() : valid_(false) { }
    ~packet_gen_macsec_config() { }

    int parse(Json::Value &r);
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->info("MACsec_Config: {\n");
        macsec_h.print(log);
        log->info("count: %d\n", count);
        log->info("inter_pkt_gap_us: %d\n", inter_pkt_gap_us);
        log->info("eth_src: %02x:%02x:%02x:%02x:%02x:%02x\n",
                                eth_src[0], eth_src[1], eth_src[2],
                                eth_src[3], eth_src[4], eth_src[5]);
        log->info("eth_dst: %02x:%02x:%02x:%02x:%02x:%02x\n",
                                eth_dst[0], eth_dst[1], eth_dst[2],
                                eth_dst[3], eth_dst[4], eth_dst[5]);
        log->info("ethertype: 0x%04x\n", ethertype);
        log->info("}\n");
    #endif
    }
    bool is_valid() { return valid_; }

    private:
        bool valid_;
};

struct packet_gen_vlan_config {
    bool enable;
    uint32_t priority;
    bool dei;
    uint32_t vid;
    uint8_t eth_src_mac[6];
    uint8_t eth_dst_mac[6];
    uint16_t ethertype;
    uint32_t count;
    uint32_t inter_pkt_gap_us;

    explicit packet_gen_vlan_config() :
                        enable(false),
                        valid_(false) { }
    ~packet_gen_vlan_config() { }

    int parse(Json::Value &r);
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->info("VLAN_Config: {\n");
        log->info("enable: %d\n", enable);
        log->info("priority: %d\n", priority);
        log->info("dei: %d\n", dei);
        log->info("vid: %d\n", vid);
        log->info("eth_src_mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
                            eth_src_mac[0], eth_src_mac[1], eth_src_mac[2],
                            eth_src_mac[3], eth_src_mac[4], eth_src_mac[5]);
        log->info("eth_dst_mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
                            eth_dst_mac[0], eth_dst_mac[1], eth_dst_mac[2],
                            eth_dst_mac[3], eth_dst_mac[4], eth_dst_mac[5]);
        log->info("ethertype: 0x%04x\n", ethertype);
        log->info("}\n");
    #endif
    }

    bool is_Valid() { return valid_; }

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
    packet_gen_ipv4_config ipv4_conf;
    packet_gen_macsec_config macsec_conf;
    packet_gen_vlan_config vlan_conf;

    static packet_gen_config *instance()
    {
        static packet_gen_config conf;
        return &conf;
    }

    int parse(const std::string filepath);
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        if (arp_conf.is_valid()) {
            arp_conf.print(log);
        }
        if (ipv4_conf.is_valid()) {
            ipv4_conf.print(log);
        }
        if (macsec_conf.is_valid()) {
            macsec_conf.print(log);
        }
        if (vlan_conf.is_Valid()) {
            vlan_conf.print(log);
        }
    #endif
    }

    private:
        explicit packet_gen_config() { }
};

}

#endif
