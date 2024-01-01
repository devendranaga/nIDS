/**
 * @brief - implements ARP filtering.
 *
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
*/
#ifndef __FW_FILTERS_ARP_FILTER_H__
#define __FW_FILTERS_ARP_FILTER_H__

#include <stdint.h>
#include <time.h>
#include <vector>
#include <mutex>
#include <sys/time.h>
#include <event_def.h>
#include <tunables.h>
#include <logger.h>

namespace firewall {

struct parser;

enum class Arp_State {
    Unknown,
    Req,
    Resp,
};

/**
 * @brief - defines mac and ipaddr combination of the arp entry
*/
struct arp_entry {
    uint8_t sender_mac[6];
    uint8_t target_mac[6];
    uint32_t sender_ipaddr;
    uint32_t target_ipaddr;
    bool resolved;
    Arp_State state;
    struct timespec last_seen;

    explicit arp_entry() :
                resolved(false),
                state(Arp_State::Unknown)
    {
        sender_mac[0] = 0xde;
        sender_mac[1] = 0xad;
        sender_mac[2] = 0xbe;
        sender_mac[3] = 0xef;
        sender_mac[4] = 0xbe;
        sender_mac[5] = 0xef;
    }
    explicit arp_entry(uint8_t *sender_macaddr,
                       uint8_t *target_macaddr,
                       uint32_t sender_ip,
                       uint32_t target_ip) :
                sender_ipaddr(sender_ip),
                target_ipaddr(target_ip),
                resolved(false),
                state(Arp_State::Unknown)
    {
        std::memcpy(sender_mac, sender_macaddr, FW_MACADDR_LEN);
        std::memcpy(target_mac, target_macaddr, FW_MACADDR_LEN);
        clock_gettime(CLOCK_MONOTONIC, &last_seen);
    }
    ~arp_entry() { }
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        std::string ipaddr;

        log->verbose("\t sender_mac: %02x-%02x-%02x-%02x-%02x-%02x\n",
                        sender_mac[0], sender_mac[1],
                        sender_mac[2], sender_mac[3],
                        sender_mac[4], sender_mac[5]);
        log->verbose("\t target_mac: %02x-%02x-%02x-%02x-%02x-%02x\n",
                        target_mac[0], target_mac[1],
                        target_mac[2], target_mac[3],
                        target_mac[4], target_mac[5]);
        get_ipaddr(sender_ipaddr, ipaddr);
        log->verbose("\t sender_ipaddr: %s\n", ipaddr.c_str());

        get_ipaddr(target_ipaddr, ipaddr);
        log->verbose("\t target_ipaddr: %s\n", ipaddr.c_str());

        log->verbose("\t resolved: %s\n", resolved ? "True": "False");

        log->verbose("\t state: %d\n", static_cast<uint16_t>(state));
    #endif
    }
};

/**
 * @brief - implements ARP filter
 */
class arp_filter {
    public:
        static arp_filter *instance()
        {
            static arp_filter arp_f;

            return &arp_f;
        }
        void init(logger *log)
        {
            log_ = log;
        }
        arp_filter(const arp_filter &) = delete;
        const arp_filter &operator=(const arp_filter &) = delete;
        arp_filter(const arp_filter &&) = delete;
        const arp_filter &&operator=(const arp_filter &&) = delete;
        ~arp_filter() { }

        event_description add_arp_frame(parser &p);
        void print_arp_table(logger *log)
        {
        #if defined(FW_ENABLE_DEBUG)
            log->verbose("Constructed ARP_Table So far: \n");
            for (auto it : arp_table_) {
                it.print(log);
            }
            log->verbose("}\n");
        #endif
        }

    private:
        explicit arp_filter() { }
        event_description check_flood();
        std::vector<arp_entry> arp_table_;
        std::mutex lock_;
        logger *log_;
};

}

#endif

