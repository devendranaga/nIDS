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
    uint8_t mac[6];
    uint32_t ipaddr;
    bool resolved;
    Arp_State state;
    struct timespec last_seen;

    explicit arp_entry() :
                resolved(false),
                state(Arp_State::Unknown) { }
    ~arp_entry() { }
    void print(logger *log)
    {
    #if defined(FW_ENABLE_DEBUG)
        log->verbose("mac: %02x-%02x-%02x-%02x-%02x-%02x\n",
                        mac[0], mac[1],
                        mac[2], mac[3],
                        mac[4], mac[5]);
        log->verbose("ipaddr: %u\n", ipaddr);
        log->verbose("resolved: %s\n", resolved ? "True": "False");
    #endif
    }
};

struct arp_filter_config {
    // interframe gap between ARP frames from the same mac
    uint32_t inter_frame_gap_from_same_mac_msec;

    explicit arp_filter_config()
    {
        inter_frame_gap_from_same_mac_msec = 2000;
    }

    bool check(parser &p);
};

class arp_filter {
    public:
        static arp_filter *instance()
        {
            static arp_filter arp_f;

            return &arp_f;
        }
        void init()
        {

        }
        ~arp_filter() { }

        event_description add_arp_frame(parser &p);
        void print_arp_table(logger *log)
        {
        #if defined(FW_ENABLE_DEBUG)
            for (auto it : arp_table_) {
                it.print(log);
            }
        #endif
        }

    private:
        explicit arp_filter() { }
        std::vector<arp_entry> arp_table_;
        arp_filter_config filter_conf_;
        std::mutex lock_;
};

}

#endif
