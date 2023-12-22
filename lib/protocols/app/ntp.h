/**
 * @brief - implements NTP serialize and deserialize.
 * 
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
*/
#ifndef __LIB_PROTOCOLS_APP_NTP_H__
#define __LIB_PROTOCOLS_APP_NTP_H__

#include <packet.h>
#include <event_def.h>
#include <logger.h>

namespace firewall {

enum class Ntp_Mode {
    Client = 3,
    Server = 4,
};

/**
 * @brief - defines NTP v3 header.
 */
struct ntp_v3_hdr {
    uint8_t peer_clock_stratum;
    uint8_t peer_polling_intvl;
    uint8_t peer_clock_precision;
    uint32_t root_delay_intvl_sec;
    uint32_t root_dispersion;
    uint32_t reference_id;
    uint64_t reference_timestamp;
    uint64_t origin_timestamp;
    uint64_t receive_timestamp;
    uint64_t transmit_timestamp;
};

/**
 * @brief - implements NTP header.
*/
struct ntp_hdr {
    uint32_t leap_indicator:2;
    uint32_t version:3;
    uint32_t mode:3;

    //
    // select the below structures based on the verison present above.
    union {
        ntp_v3_hdr v3_hdr;
    } v;

    int serialize(packet &p);
    event_description deserialize(packet &p, logger *log, bool debug = false);
    void print(logger *log);
};

}

#endif

