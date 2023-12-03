/**
 * @brief - Implements IPSec AH (Authentication Header) parsing.
 * 
 * @copyright - 2023-present. Devendra Naga All rights reserved.
*/
#ifndef __FW_LIB_PROTOCOLS_L3_IP_AH_H__
#define __FW_LIB_PROTOCOLS_L3_IP_AH_H__

#include <memory>
#include <packet.h>
#include <event_def.h>
#include <logger.h>

namespace firewall {

#define IPSEC_AH_ICV_LEN 32
#define IPSEC_AH_LEN_NO_ICV 12

struct ipv6_hdr;

struct ipsec_ah_hdr {
    uint8_t nh;
    uint8_t len;
    uint16_t reserved;
    uint32_t ah_spi;
    uint32_t ah_seq;
    uint32_t icv_len;
    uint8_t ah_icv[IPSEC_AH_ICV_LEN];

    std::shared_ptr<ipv6_hdr> ipv6_h;

    int serialize(packet &p);

    /**
     * @brief - deserialize the IPv6-AH packet.
     *
     * @param [inout] p - packet
     * @param [in] log - logger
     * @param [in] debug - debug print
     * 
     * @return returns the event description after parsing the frame.
    */
    event_description deserialize(packet &p, logger *log, bool debug = false);

    /**
     * @brief - prints the ipv4 header
     *
     * @param [in] log - logger.
     */
    void print(logger *log);

    private:
        const int len_ = 1;
};

}

#endif


