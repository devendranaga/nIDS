/**
 * @brief - implements parser
 * 
 * @copyright - 2023-present All rights reserved. Devendra Naga.
*/
#ifndef __FW_PARSER_H__
#define __FW_PARSER_H__

#include <logger.h>
// ethernet header
#include <eth.h>
// ARP header
#include <arp.h>
#include <ipv4.h>
#include <packet.h>
#include <rule_parser.h>

namespace firewall {

struct protocol_bits {
    uint32_t eth:1;
    uint32_t ipv4:1;

    explicit protocol_bits() :
                        eth(0),
                        ipv4(0)
    { }
    ~protocol_bits() { }

    void set_eth() { eth = 1; }
    void set_ipv4() { ipv4 = 1; }
    bool has_eth() { return eth == 1; }
    bool has_ipv4() { return ipv4 == 1; }
};

/**
 * @brief - Implements packet parser.
*/
struct parser {
    public:
        explicit parser(logger *log);
        ~parser();

        // ethernet header
        eth_hdr eh;

        // ipv4 header
        ipv4_hdr ipv4_h;

        // parsed protocols so far
        protocol_bits protocols_avail;

        int run(packet &pkt);

    private:
        logger *log_;
};

}

#endif
