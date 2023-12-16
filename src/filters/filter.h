/**
 * @brief - Implements firewall filter.
 *
 * @copyright - 2023-present All rights reserved. Devendra Naga.
*/
#ifndef __FW_FILTER_H__
#define __FW_FILTER_H__

#include <config.h>
#include <tunables.h>
#include <logger.h>
#include <rule_parser.h>
#include <packet.h>
#include <arp_filter.h>
#include <icmp_filter.h>
#include <port_filter.h>
#include <common.h>

namespace firewall {

class filter {
    public:
        ~filter() { }

        static filter *instance()
        {
            static filter f;
            return &f;
        }

        fw_error_type init();
        int run(packet &pkt, rule_config *rule_cfg);

    private:
        explicit filter() { }
        logger *log_;
};

}

#endif
