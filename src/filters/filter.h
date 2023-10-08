/**
 * @brief - Implements firewall filter.
 * 
 * @copyright - 2023-present All rights reserved. Devendra Naga.
*/
#ifndef __FW_FILTER_H__
#define __FW_FILTER_H__

#include <logger.h>
#include <rule_parser.h>
#include <packet.h>

namespace firewall {

class filter {
    public:
        explicit filter(logger *log) : log_(log) { }
        ~filter() { }

        int run(packet &pkt, rule_config *rule_cfg);

    private:
        logger *log_;
};

}

#endif
