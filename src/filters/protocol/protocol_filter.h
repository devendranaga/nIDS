#ifndef __FW_SRC_FILTERS_PROTOCOL_FILTER_H__
#define __FW_SRC_FILTERS_PROTOCOL_FILTER_H__

#include <logger.h>
#include <parser.h>
#include <rule_parser.h>

namespace firewall {

class protocol_filter {
    public:
        ~protocol_filter() { }

        void init(logger *log);
        int run(parser &p,
                std::vector<rule_config_item>::iterator &it,
                logger *log, bool debug);

    private:
        explicit protocol_filter() { }
};

}

#endif

