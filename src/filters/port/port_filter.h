#ifndef __FW_SRC_FILTERS_PORT_FILTER_H__
#define __FW_SRC_FILTERS_PORT_FILTER_H__

#include <vector>
#include <logger.h>
#include <rule_parser.h>

namespace firewall {

struct parser;

class port_filter {
    public:
        static port_filter *instance()
        {
            static port_filter f;
            return &f;
        }
        ~port_filter() { }

        void init();
        void run(parser &p, std::vector<rule_config_item>::iterator &rule, logger *log, bool debug);

    private:
        explicit port_filter() { }
        void match_allowed_ports(parser &p, std::vector<rule_config_item>::iterator &rule, logger *log, bool debug);
        bool match_ports(std::vector<uint16_t> &port_list, parser &p, logger *log, bool debug);
        void match_port_ranges(parser &p,
                               std::vector<rule_config_item>::iterator &rule,
                               logger *log, bool debug);
};

}

#endif
