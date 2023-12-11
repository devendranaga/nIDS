#ifndef __FW_FILTER_ETH_FILTER_H__
#define __FW_FILTER_ETH_FILTER_H__

#include <vector>
#include <logger.h>

namespace firewall {

struct parser;

class eth_filter {
    public:
        static eth_filter *instance()
        {
            static eth_filter eth_f;
            return &eth_f;
        }
        ~eth_filter() { }

        eth_filter(const eth_filter &) = delete;
        const eth_filter &operator=(const eth_filter &) = delete;
        eth_filter(const eth_filter &&) = delete;
        const eth_filter &&operator=(const eth_filter &&) = delete;

        int run_filter(parser &p,
                       std::vector<rule_config_item>::iterator &it,
                       logger *log, bool debug);
    private:
        explicit eth_filter() { }
};

}

#endif
