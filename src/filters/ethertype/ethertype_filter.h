#ifndef __FW_FILTER_ETHERTYPE_FILTER_H__
#define __FW_FILTER_ETHERTYPE_FILTER_H__

#include <logger.h>

namespace firewall {

struct parser;

class ethertype_filter {
    public:
        static ethertype_filter *instance()
        {
            static ethertype_filter eth_f;
            return &eth_f;
        }
        ~ethertype_filter() { }

        ethertype_filter(const ethertype_filter &) = delete;
        const ethertype_filter &operator=(const ethertype_filter &) = delete;
        ethertype_filter(const ethertype_filter &&) = delete;
        const ethertype_filter &&operator=(const ethertype_filter &&) = delete;

        int run(parser &prs, logger *log, bool debug);

    private:
        explicit ethertype_filter() { }
};

}

#endif
