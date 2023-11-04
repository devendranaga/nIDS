#ifndef __FW_FILTERS_ICMP_FILTER_H__
#define __FW_FILTERS_ICMP_FILTER_H__

#include <parser.h>
#include <event_def.h>
#include <logger.h>

namespace firewall {

class icmp_filter {
    public:
        static icmp_filter *instance()
        {
            static icmp_filter f;
            return &f;
        }
        ~icmp_filter() { }
        void init()
        {

        }
        event_description run_filter(parser &p, packet &pkt, logger *log, bool debug);
    private:
        explicit icmp_filter() { }
};

}

#endif
