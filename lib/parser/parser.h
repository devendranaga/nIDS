#ifndef __FW_PARSER_H__
#define __FW_PARSER_H__

#include <logger.h>
#include <eth.h>
#include <packet.h>
#include <rule_parser.h>

namespace firewall {

struct parser {
    public:
        explicit parser(logger *log);
        ~parser();

        eth_hdr eh;

        int run(packet &pkt);

    private:
        logger *log_;
};

}

#endif
