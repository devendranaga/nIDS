#include <logger.h>
#include <parser.h>
#include <event_mgr.h>

namespace firewall {

parser::parser(logger *log): log_(log) { }
parser::~parser() { }

int parser::run(packet &pkt)
{
    eh.deserialize(pkt);
    eh.print(log_);

    return 0;
}

}
