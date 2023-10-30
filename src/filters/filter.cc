#include <filter.h>

namespace firewall {

fw_error_type filter::init()
{
    arp_filter *arp_f = arp_filter::instance();

    arp_f->init();

    return fw_error_type::eNo_Error;
}

int filter::run(packet &pkt, rule_config *rule_cfg)
{
    return 0;
}

}
