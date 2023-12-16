/**
 * @brief - Implements filter.
 *
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
 */
#include <filter.h>

namespace firewall {

fw_error_type filter::init()
{
    logger *log = logger::instance();
    firewall_config *conf = firewall_config::instance();
    tunables *tunable_cfg = tunables::instance();
    arp_filter *arp_f = arp_filter::instance();
    icmp_filter *icmp_f = icmp_filter::instance();
    port_filter *port_f = port_filter::instance();
    int ret;

    ret = tunable_cfg->parse(conf->tunables_config_filename);
    if (ret != 0) {
        log->error("filter: failed to parse tunables configuration\n");
        return fw_error_type::eConfig_Error;
    }

    log->info("filter: parsed tunables config\n");

    arp_f->init();
    icmp_f->init();
    port_f->init();

    return fw_error_type::eNo_Error;
}

int filter::run(packet &pkt, rule_config *rule_cfg)
{
    return 0;
}

}

