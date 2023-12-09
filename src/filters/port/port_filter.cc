#include <event_mgr.h>
#include <parser.h>
#include <port_filter.h>

namespace firewall {

void port_filter::run(parser &p,
                      std::vector<rule_config_item>::iterator &rule,
                      logger *log,
                      bool debug)
{
    match_allowed_ports(p, rule, log, debug);
}

void port_filter::match_allowed_ports(parser &p,
                                      std::vector<rule_config_item>::iterator &rule,
                                      logger *log,
                                      bool debug)
{
    bool match = false;
    event_type evt_type;
    event_mgr *evt_mgr = event_mgr::instance();

    match = match_ports(rule->port_rule.port_list, p, log, debug);
    if (match == false)
        evt_type = event_type::Evt_Deny;
    else
        evt_type = event_type::Evt_Allow;

    evt_mgr->store(evt_type, event_description::Evt_Port_Matched, p);
}

bool port_filter::match_ports(std::vector<uint16_t> &port_list,
                              parser &p,
                              logger *log,
                              bool debug)
{
    for (auto it : port_list) {
        if (p.protocols_avail.has_tcp()) {
            if ((it == p.tcp_h.src_port) || (it == p.tcp_h.dst_port)) {
                return true;
            }
        }
        if (p.protocols_avail.has_udp()) {
            if ((it == p.udp_h.src_port) || (it == p.udp_h.dst_port)) {
                return true;
            }
        }
    }

    return false;
}

void port_filter::init()
{

}

}

