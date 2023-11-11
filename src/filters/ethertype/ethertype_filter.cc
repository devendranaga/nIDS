#include <parser.h>
#include <rule_parser.h>
#include <ethertype_filter.h>
#include <event_mgr.h>

namespace firewall {

int ethertype_filter::run(parser &p, logger *log, bool debug)
{
    uint16_t ethertype = 0;
    rule_config *rules = p.get_rules();
    bool deny_matched = false;
    std::vector<rule_config_item>::iterator it;
    event_mgr *evt_mgr = event_mgr::instance();
    event evt;

    //
    // if ethernet header is present get the ethertype
    if (p.eh)
        ethertype = p.eh->ethertype;

    //
    // if there's vlan header, get the ethertype
    if (p.vh)
        ethertype = p.vh->ethertype;

    if (ethertype == 0)
        return -1;

    for (it = rules->rules_cfg_.begin(); it != rules->rules_cfg_.end(); it ++) {
        if ((it->sig_mask.eth_sig.ethertype) &&
            (ethertype == it->eth_rule.ethertype)) {

            //
            // if the ruletype is deny, fill the event
            if (it->type == rule_type::Deny) {
                evt.rule_id = it->rule_id;
                evt.evt_type = event_type::Evt_Deny;
                evt.ethertype = ethertype;
                deny_matched = true;
                break;
            }
            it->sig_detected.eth_sig.ethertype = 1;
        }
    }

    if (deny_matched) {
        evt_mgr->store(evt);
        return -1;
    }

    return 0;
}

}
