#include <parser.h>
#include <rule_parser.h>
#include <eth_filter.h>
#include <event_mgr.h>

namespace firewall {

int eth_filter::ethertype_filter(parser &p,
                                 std::vector<rule_config_item>::iterator &it,
                                 logger *log, bool debug)
{
    bool deny_matched = false;
    event_mgr *evt_mgr = event_mgr::instance();
    event evt;

    if ((it->sig_mask.eth_sig.ethertype) &&
        (p.eh.ethertype = it->eth_rule.ethertype)) {
        //
        // if the ruletype is deny, fill the event
        if (it->type == rule_type::Deny) {
            evt.rule_id = it->rule_id;
            evt.evt_type = event_type::Evt_Deny;
            evt.ethertype = p.eh.ethertype;
            deny_matched = true;
        }
        it->sig_detected.eth_sig.ethertype = 1;
    }

    if (deny_matched) {
        evt_mgr->store(evt);
        return -1;
    }

    return 0;
}

}
