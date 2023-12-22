#include <parser.h>
#include <rule_parser.h>
#include <eth_filter.h>
#include <event_mgr.h>

namespace firewall {

int eth_filter::run_filter(parser &p,
                           std::vector<rule_config_item>::iterator &it,
                           logger *log, bool debug)
{
    bool deny_matched = false;
    event_mgr *evt_mgr = event_mgr::instance();
    event evt;

    if ((it->sig_mask.eth_sig.from_src) &&
        (std::memcmp(p.eh.src_mac, it->eth_rule.from_src, FW_MACADDR_LEN) == 0)) {
        if (it->type == rule_type::Deny)
            deny_matched = true;

        it->sig_detected.eth_sig.from_src = 1;
    }
    if ((it->sig_mask.eth_sig.to_dst) &&
        (std::memcmp(p.eh.dst_mac, it->eth_rule.to_dst, FW_MACADDR_LEN) == 0)) {
        if (it->type == rule_type::Deny)
            deny_matched = true;

        it->sig_detected.eth_sig.to_dst = 1;
    }
    if ((it->sig_mask.eth_sig.ethertype) &&
        (p.eh.ethertype == it->eth_rule.ethertype)) {
        if (it->type == rule_type::Deny)
            deny_matched = true;

        //
        // what to do for Allowed events?
        it->sig_detected.eth_sig.ethertype = 1;
    }

    //
    // if the ruletype is deny, fill the event
    if (deny_matched) {
        evt.rule_id = it->rule_id;
        evt.evt_type = event_type::Evt_Deny;
        evt.ethertype = p.eh.ethertype;
        evt_mgr->store(evt);
        return -1;
    }

    return 0;
}

}
