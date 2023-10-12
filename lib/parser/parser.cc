#include <logger.h>
#include <parser.h>
#include <event_mgr.h>

namespace firewall {

parser::parser(logger *log): log_(log) { }
parser::~parser() { }

int parser::run(packet &pkt)
{
    event_description evt_desc;
    ether_type ether = eh.get_ethertype();

    eh.deserialize(pkt, log_);
    protocols_avail.set_eth();

    if (eh.has_ethertype_vlan()) {

    }

    switch (ether) {
        case ether_type::Ether_Type_ARP: {
            
        }
        case ether_type::Ether_Type_IPv4: {
            evt_desc = ipv4_h.deserialize(pkt);
            protocols_avail.set_ipv4();
        } break;
        default:
        break;
    }

    if (evt_desc != event_description::Evt_Parse_Ok) {
        // log the event and return
    }

    return 0;
}

}
