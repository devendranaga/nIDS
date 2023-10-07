#include <eth.h>

namespace firewall {

void eth_hdr::serialize(const packet &p)
{
}

void eth_hdr::deserialize(packet &p)
{
	p.serialize(src_mac);
	p.serialize(dst_mac);
	p.serialize(ethertype);
}

}


