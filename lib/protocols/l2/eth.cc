#include <eth.h>
#include <rule_parser.h>

namespace firewall {

void eth_hdr::serialize(packet &p)
{
	p.serialize(src_mac);
	p.serialize(dst_mac);
	p.serialize(ethertype);
}

void eth_hdr::deserialize(packet &p, logger *log, bool debug)
{
	p.deserialize(src_mac);
	p.deserialize(dst_mac);
	p.deserialize(ethertype);

	if (debug) {
		print(log);
	}
}

void eth_hdr::print(logger *log)
{
	log->info("eth_hdr: {\n");
	log->info("\tsrc_mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
					src_mac[0], src_mac[1],
					src_mac[2], src_mac[3],
					src_mac[4], src_mac[5]);
	log->info("\tdst_mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
					dst_mac[0], dst_mac[1],
					dst_mac[2], dst_mac[3],
					dst_mac[4], dst_mac[5]);
	log->info("\tethertype: %04x\n", ethertype);
	log->info("}\n");
}

}


