/**
 * @brief - implements packet_gen core.
 * 
 * @copyright - 2023-present All rights reserved. Devendra Naga.
*/
#include <packet_gen.h>

namespace firewall {

static void usage(const char *progname)
{
    fprintf(stderr, "%s <-f filename>\n", progname);
}

int packet_gen::init(int argc, char **argv)
{
    int ret;

    while ((ret = getopt(argc, argv, "f:")) != -1) {
        switch (ret) {
            case 'f':
                filename_ = optarg;
            break;
            default:
                usage(argv[0]);
                return -1;
        }
    }

    log_ = logger::instance();

    log_->info("parse configuration %s\n", filename_.c_str());

    conf_ = packet_gen_config::instance();
    ret = conf_->parse(filename_);
    if (ret != 0) {
        log_->error("failed to parse %s\n", filename_.c_str());
        return -1;
    }
    conf_->print(log_);

    log_->info("configuration %s parsed ok\n", filename_.c_str());

    raw_ = std::make_shared<raw_socket>(conf_->ifname, 0);
    log_->info("raw socket create ok\n");

    return 0;
}

void packet_gen::run_pcap_replay()
{
    std::unique_ptr<pcap_replay> replay;

    replay = std::make_unique<pcap_replay>(
                        raw_,
                        conf_->pcap_conf.filepath,
                        conf_->pcap_conf.intvl_us,
                        conf_->pcap_conf.repeat);
    replay->replay();
}

void packet_gen::run_arp_replay()
{
    eth_hdr eh;
    packet p(eh.get_hdr_len() + conf_->arp_conf.arp_h.get_hdr_len());
    uint8_t dst[6] = {0};
    int count = 0;

    log_->info("starting ARP replay\n");

    std::memcpy(eh.src_mac,
                conf_->arp_conf.arp_h.sender_hw_addr,
                FW_MACADDR_LEN);
    std::memcpy(eh.dst_mac,
                conf_->arp_conf.arp_h.target_hw_addr,
                FW_MACADDR_LEN);
    eh.ethertype = static_cast<uint16_t>(Ether_Type::Ether_Type_ARP);

    eh.serialize(p);
    conf_->arp_conf.arp_h.serialize(p);

    count = conf_->arp_conf.count;

    while ((count > 0) || (conf_->arp_conf.repeat)) {
        raw_->send_msg(dst, p.buf, p.buf_len);
        count --;

        std::this_thread::sleep_for(
                std::chrono::microseconds(conf_->arp_conf.inter_pkt_gap_us));
    }

    log_->info("ARP replay complete\n");
}

void packet_gen::run()
{
    if (conf_->pcap_conf.is_valid()) {
        run_pcap_replay();
    }
    if (conf_->eth_conf.is_valid()) {
        run_eth_replay();
    }
    if (conf_->arp_conf.is_valid()) {
        run_arp_replay();
    }
}

void packet_gen::run_eth_replay()
{
    packet p(conf_->eth_conf.pkt_len);
    eth_hdr eh;
    uint8_t dst[6] = {0};
    int count = 0;

    log_->info("Starting Ethernet Replay\n");

    std::memcpy(eh.src_mac,
                conf_->eth_conf.src_mac, sizeof(conf_->eth_conf.src_mac));
    std::memcpy(eh.dst_mac,
                conf_->eth_conf.dst_mac, sizeof(conf_->eth_conf.dst_mac));
    eh.ethertype = conf_->eth_conf.ethertype;
    eh.serialize(p);

    p.buf_len = p.off + conf_->eth_conf.pkt_len;

    count = conf_->eth_conf.count;

    log_->info("count %d repeat_enable %d\n", count, conf_->eth_conf.repeat);

    while ((count > 0) || (conf_->eth_conf.repeat)) {
        raw_->send_msg(dst, p.buf, p.buf_len);
        count --;

        std::this_thread::sleep_for(
                std::chrono::microseconds(conf_->eth_conf.inter_pkt_gap_us));
    }

    log_->info("replay complete\n");
}

void packet_gen::run_ipv4_replay()
{
}

}

int main(int argc, char **argv)
{
    firewall::packet_gen pktgen;
    int ret;

    ret = pktgen.init(argc, argv);
    if (ret != 0) {
        return -1;
    }

    pktgen.run();

    return 0;
}

