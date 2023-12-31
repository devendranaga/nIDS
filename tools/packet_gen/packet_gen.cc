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

    log_->init(false, "", false, true);

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
                        conf_->pcap_conf.use_pcap_timestamps,
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
                conf_->eth_conf.src_mac,
                FW_MACADDR_LEN);
    std::memcpy(eh.dst_mac,
                conf_->eth_conf.dst_mac,
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
    if (conf_->pcap_conf.enable && conf_->pcap_conf.is_valid())
        run_pcap_replay();

    if (conf_->eth_conf.enable && conf_->eth_conf.is_valid())
        run_eth_replay();

    if (conf_->arp_conf.enable && conf_->arp_conf.is_valid())
        run_arp_replay();

    if (conf_->ipv4_conf.enable && conf_->ipv4_conf.is_valid())
        run_ipv4_replay();

    if (conf_->macsec_conf.enable && conf_->macsec_conf.is_valid())
        run_macsec_replay();

    if (conf_->vlan_conf.enable && conf_->vlan_conf.is_Valid())
        run_vlan_replay();
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

int packet_gen::make_ipv4_packet(packet &p, int count)
{
    eth_hdr eh;
    ipv4_hdr ipv4_h;
    uint32_t ttl;
    int ret;

    p.off = 0;

    std::memcpy(eh.src_mac,
                conf_->ipv4_conf.src_mac, sizeof(conf_->ipv4_conf.src_mac));
    std::memcpy(eh.dst_mac,
                conf_->ipv4_conf.dest_mac, sizeof(conf_->ipv4_conf.dest_mac));
    eh.ethertype = static_cast<uint16_t>(Ether_Type::Ether_Type_IPv4);
    eh.serialize(p);

    ipv4_h.version = 4;
    ipv4_h.dscp = 0;
    ipv4_h.ecn = 0;
    ipv4_h.total_len = conf_->ipv4_conf.ipv4_len;
    ipv4_h.identification = conf_->ipv4_conf.id;
    ipv4_h.reserved = 0;
    ipv4_h.dont_frag = 0;
    ipv4_h.more_frag = 0;
    ipv4_h.frag_off = 0;

    ttl = conf_->ipv4_conf.ttl;
    if (conf_->ipv4_conf.auto_ttl)
        ttl = count;

    ipv4_h.ttl = ttl;
    ipv4_h.protocol = conf_->ipv4_conf.protocol;
    ipv4_h.src_addr = conf_->ipv4_conf.src_ipaddr;
    ipv4_h.dst_addr = conf_->ipv4_conf.dest_ipaddr;
    ret = ipv4_h.serialize(p);
    if (ret < 0) {
        log_->error("failed to serialize ipv4 packet\n");
        return -1;
    }

    return 0;
}

void packet_gen::run_ipv4_replay()
{
    packet p(1500);
    uint8_t dst[6] = {0};
    uint32_t count = 0;
    uint32_t total_count;

    log_->info("Starting IPv4 Replay\n");

    total_count = conf_->ipv4_conf.count;
    if (conf_->ipv4_conf.auto_ttl) {
        total_count = 255;
    }
    for (; count < total_count; count ++) {
        make_ipv4_packet(p, count + 1);

        p.buf_len = p.off;

        raw_->send_msg(dst, p.buf, p.buf_len);

        std::this_thread::sleep_for(
                std::chrono::microseconds(conf_->ipv4_conf.inter_pkt_gap_us));

        printf("sent [%d]\n", count + 1);
    }

    log_->info("Replay complete\n");
}

void packet_gen::run_vlan_replay()
{
    packet p(1500);
    uint8_t dst[6] = {0};
    uint32_t count = 0;
    eth_hdr eh;
    vlan_hdr vh;

    log_->info("Starting VLAN Replay\n");

    std::memcpy(eh.src_mac,
                conf_->vlan_conf.eth_src_mac, FW_MACADDR_LEN);
    std::memcpy(eh.dst_mac,
                conf_->vlan_conf.eth_dst_mac, FW_MACADDR_LEN);
    eh.ethertype = static_cast<uint16_t>(Ether_Type::Ether_Type_VLAN);
    eh.serialize(p);

    vh.pri = conf_->vlan_conf.priority;
    vh.dei = conf_->vlan_conf.dei;
    vh.vid = conf_->vlan_conf.vid;
    vh.ethertype = conf_->vlan_conf.ethertype;
    vh.serialize(p);

    for (; count < conf_->vlan_conf.count; count ++) {
        p.buf_len = p.off;

        raw_->send_msg(dst, p.buf, p.buf_len);

        std::this_thread::sleep_for(
                std::chrono::microseconds(conf_->vlan_conf.inter_pkt_gap_us));

        printf("sent [%d]\n", count + 1);
    }

    log_->info("Replay complete\n");
}

void packet_gen::run_macsec_replay()
{
    packet p(1500);
    uint8_t dst[6] = {0};
    uint32_t count = 0;
    eth_hdr eh;

    log_->info("Starting MACsec Replay\n");

    std::memcpy(eh.src_mac,
                conf_->macsec_conf.eth_src,
                sizeof(conf_->macsec_conf.eth_src));
    std::memcpy(eh.dst_mac,
                conf_->macsec_conf.eth_dst,
                sizeof(conf_->macsec_conf.eth_dst));
    eh.ethertype = conf_->macsec_conf.ethertype;

    eh.serialize(p);
    //
    // freed by the destructor of macsec_hdr.
    conf_->macsec_conf.macsec_h.data = (uint8_t *)calloc(1, conf_->macsec_conf.macsec_h.data_len);
    if (!conf_->macsec_conf.macsec_h.data) {
        return;
    }
    conf_->macsec_conf.macsec_h.serialize(p);

    p.buf_len = p.off;

    for (count = 0; count < conf_->macsec_conf.count; count ++) {    
        raw_->send_msg(dst, p.buf, p.buf_len);

        std::this_thread::sleep_for(
                std::chrono::microseconds(conf_->macsec_conf.inter_pkt_gap_us));

        printf("sent [%d]\n", count + 1);
    }

    log_->info("Replay complete\n");
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

