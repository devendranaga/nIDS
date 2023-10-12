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

    log_->info("configuration %s parsed ok\n", filename_.c_str());

    raw_ = std::make_shared<raw_socket>(conf_->ifname, 0);
    log_->info("raw socket create ok\n");

    return 0;
}

void packet_gen::run()
{
    std::unique_ptr<pcap_replay> replay;

    if (conf_->pcap_conf.is_valid()) {
        replay = std::make_unique<pcap_replay>(
                            raw_,
                            conf_->pcap_conf.filepath,
                            conf_->pcap_conf.intvl_us,
                            conf_->pcap_conf.repeat);
        replay->replay();
    }
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

