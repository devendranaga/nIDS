/**
 * @brief - Implements core service.
 *
 * @copyright - 2023-present All rights reserved. Devendra Naga.
*/
#include <core.h>
#include <packet_stats.h>

namespace firewall {

fw_core::fw_core() { }
fw_core::~fw_core() { }

void usage(const char *progname)
{
    fprintf(stderr, "<%s> -f <filename>\n", progname);
}

fw_error_type fw_core::init(int argc, char **argv)
{
    firewall_config *conf = firewall_config::instance();
    char *filename = NULL;
    fw_error_type ret;
    int rc;

    log_ = logger::instance();

    if (argc == 1) {
        usage(argv[0]);
        return fw_error_type::eInvalid;
    }

    while ((rc = getopt(argc, argv, "f:")) != -1) {
        switch (rc) {
            case 'f':
                filename = optarg;
            break;
            default:
                usage(argv[0]);
                return fw_error_type::eInvalid;
        }
    }

    ret = conf->parse(filename);
    if (ret != fw_error_type::eNo_Error) {
        fprintf(stderr, "failed to parse configuration %s\n", filename);
        return ret;
    }

    //
    // init the logging interface
    log_->init(conf->debug.log_to_file,
               conf->debug.log_file_path,
               conf->debug.log_to_syslog,
               conf->debug.log_to_console);

    ret = filter::instance()->init();
    if (ret != fw_error_type::eNo_Error) {
        log_->error("failed to init filter\n");
        return ret;
    }

    for (auto it : conf->intf_list) {
        std::shared_ptr<firewall_intf> intf;

        log_->info("create interface context on %s\n", it.intf_name.c_str());

        //
        // allocate interface pointer
        intf = std::make_shared<firewall_intf>(log_);
        if (!intf) {
            return fw_error_type::eOut_Of_Memory;
        }

        //
        // initialize interface
        ret = intf->init(it.intf_name, it.rule_file, it.log_pcaps);
        if (ret != fw_error_type::eNo_Error) {
            log_->error("failed to init interface on %s\n", it.intf_name.c_str());
            return ret;
        }

        intf_list_.push_back(intf);
    }

    evt_mgr_ = event_mgr::instance();
    ret = evt_mgr_->init(log_);
    if (ret != fw_error_type::eNo_Error) {
        log_->error("failed to init event manager\n");
    }

    log_->info("event_mgr init ok\n");

    return fw_error_type::eNo_Error;
}

firewall_intf::firewall_intf(logger *log) : log_(log)
{
    rule_data_ = rule_config::instance();
}

firewall_intf::~firewall_intf() { }

void firewall_intf::init_pcap_writer()
{
    const std::string filename = "./logs/" + ifname_;
    time_t now = time(0);
    struct tm *t;
    char pcap_file[1024];

    t = gmtime(&now);

    snprintf(pcap_file, sizeof(pcap_file),
                "%s_%04d_%02d_%02d_%02d_%02d_%02d.pcap",
                filename.c_str(),
                t->tm_year + 1900, t->tm_mon + 1,
                t->tm_mday, t->tm_hour,
                t->tm_min, t->tm_sec);
    pcap_w_ = std::make_shared<pcap_writer>(pcap_file);
}

fw_error_type firewall_intf::init(const std::string ifname,
                                  const std::string rule_file,
                                  bool log_pcap)
{
    fw_error_type ret;

    ifname_ = ifname;
    log_pcap_ = log_pcap;

    // Parse rules file
    ret = rule_data_->parse(rule_file);
    if (ret != fw_error_type::eNo_Error) {
        log_->error("failed to parse rules file %s\n", rule_file.c_str());
        return ret;
    }

    log_->info("parse rules file %s for ifname %s ok\n",
                            rule_file.c_str(),
                            ifname.c_str());

    // Create raw socket
    raw_ = std::make_shared<raw_socket>(ifname, 0);

    log_->info("create raw on %s ok\n", ifname.c_str());

    // Create receive thread
    rx_thr_id_ = std::make_shared<std::thread>(&firewall_intf::rx_thread, this);
    rx_thr_id_->detach();

    // Create filter thread
    filt_thr_id_ = std::make_shared<std::thread>(&firewall_intf::filter_thread, this);
    filt_thr_id_->detach();

    log_->info("create rx thread ok\n");

    pkt_perf_ = perf_ctx_.new_perf("pkt_perf");

    //
    // if log pcap is enabled, initialize pcap writer
    if (log_pcap_) {
        init_pcap_writer();
    }

    return fw_error_type::eNo_Error;
}

void firewall_intf::rx_thread()
{
    packet pkt;
    uint8_t mac[6];
    int ret;

    while (1) {
        // receive the frame
        ret = raw_->recv_msg(mac, pkt.buf, sizeof(pkt.buf));
        if (ret < 0) {
            return;
        }

        pkt.buf_len = ret;

        // increment rx frame count
        firewall_pkt_stats::instance()->stats_update(Pktstats_Type::Type_Rx,ifname_);

        {
            // queue the frame
            std::unique_lock<std::mutex> lock(rx_thr_lock_);
            rx_thr_cond_.notify_one();
            pkt_q_.push(pkt);
        }

        if (log_pcap_) {
            pcap_w_->write_packet(pkt.buf, pkt.buf_len);
        }
    }
}

/**
 * @brief - run the packet filter.
 * 
 * This is written indepdently out of the queue retrieve logic to increase
 * the flexibility of queue retrieval design.
*/
void firewall_intf::run_filter(packet &pkt)
{
    parser p(ifname_, log_);
    int ret;

    pkt_perf_->start();

    log_->verbose("filter packet with size %d\n", pkt.buf_len);

    ret = p.run(pkt);
    if (ret != 0) {
        firewall_pkt_stats::instance()->stats_update(Pktstats_Type::Type_Deny, ifname_);
    }

    pkt_perf_->stop(true);
}

void firewall_intf::filter_thread()
{
    while (1) {
        packet pkt;

        // retrieve one packet from the queue
        {
            std::unique_lock<std::mutex> lock(rx_thr_lock_);
            rx_thr_cond_.wait(lock);
            while (pkt_q_.size() > 0) {
                pkt = pkt_q_.front();

                run_filter(pkt);
                pkt_q_.pop();
            }
        }
    }
}

}

int main(int argc, char **argv)
{
    firewall::fw_core core;
    firewall::fw_error_type ret;

    if (geteuid() != 0) {
        fprintf(stderr, "fwd requires super user privileges to run\n");
        return -1;
    }

    // initialize the core firewall library
    ret = core.init(argc, argv);
    if (ret != firewall::fw_error_type::eNo_Error) {
        return -1;
    }

    while (1) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

