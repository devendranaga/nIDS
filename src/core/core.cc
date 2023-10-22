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

    log_->info("parsing configuration %s\n", filename);

    ret = conf->parse(filename);
    if (ret != fw_error_type::eNo_Error) {
        log_->error("failed to parse configuration %s\n", filename);
        return ret;
    }

    for (auto it : conf->intf_list) {
        std::shared_ptr<firewall_intf> intf;

        log_->info("create interface context on %s\n", it.intf_name.c_str());

        intf = std::make_shared<firewall_intf>(log_);
        ret = intf->init(it.intf_name, it.rule_file);
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

fw_error_type firewall_intf::init(const std::string ifname,
                                  const std::string rule_file)
{
    fw_error_type ret;

    ifname_ = ifname;

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

    return fw_error_type::eNo_Error;
}

void firewall_intf::rx_thread()
{
    packet pkt;
    uint8_t mac[6];
    uint8_t buf[4096];
    int ret;

    while (1) {
        // receive the frame
        ret = raw_->recv_msg(mac, buf, sizeof(buf));
        if (ret < 0) {
            return;
        }

        pkt.buf_len = ret;
        pkt.create(buf, ret);

        // increment rx frame count
        firewall_pkt_stats::instance()->inc_n_rx(ifname_);

        {
            // queue the frame
            std::unique_lock<std::mutex> lock(rx_thr_lock_);
            rx_thr_cond_.notify_one();
            pkt_q_.push(pkt);
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

    log_->verbose("filter packet with size %d\n", pkt.buf_len);

    ret = p.run(pkt);
    if (ret != 0) {
        firewall_pkt_stats::instance()->inc_n_deny(ifname_);
    }
    pkt.free_pkt();
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

    // initialize the core firewall library
    ret = core.init(argc, argv);
    if (ret != firewall::fw_error_type::eNo_Error) {
        return -1;
    }

    while (1) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

