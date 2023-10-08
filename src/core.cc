#include <core.h>

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

    return fw_error_type::eNo_Error;
}

firewall_intf::firewall_intf(logger *log) : log_(log) { }
firewall_intf::~firewall_intf() { }

fw_error_type firewall_intf::init(const std::string ifname,
                                  const std::string rule_file)
{
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

        stats_.rx_count ++;
        pkt.buf_len = ret;
        pkt.create(buf, ret);

        log_->verbose("rx packet %d\n", stats_.rx_count);

        {
            // queue the frame
            std::unique_lock<std::mutex> lock(rx_thr_lock_);
            rx_thr_cond_.notify_one();
            pkt_q_.push(pkt);
        }
    }
}

void firewall_intf::filter_thread()
{
    while (1) {
        packet pkt;
        bool valid_pkt = false;

        // retrieve one packet from the queue
        {
            std::unique_lock<std::mutex> lock(rx_thr_lock_);
            rx_thr_cond_.wait(lock);
            if (pkt_q_.size() > 0) {
                pkt = pkt_q_.front();
                valid_pkt = true;
            }
            pkt_q_.pop();
        }

        if (valid_pkt) {
            log_->verbose("filter packet with size %d\n", pkt.buf_len);
        }

        pkt.free_pkt();
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
