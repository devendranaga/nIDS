/**
 * @brief - implements firewall control utility base code.
 *
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
*/
#include <getopt.h>
#include <unistd.h>
#include <sys/time.h>
#include <time_util.h>
#include <time.h>
#include <fw_ctl.h>
#include <fw_ctl_mqtt.h>

namespace firewall {

static std::string mqtt_ipaddr_port;
static std::string topicname;
static std::string keyfile;
static bool mqtt_option = false;
static bool console_mode = false;
static std::string local_sockpath = "";
static bool stats = false;

static void usage(std::string progname)
{
    fprintf(stderr, "%s allows to get stats or listen to events from the IDS.\n"
                    "It supports various interfaces. Below are the sample usages: \n", progname.c_str());
    fprintf(stderr, "\t <-m mqtt ip:port> <-t topicname> <-d decryption key>\n");
    fprintf(stderr, "\t <-l local socket path> <-s get stats>\n");
}

int fw_ctl::init(int argc, char **argv)
{
    int ret;

    while ((ret = getopt(argc, argv, "l:m:t:d:p:s")) != -1) {
        switch (ret) {
            //
            // local socket
            case 'l':
                local_sockpath = optarg;
            break;
            case 'm':
                mqtt_ipaddr_port = optarg;
                mqtt_option = true;
            break;
            case 't':
                mqtt_option = true;
            break;
            case 'd':
                keyfile = optarg;
            break;
            case 'p':
                console_mode = true;
            break;
            //
            // get stats
            case 's':
                stats = true;
            break;
            default:
                usage(argv[0]);
            return -1;
        }
    }

    if (mqtt_option) {
        mqtt_thr_ = std::make_shared<std::thread>(&fw_ctl::listen_for_mqtt_msgs, this);
        mqtt_thr_->detach();
    } else if (local_sockpath != "") { // if local socket given lets initialize
        ret = local_sock_init(local_sockpath);
    }
    if (console_mode) {
    }

    return 0;
}

int fw_ctl::local_sock_init(const std::string &path)
{
    int ret;

    //
    // create unix socket client
    sock_ = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sock_ < 0)
        return -1;

    unlink(path.c_str());

    addr_.sun_family = AF_UNIX;
    strcpy(addr_.sun_path, path.c_str());

    ret = bind(sock_, (struct sockaddr *)&addr_, sizeof(addr_));
    if (ret < 0) {
        close(sock_);
        sock_ = -1;
        return -1;
    }

    server_addr_.sun_family = AF_UNIX;
    strcpy(server_addr_.sun_path, FWCTL_SOCKET_PATH);

    //
    // get stats
    if (stats) {
        local_sock_get_stats();
    }

    return 0;
}

void fw_ctl::local_sock_get_stats()
{
    struct timespec cur_tp;
    struct fwctl_msg *ctl;
    uint8_t *msg[4096];
    uint32_t msg_len = 0;
    int off = 0;
    int ret;

    //
    // prepare the get stats message
    ctl = (fwctl_msg *)msg;
    ctl->type = FWCTL_MSG_GET_STATS;

    msg_len = sizeof(fwctl_msg);

    ret = sendto(sock_, msg, msg_len, 0,
                 (struct sockaddr *)&server_addr_, sizeof(server_addr_));
    if (ret < 0) {
        fprintf(stderr, "sendto failure.. couldn't reach server error : %d\n", errno);
        return;
    }

    ret = recvfrom(sock_, msg, sizeof(msg), 0, nullptr, nullptr);
    if (ret < 0) {
        fprintf(stderr, "recvfrom failure error: %d\n", errno);
        return;
    }

    if (ctl->type != FWCTL_MSG_GET_STATS) {
        fprintf(stderr, "recieved message is not stats\n");
        return;
    }

    //
    // print get stats
    ret -= sizeof(fwctl_msg);

    timestamp_wall(&cur_tp);

    fprintf(stderr, "stats: {\n");

    while (off < ret) {
        struct fwctl_stats *stats = (struct fwctl_stats *)(ctl->data + off);
        struct timespec tp;
        double delta;

        tp.tv_sec = stats->startup_time.ts_sec;
        tp.tv_nsec = stats->startup_time.ts_nsec;

        delta = diff_time_ns(&cur_tp, &tp);

        fprintf(stderr, "\t ifname: %s {\n", stats->ifname);
        fprintf(stderr, "\t\t uptime: %f sec\n", delta / 1000000000);
        fprintf(stderr, "\t\t n_rx: %ju\n", stats->n_rx);
        fprintf(stderr, "\t\t n_allowed: %ju\n", stats->n_allowed);
        fprintf(stderr, "\t\t n_deny: %ju\n", stats->n_deny);
        fprintf(stderr, "\t }\n");

        off += sizeof(struct fwctl_stats);
    }

    fprintf(stderr, "}\n");
}

void fw_ctl::run()
{
    //
    // we are using local socket.. no need to call run
    if (local_sockpath != "")
        return;

    mqtt_listen(mqtt_ipaddr_port, topicname);

    while (1) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void fw_ctl::listen_for_mqtt_msgs()
{
    event_msg_codec codec;
    queue_msg m;
    bool new_msg;
    uint8_t dec_buf[4096];
    event evt;
    int ret;

    while (1) {
        new_msg = global_queue::instance()->new_msg_received(m);
        if (!new_msg)
            continue;

        fprintf(stderr, "Received new msg: %d\n", m.msg_len);
        ret = codec.hash_and_decrypt(m.msg, m.msg_len, dec_buf, keyfile);
        if (ret < 0) {
            fprintf(stderr, "failed to decrypt: is key [%s] correct?\n", keyfile.c_str());
            return;
        }

        ret = codec.deserialize(evt, (event_msg *)dec_buf);
        if (ret < 0) {
            fprintf(stderr, "failed to deserialize\n");
            return;
        }

        fprintf(stderr, "event: {\n");
        fprintf(stderr, "\t event_type: %d\n", static_cast<int>(evt.evt_type));
        fprintf(stderr, "\t event_description: %d\n", static_cast<int>(evt.evt_details));
        fprintf(stderr, "\t ethertype: %04x\n", evt.ethertype);
        fprintf(stderr, "}\n");
    }
}

}

int main(int argc, char **argv)
{
    firewall::fw_ctl f;
    int ret;

    ret = f.init(argc, argv);
    if (ret != 0) {
        return -1;
    }

    f.run();
    return 0;
}
