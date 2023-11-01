#include <getopt.h>
#include <fw_ctl.h>
#include <fw_ctl_mqtt.h>

namespace firewall {

static std::string mqtt_ipaddr_port;
static std::string topicname;
static std::string keyfile;

static void usage(std::string progname)
{
    fprintf(stderr, "<%s> <-m mqtt ip:port> <-t topicname> <-d decryption key>\n", progname.c_str());
}

int fw_ctl::init(int argc, char **argv)
{
    int ret;

    while ((ret = getopt(argc, argv, "m:t:d:")) != -1) {
        switch (ret) {
            case 'm':
                mqtt_ipaddr_port = optarg;
            break;
            case 't':
                topicname = optarg;
            break;
            case 'd':
                keyfile = optarg;
            break;
            default:
                usage(argv[0]);
            return -1;
        }
    }

    mqtt_thr_ = std::make_shared<std::thread>(&fw_ctl::listen_for_mqtt_msgs, this);
    mqtt_thr_->detach();

    return 0;
}

void fw_ctl::run()
{
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
