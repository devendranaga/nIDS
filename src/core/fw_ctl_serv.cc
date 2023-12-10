/**
 * @brief - Implements fwctl front end for the clients connected to IDS.
 *
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
*/
#include <packet_stats.h>
#include <fw_ctl_serv.h>

namespace firewall {

fwctl_server::fwctl_server(logger *log)
{
    int ret;

    log_ = log;

    sock_ = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sock_ < 0)
        throw std::system_error(errno, std::generic_category());

    unlink(FWCTL_SOCKET_PATH);

    addr_.sun_family = AF_UNIX;
    strcpy(addr_.sun_path, FWCTL_SOCKET_PATH);

    ret = bind(sock_, (struct sockaddr *)&addr_, sizeof(addr_));
    if (ret < 0) {
        close(sock_);
        throw std::system_error(errno, std::generic_category());
    }

    rx_thr_ = std::make_unique<std::thread>(&fwctl_server::fwctl_rx_pkt, this);
    rx_thr_->detach();
}

void fwctl_server::fwctl_rx_pkt()
{
    struct sockaddr_un sender;
    socklen_t sender_len;
    struct fwctl_msg *ctl;
    uint8_t msg[4096];
    int ret;

    while (1) {
        sender_len = sizeof(struct sockaddr_un);

        //
        // receive and process the client request
        ret = recvfrom(sock_, msg, sizeof(msg), 0,
                       (struct sockaddr *)&sender, &sender_len);
        if (ret < 0)
            continue;

        ctl = (struct fwctl_msg *)msg;

        switch (ctl->type) {
            case FWCTL_MSGTYPE_GET_STATS: {
                fwctl_write_stats(&sender, sender_len);
            } break;
            default:
            return;
        }
    }
}

void fwctl_server::fwctl_write_stats(struct sockaddr_un *sender,
                                     socklen_t sender_len)
{
    firewall_pkt_stats *stats = firewall_pkt_stats::instance();
    std::map<std::string, firewall_intf_stats> intf_stats;
    struct fwctl_stats *ctl_stats;
    struct fwctl_msg *ctl;
    uint8_t msg[4096];
    int total_len = 0;
    int off = 0;

    ctl = (fwctl_msg *)msg;

    stats->get(intf_stats);

    ctl->type = FWCTL_MSGTYPE_GET_STATS;

    //
    // for each interface copy the stats
    for (auto it : intf_stats) {
        ctl_stats = (fwctl_stats *)(ctl->data + off);

        ctl_stats->startup_time.ts_sec = it.second.startup_time.tv_sec;
        strcpy(ctl_stats->ifname, it.first.c_str());
        ctl_stats->n_rx = it.second.n_rx;
        ctl_stats->n_allowed = it.second.n_allowed;
        ctl_stats->n_deny = it.second.n_deny;

        off += sizeof(fwctl_stats);
    }

    //
    // total length is header (type) + data (series of buffers of fwctl_stats)
    total_len = sizeof(fwctl_msg) + off;

    sendto(sock_, msg, total_len, 0, (struct sockaddr *)sender, sender_len);
}

fwctl_server::~fwctl_server()
{

}

}
