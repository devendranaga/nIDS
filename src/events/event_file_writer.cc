/**
 * @brief - Writes event logs to disk
 * 
 * @copyright - 2023-present All rights reserved. Devendra Naga.
*/
#include <config.h>
#include <ether_types.h>
#include <event_file_writer.h>

namespace firewall {

//
// create a filename with timestamp.
fw_error_type event_file_writer::create_new_file(bool is_json)
{
    char filename[1024];
    time_t now;
    struct tm *t;
    struct timespec ts;

    if (fp_) {
        if (is_json) {
            fprintf(fp_, "\n]\n}\n");
        }
        fflush(fp_);
        fclose(fp_);
    }

    now = time(0);
    t = gmtime(&now);
    clock_gettime(CLOCK_REALTIME, &ts);

    snprintf(filename, sizeof(filename), "%s/event_log_%04d_%02d_%02d_%02d_%02d_%02d_%04lld.bin",
                        filepath_.c_str(),
                        t->tm_year + 1900,
                        t->tm_mon + 1,
                        t->tm_mday,
                        t->tm_hour,
                        t->tm_min,
                        t->tm_sec,
                        ts.tv_nsec / 1000000ull);
    fp_ = fopen(filename, "w");
    if (!fp_) {
        return fw_error_type::eInvalid;
    }

    if (is_json) {
        fprintf(fp_, "{\n\"event_info\":[\n");
    }

    return fw_error_type::eNo_Error;
}

fw_error_type event_file_writer::init(const std::string filepath, uint32_t filesize_bytes)
{
    firewall_config *conf = firewall_config::instance();

    //
    // if already opened, close it
    if (fp_) {
        fflush(fp_);
        fclose(fp_);
    }

    cur_size_ = 0;
    filepath_ = filepath;
    filesize_bytes_ = filesize_bytes;
    fp_ = NULL;

    return create_new_file(conf->evt_config.evt_file_format == event_file_format::Json);
}

fw_error_type event_file_writer::write(const event &evt)
{
    fw_error_type ret;
    uint8_t buf[2048];
    event_msg *msg = (event_msg *)buf;
    int total_len = 0;

    std::memset(buf, 0, sizeof(buf));

    msg->evt_type = evt.evt_type;
    msg->evt_desc = evt.evt_details;
    msg->rule_id = evt.rule_id;
    msg->ethertype = evt.ethertype;

    total_len += sizeof(event_msg);

    switch (evt.ethertype) {
        case static_cast<uint16_t>(ether_type::Ether_Type_IPv4): {
            event_ipv4_info *ipv4_evt = (event_ipv4_info *)msg->data;

            ipv4_evt->src_addr = evt.src_addr;
            ipv4_evt->dst_addr = evt.dst_addr;
            ipv4_evt->ttl = evt.ttl;
        } break;
    }

    //
    // if its over filesize, rotate it
    if (cur_size_ >= filesize_bytes_) {
        ret = create_new_file(false);
        if (ret != fw_error_type::eNo_Error) {
            return ret;
        }
        cur_size_ = 0;
    }

    if (fp_) {
        fwrite(msg, total_len, 1, fp_);
        fflush(fp_);
        cur_size_ += total_len;
    }

    return fw_error_type::eNo_Error;
}

static void src_mac_to_str(const uint8_t *src, char *src_str)
{
    sprintf(src_str, "%02x-%02x-%02x-%02x-%02x-%02x",
                        src[0], src[1],
                        src[2], src[3],
                        src[4], src[5]);
}

fw_error_type event_file_writer::write_json(const event &evt)
{
    fw_error_type ret;
    char buf[2048];
    char mac_str[32];
    int len = 0;

    len = snprintf(buf, sizeof(buf), "{\n");

    len += snprintf(buf + len, sizeof(buf) - len,
                    "\t\"event_type\": %d,\n", static_cast<uint32_t>(evt.evt_type));
    len += snprintf(buf + len, sizeof(buf) - len,
                    "\t\"event_description\": %d,\n", static_cast<uint32_t>(evt.evt_details));
    len += snprintf(buf + len, sizeof(buf) - len,
                    "\t\"rule_id\": %d,\n", static_cast<uint32_t>(evt.rule_id));
    src_mac_to_str(evt.src_mac, mac_str);
    len += snprintf(buf + len, sizeof(buf) - len,
                    "\t\"src_mac\": \"%s\",\n", mac_str);
    src_mac_to_str(evt.dst_mac, mac_str);
    len += snprintf(buf + len, sizeof(buf) - len,
                    "\t\"dst_mac\": \"%s\",\n", mac_str);
    len += snprintf(buf + len, sizeof(buf) - len,
                    "\t\"ethertype\": \"0x%04x\",\n", evt.ethertype);

    switch (static_cast<ether_type>(evt.ethertype)) {
        case ether_type::Ether_Type_IPv4: {
            len += snprintf(buf + len, sizeof(buf) - len,
                            "\t\"src_addr\": %u,\n", evt.src_addr);
            len += snprintf(buf + len, sizeof(buf) - len,
                            "\t\"dst_addr\": %u,\n", evt.dst_addr);
            len += snprintf(buf + len, sizeof(buf) - len,
                            "\t\"protocol\": %u,\n", evt.protocol);
        } break;
        default:
        break;
    }

    switch (static_cast<protocols_types>(evt.protocol)) {
        case protocols_types::Protocol_Tcp: {
            len += snprintf(buf + len, sizeof(buf) - len,
                            "\t\"src_port\": %u,\n", evt.src_port);
            len += snprintf(buf + len, sizeof(buf) - len,
                            "\t\"dst_port\": %u,\n", evt.dst_port);
        } break;
        default:
        break;
    }

    len += snprintf(buf + len, sizeof(buf) - len,
                    "\t\"packet_len\": %u\n", evt.pkt_len);

    //
    // if its over filesize, rotate it
    if (cur_size_ >= filesize_bytes_) {
        len += snprintf(buf + len, sizeof(buf) - len, "}\n");
        fwrite(buf, len, 1, fp_);
        fflush(fp_);

        ret = create_new_file(true);
        if (ret != fw_error_type::eNo_Error) {
            return ret;
        }
        cur_size_ = 0;
    } else {
        len += snprintf(buf + len, sizeof(buf) - len, "},\n");
        fwrite(buf, len, 1, fp_);
        fflush(fp_);
        cur_size_ += len;
    }

    return fw_error_type::eNo_Error;
}

}
