/**
 * @brief - Writes event logs to disk
 * 
 * @copyright - 2023-present All rights reserved. Devendra Naga.
*/
#include <ether_types.h>
#include <event_file_writer.h>

namespace firewall {

//
// create a filename with timestamp.
fw_error_type event_file_writer::create_new_file()
{
    char filename[1024];
    time_t now;
    struct tm *t;
    struct timespec ts;

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

    cur_size_ = 0;

    return fw_error_type::eNo_Error;
}

fw_error_type event_file_writer::init(const std::string filepath, uint32_t filesize_bytes)
{
    //
    // if already opened, close it
    if (fp_) {
        fflush(fp_);
        fclose(fp_);
    }

    filepath_ = filepath;
    filesize_bytes_ = filesize_bytes;
    fp_ = NULL;

    return create_new_file();
}

fw_error_type event_file_writer::write(const event &evt)
{
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
        create_new_file();
    }

    if (fp_) {
        fwrite(msg, total_len, 1, fp_);
        fflush(fp_);
    }

    cur_size_ += total_len;

    return fw_error_type::eNo_Error;
}

}
