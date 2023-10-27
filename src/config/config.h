/**
 * @brief - Implements firewall configuration.
 * 
 * @copyright - 2023-present All rights reserved. Devendra Naga.
*/
#ifndef __FW_CONFIG_H__
#define __FW_CONFIG_H__

#include <string>
#include <vector>
#include <common.h>

namespace firewall {

struct firewall_intf_info {
    std::string intf_name;
    std::string rule_file;
};

enum class event_file_format {
    Json,
    Binary,
};

enum class event_encryption_algorithm {
    AES_GCM_128_W_SHA256,
};

struct firewall_event_info_config {
    std::string event_file_path;
    uint32_t event_file_size_bytes;
    event_file_format evt_file_format;
    bool log_to_syslog;
    bool encrypt_log_file;
    std::string encryption_key;
    event_encryption_algorithm enc_alg;
};

/**
 * @brief - parses the json configuration of firewall service
*/
struct firewall_config {
    std::vector<firewall_intf_info> intf_list;
    firewall_event_info_config evt_config;

    ~firewall_config() { }
    static firewall_config *instance()
    {
        static firewall_config conf;
        return &conf;
    }

    fw_error_type parse(const std::string config);

    private:
        explicit firewall_config() { }
        explicit firewall_config(const firewall_config &) = delete;
};

}

#endif
