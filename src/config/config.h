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
    bool log_pcaps;
};

enum class event_file_format {
    Json,
    Binary,
};

enum class event_encryption_algorithm {
    None,
    AES_CTR_128,
    AES_GCM_128,
    AES_GCM_128_W_SHA256,
};

enum class event_hash_algorithm {
    None,
    SHA256,
};

enum class Event_Upload_Method_Type {
    None,
    MQTT,
};

struct firewall_event_upload_mqtt {
    std::string ipaddr;
    uint32_t port;
    std::string topic_name;
};

/**
 * @brief - implements event configuration.
 */
struct firewall_event_info_config {
    std::string event_file_path;
    uint32_t event_file_size_bytes;
    event_file_format evt_file_format;
    bool log_to_console;
    bool log_to_syslog;
    bool log_to_file;
    bool encrypt_log_file;
    std::string encryption_key;
    event_hash_algorithm hash_alg;
    event_encryption_algorithm enc_alg;
    Event_Upload_Method_Type upload_method;
    firewall_event_upload_mqtt mqtt;
};

struct firewall_debugging {
    bool log_to_console;
    bool log_to_file;
    std::string log_file_path;
    bool log_to_syslog;
};

/**
 * @brief - parses the json configuration of firewall service
*/
struct firewall_config {
    std::vector<firewall_intf_info> intf_list;
    firewall_debugging debug;
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
