/**
 * @brief - Implement firewall configuration parser.
 * 
 * @copyright - 2023-present All rights reserved. Devendra Naga.
*/
#include <iostream>
/**
 * @brief - Implements firewall configuration parser.
 * 
 * @copyright - 2023-present All rights reserved. Devendra Naga.
*/
#include <fstream>
#include "jsoncpp/json/json.h"
#include <config.h>

namespace firewall {

fw_error_type firewall_config::parse(const std::string config_file)
{
    Json::Value root;
    std::ifstream conf(config_file, std::ifstream::binary);

    conf >> root;

    auto intf_info = root["interface_info"];

    for (auto it : intf_info) {
        firewall_intf_info ifinfo;

        ifinfo.intf_name = it["interface"].asString();
        ifinfo.rule_file = it["rule_file"].asString();
        ifinfo.log_pcaps = it["log_pcaps"].asBool();

        intf_list.emplace_back(ifinfo);
    }

    tunables_config_filename = root["tunables_config"].asString();

    //
    // Debugging configuration
    debug.log_to_console = root["debugging"]["log_to_console"].asBool();
    debug.log_to_file = root["debugging"]["log_to_file"].asBool();
    debug.log_file_path = root["debugging"]["log_file_path"].asString();
    debug.log_to_syslog = root["debugging"]["log_to_syslog"].asBool();

    evt_config.event_file_path = root["events"]["event_file_path"].asString();
    evt_config.event_file_size_bytes = root["events"]["event_file_size_bytes"].asUInt();
    auto evt_file_fmt = root["events"]["event_file_format"].asString();
    if (evt_file_fmt == "json") {
        evt_config.evt_file_format = event_file_format::Json;
    } else if (evt_file_fmt == "binary") {
        evt_config.evt_file_format = event_file_format::Binary;
    } else {
        return fw_error_type::eConfig_Error;
    }
    evt_config.log_to_syslog = root["events"]["log_to_syslog"].asBool();
    evt_config.log_to_file = root["events"]["log_to_file"].asBool();
    evt_config.encrypt_log_file = root["events"]["encrypt_log_file"].asBool();
    evt_config.encryption_key = root["events"]["encryption_key"].asString();
    evt_config.log_to_console = root["events"]["log_to_console"].asBool();

    auto enc_alg = root["events"]["encryption_algorithm"].asString();
    if (enc_alg == "aes_gcm_128_with_sha256") {
        evt_config.enc_alg = event_encryption_algorithm::AES_GCM_128_W_SHA256;
    } else if (enc_alg == "aes_gcm_128") {
        evt_config.enc_alg = event_encryption_algorithm::AES_GCM_128;
    } else if (enc_alg == "aes_ctr_128") {
        evt_config.enc_alg = event_encryption_algorithm::AES_CTR_128;
    } else {
        return fw_error_type::eConfig_Error;
    }
    auto hash_alg = root["events"]["hash_algorithm"].asString();
    if (hash_alg == "SHA256") {
        evt_config.hash_alg = event_hash_algorithm::SHA256;
    } else {
        return fw_error_type::eConfig_Error;
    }

    auto evt_upload_method = root["events"]["event_upload_method"].asString();
    if (evt_upload_method == "mqtt") {
        evt_config.upload_method = Event_Upload_Method_Type::MQTT;

        evt_config.mqtt.ipaddr = root["events"]["mqtt_config"]["ip"].asString();
        evt_config.mqtt.port = root["events"]["mqtt_config"]["port"].asUInt();
        evt_config.mqtt.topic_name = root["events"]["mqtt_config"]["topic_name"].asString();
    } else if (evt_upload_method == "udp") {
        evt_config.upload_method = Event_Upload_Method_Type::UDP;

        evt_config.udp_config.ipaddr = root["events"]["udp_config"]["ip"].asString();
        evt_config.udp_config.port = root["events"]["udp_config"]["port"].asUInt();
    } else if (evt_upload_method == "local_unix") {
        evt_config.upload_method = Event_Upload_Method_Type::Local_UNIX;

        evt_config.local_unix_config.path = root["events"]["local_unix_config"]["path"].asString();
    }

    return fw_error_type::eNo_Error;
}

}
