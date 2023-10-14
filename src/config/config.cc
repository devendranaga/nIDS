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

        intf_list.emplace_back(ifinfo);
    }

    evt_config.event_file_path = root["events"]["event_file_path"].asString();
    evt_config.event_file_size_bytes = root["events"]["event_file_size_bytes"].asUInt();
    auto evt_file_fmt = root["events"]["event_file_format"].asString();
    if (evt_file_fmt == "json") {
        evt_config.evt_file_format = event_file_format::Json;
    } else {
        return fw_error_type::eConfig_Error;
    }
    evt_config.encrypt_log_file = root["events"]["encrypt_log_file"].asBool();
    evt_config.encryption_key = root["events"]["encryption_key"].asString();

    auto enc_alg = root["events"]["encryption_algorithm"].asString();
    if (enc_alg == "aes_gcm_128_with_sha256") {
        evt_config.enc_alg = event_encryption_algorithm::AES_GCM_128_W_SHA256;
    } else {
        return fw_error_type::eConfig_Error;
    }

    return fw_error_type::eNo_Error;
}

}
