#include <iostream>
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

    evt_config.event_file_path = root["event_file_path"].asString();
    evt_config.event_file_size_bytes = root["event_file_size_bytes"].asUInt();
    auto evt_file_fmt = root["event_file_format"].asString();
    if (evt_file_fmt == "json") {
        evt_config.evt_file_format = event_file_format::Json;
    } else {
        return fw_error_type::eConfig_Error;
    }

    return fw_error_type::eNo_Error;
}

}
