/**
 * @brief - Implements commonly used functions.
 * 
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
*/
#include <iostream>
#include <stdint.h>
#include <string.h>
#include <string>
#include <common.h>

namespace firewall {

int parse_str_to_uint16(const std::string &v,
                        uint16_t &r)
{
    char *err = NULL;

    r = strtoul(v.c_str(), &err, 10);
    if (err && (err[0] != '\0')) {
        return -1;
    }

    return 0;
}

int parse_str_to_uint16_h(const std::string &v,
                          uint16_t &r)
{
    char *err = NULL;

    r = strtoul(v.c_str(), &err, 16);
    if (err && (err[0] != '\0')) {
        return -1;
    }

    return 0;
}

int parse_str_to_uint32(const std::string &v,
                        uint32_t &r)
{
    char *err = NULL;

    r = strtoul(v.c_str(), &err, 10);
    if (err && (err[0] != '\0')) {
        return -1;
    }

    return 0;
}

int parse_str_to_uint32_h(const std::string &v,
                          uint32_t &r)
{
    char *err = NULL;

    r = strtoul(v.c_str(), &err, 16);
    if (err && (err[0] != '\0')) {
        return -1;
    }

    return 0;
}

int parse_str_to_mac(const std::string &v, uint8_t *mac)
{
    uint32_t mac_addr[6];
    int ret;

    ret = sscanf(v.c_str(), "%02x:%02x:%02x:%02x:%02x:%02x",
                            &mac_addr[0], &mac_addr[1],
                            &mac_addr[2], &mac_addr[3],
                            &mac_addr[4], &mac_addr[5]);
    if (ret != 6) {
        return -1;
    }

    mac[0] = mac_addr[0];
    mac[1] = mac_addr[1];
    mac[2] = mac_addr[2];
    mac[3] = mac_addr[3];
    mac[4] = mac_addr[4];
    mac[5] = mac_addr[5];

    return 0;
}

}
