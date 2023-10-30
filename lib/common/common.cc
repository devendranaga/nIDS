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

void get_ipaddr(uint32_t ipaddr, std::string &ipaddr_str)
{
    char ipaddr_s[48];

    snprintf(ipaddr_s, sizeof(ipaddr_s), "%u.%u.%u.%u",
                       (ipaddr & 0x000000FF),
                       (ipaddr & 0x0000FF00) >> 8,
                       (ipaddr & 0x00FF0000) >> 16,
                       (ipaddr & 0xFF000000) >> 24);

    ipaddr_str = ipaddr_s;
}

int parse_str_to_ipv4_addr(const std::string &v, uint32_t &ipaddr)
{
    uint32_t ip_4;
    uint32_t ip_3;
    uint32_t ip_2;
    uint32_t ip_1;
    int ret;

    ret = sscanf(v.c_str(), "%u.%u.%u.%u", &ip_4, &ip_3, &ip_2, &ip_1);
    if (ret != 4) {
        return -1;
    }

    ipaddr = (ip_4) + (ip_3 << 8) + (ip_2 << 16) + (ip_1 << 24);
    return 0;
}

double diff_timespec(const struct timespec *time1, const struct timespec *time0)
{
    return ((time1->tv_sec - time0->tv_sec) * 1000000000.0) +
            (time1->tv_nsec - time0->tv_nsec);
}

}

