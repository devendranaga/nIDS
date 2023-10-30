/**
 * @brief - Implements common definitions.
 * 
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
*/
#ifndef __FW_COMMON_H__
#define __FW_COMMON_H__

#include <string>

namespace firewall {

#define FW_MACADDR_LEN 6

/**
 * @brief - list of error types.
*/
enum class fw_error_type {
    eSerialize_Failure,
    eDeserialize_Failure,
    eOut_Of_Bounds,
    eToo_Short,
    eInvalid,
    eOut_Of_Memory,

    /* Configuration error. */
    eConfig_Error,

    /* Success. */
    eNo_Error,
};

/**
 * @brief - parse string to uint16_t.
 *
 * @param [in] v - in string.
 * @param [inout] r - output converted integer.
 * 
 * @return 0 on success -1 on failure.
*/
int parse_str_to_uint16(const std::string &v,
                        uint16_t &r);

int parse_str_to_uint16_h(const std::string &v,
                          uint16_t &r);

int parse_str_to_uint32_h(const std::string &v,
                          uint32_t &r);

int parse_str_to_uint32(const std::string &v,
                        uint32_t &r);

int parse_str_to_mac(const std::string &v, uint8_t *mac);

void get_ipaddr(uint32_t ipaddr, std::string &ipaddr_str);

int parse_str_to_ipv4_addr(const std::string &v, uint32_t &ipaddr);

double diff_timespec(const struct timespec *time1,
                     const struct timespec *time0);

}

#endif

