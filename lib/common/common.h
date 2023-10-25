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

int parse_str_to_uint16(const std::string &v,
                        uint16_t &r);

int parse_str_to_uint16_h(const std::string &v,
                          uint16_t &r);

int parse_str_to_uint32_h(const std::string &v,
                          uint32_t &r);

int parse_str_to_uint32(const std::string &v,
                        uint32_t &r);

int parse_str_to_mac(const std::string &v, uint8_t *mac);

}

#endif

