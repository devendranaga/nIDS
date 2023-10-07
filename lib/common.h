/**
 * @brief - Implements common definitions.
 * 
 * @copyright - 2023-present All rights reserved.
*/
#ifndef __FW_COMMON_H__
#define __FW_COMMON_H__

namespace firewall {

#define FW_MACADDR_LEN 6

enum class fw_error_type {
	eSerialize_Failure,
	eDeserialize_Failure,
	eOut_Of_Bounds,
	eToo_Short,
	eInvalid,

	/* Configuration error. */
	eConfig_Error,

	/* Success. */
	eNo_Error,
};

}

#endif

