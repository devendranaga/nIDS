#ifndef __FW_COMMON_H__
#define __FW_COMMON_H__

namespace firewall {

enum class fw_error_type {
	eSerialize_Failure,
	eDeserialize_Failure,
	eOut_Of_Bounds,
	eToo_Short,
	eNo_Error,
};

}

#endif

