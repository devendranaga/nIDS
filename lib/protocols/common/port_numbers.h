#ifndef __FW_LIB_PROTOCOLS_PORT_NUMBERS_H__
#define __FW_LIB_PROTOCOLS_PORT_NUMBERS_H__

#include <stdint.h>

namespace firewall {

//
// List of known port numbers
enum class Port_Numbers : uint16_t {
	Port_Number_DHCP = 67,
	Port_Number_SNMP = 161,
	Port_Number_Max = 65535,
};

}

#endif

