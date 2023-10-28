#ifndef __FW_LIB_PROTOCOLS_PORT_NUMBERS_H__
#define __FW_LIB_PROTOCOLS_PORT_NUMBERS_H__

#include <stdint.h>

namespace firewall {

//
// List of known port numbers
enum class Port_Numbers : uint16_t {
	Port_Number_DHCP_Client = 67,
	Port_Number_DHCP_Server = 68,
	Port_Number_HTTP = 80,
	Port_Number_NTP = 123,
	Port_Number_SNMP = 161,
	Port_Number_TLS = 443,
	Port_Number_MSBlast_CmdCtrl = 4444,
#if defined(FW_ENABLE_AUTOMOTIVE)
	Port_Number_DoIP = 13400,
#endif
	Port_Number_Max = 65535,
};

}

#endif

