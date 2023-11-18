#ifndef __FW_LIB_COMMON_NW_IOCTL_H__
#define __FW_LIB_COMMON_NW_IOCTL_H__

#include <stdint.h>

namespace firewall {

int nw_ioctl_get_broadcast_addr(const char *ifname,
                                uint32_t *addr);

}

#endif
