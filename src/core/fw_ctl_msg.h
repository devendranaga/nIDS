/**
 * @brief - Implements Firewall message interface definition.
 *
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
*/
#ifndef __FW_CTL_MSG_H__
#define __FW_CTL_MSG_H__

#include <stdint.h>

//
// List of types
#define FWCTL_MSGTYPE_GET_STATS 0x01
#define FWCTL_MSGTYPE_INVAL 0xFF
#define FWCTL_IFNAME_MAX 20

//
// FW control Server socket path
#define FWCTL_SOCKET_PATH "./nids_fwctl.sock"

struct fwctl_timestamp {
    uint64_t ts_sec;
    uint64_t ts_nsec;
} __attribute__ ((__packed__));

struct fwctl_stats {
    char ifname[FWCTL_IFNAME_MAX];
    fwctl_timestamp startup_time;
    uint64_t n_rx;
    uint64_t n_allowed;
    uint64_t n_deny;
} __attribute__ ((__packed__));

struct fwctl_msg {
    uint8_t type;
    uint8_t data[0];
} __attribute__ ((__packed__));

#endif

