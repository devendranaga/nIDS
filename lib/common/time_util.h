/**
 * @brief - Implements Time Utilities.
 *
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
 */
#ifndef __FW_LIB_COMMON_TIME_UTIL_H__
#define __FW_LIB_COMMON_TIME_UTIL_H__

#include <time.h>
#include <sys/time.h>

namespace firewall {

void timestamp_wall(struct timespec *tp);
void timestamp_perf(struct timespec *tp);
double diff_time_ns(const struct timespec *time_new,
                    const struct timespec *time_old);

}

#endif


