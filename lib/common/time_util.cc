/**
 * @brief - Implements Time Utilities.
 *
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
 */
#include <time_util.h>

namespace firewall {

void timestamp_wall(struct timespec *tp)
{
    clock_gettime(CLOCK_REALTIME, tp);
}

void timestamp_perf(struct timespec *tp)
{
    clock_gettime(CLOCK_MONOTONIC, tp);
}

double diff_time_ns(const struct timespec *time1, const struct timespec *time0)
{
    return ((time1->tv_sec - time0->tv_sec) * 1000000000.0) +
            (time1->tv_nsec - time0->tv_nsec);
}

}

