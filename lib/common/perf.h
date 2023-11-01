/**
 * @brief - Implements performance analyser.
 * 
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
*/
#ifndef __FW_LIB_COMMON_FW_H__
#define __FW_LIB_COMMON_FW_H__

#include <string>
#include <vector>
#include <memory>
#include <time.h>
#include <sys/time.h>
#include <logger.h>

namespace firewall {

/**
 * @brief - implements a perf item.
*/
class perf_item {
    public:
        explicit perf_item(std::string item_name) :
                            item_name_(item_name) { }
        ~perf_item() { }

        inline void start()
        {
            clock_gettime(CLOCK_MONOTONIC, &start_);
        }
        inline void stop(bool print = false)
        {
            clock_gettime(CLOCK_MONOTONIC, &stop_);
            double diff = diff_timespec(&stop_, &start_);
            deltas_.push_back(diff);

            if (print) {
                logger *log = logger::instance();
                double avg = 0.0;

                for (auto it : deltas_) {
                    avg += it;
                }
                avg /= deltas_.size();
                log->info("name: [%s] cur_diff %f usec avg: %f usec\n",
                                item_name_.c_str(), diff / 1000.0, avg / 1000.0);
            }
        }

    private:
        inline double diff_timespec(const struct timespec *time1, const struct timespec *time0)
        {
            return ((time1->tv_sec - time0->tv_sec) * 1000000000.0) +
                    (time1->tv_nsec - time0->tv_nsec);
        }
        std::string item_name_;
        struct timespec start_;
        struct timespec stop_;
        std::vector<double> deltas_;
};

/**
 * @brief - implements perf.
*/
class perf {
    public:
        explicit perf() { }
        ~perf() { }

        inline std::shared_ptr<perf_item> new_perf(std::string item_name)
        {
            std::shared_ptr<perf_item> p;

            p = std::make_shared<perf_item>(item_name);
            perf_list_.push_back(p);

            return p;
        }

    private:
        std::vector<std::shared_ptr<perf_item>> perf_list_;
};

}

#endif

