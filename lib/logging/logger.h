/**
 * @brief - Implements Logger.
 * 
 * @copyright - 2023-present All rights reserved.
*/
#ifndef __FW_LOGGER_H__
#define __FW_LOGGER_H__

namespace firewall {

class logger {
    public:
        static logger *instance()
        {
            static logger log;

            return &log;
        }
        ~logger() = default;

        void info(const char *fmt, ...);
        void verbose(const char *fmt, ...);
        void warn(const char *fmt, ...);
        void error(const char *fmt, ...);
        void fatal(const char *fmt, ...);

    private:
        explicit logger() { }
        explicit logger(const logger &) = delete;
        const logger& operator=(const logger &) = delete;
        explicit logger(const logger &&) = delete;
        const logger&& operator=(const logger &&) = delete;
};

}

#endif

