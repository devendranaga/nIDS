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
        /**
         * @brief - get instance of the logger.
         */
        static logger *instance()
        {
            static logger log;

            return &log;
        }
        ~logger() = default;

        /**
         * @brief - print info message.
         *
         * @param [in] fmt - string format.
         */
        void info(const char *fmt, ...);
        /**
         * @brief - print verbose message.
         *
         * @param [in] fmt - string format.
         */
        void verbose(const char *fmt, ...);
        /**
         * @brief - print warn message.
         *
         * @param [in] fmt - string format.
         */
        void warn(const char *fmt, ...);
        /**
         * @brief - print error message.
         *
         * @param [in] fmt - string format.
         */
        void error(const char *fmt, ...);
        /**
         * @brief - print fatal message.
         *
         * @param [in] fmt - string format.
         */
        void fatal(const char *fmt, ...);

        explicit logger(const logger &) = delete;
        const logger& operator=(const logger &) = delete;
        explicit logger(const logger &&) = delete;
        const logger&& operator=(const logger &&) = delete;
    private:
        explicit logger() { }
};

}

#endif

