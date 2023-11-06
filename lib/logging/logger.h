/**
 * @brief - Implements Logger.
 *
 * @copyright - 2023-present All rights reserved.
*/
#ifndef __FW_LOGGER_H__
#define __FW_LOGGER_H__

#include <iostream>
#include <string>

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
         * @brief - init the logger
         *
         * @param [in] log_to_file - log to file stream
         * @param [in] log_file_path - log file path
         * @param [in] log_to_syslog - log to syslog sink
         * @param [in] log_to_console - log to console sink
        */
        void init(bool log_to_file,
                  const std::string &log_file_path,
                  bool log_to_syslog,
                  bool log_to_console);

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
        bool log_to_file_;
        std::string log_file_path_;
        bool log_to_syslog_;
        bool log_to_console_;
        FILE *fp_;

        /**
         * @brief - log the message to appropriate sinks.
         *
         * @param [in] fmt - log format
         * @param [in] logger_msg - log message.
         * @param [in] ap - variable argument parameters.
        */
        void log_msg(const char *fmt,
                     const char *logger_msg,
                     va_list ap);
};

}

#endif

