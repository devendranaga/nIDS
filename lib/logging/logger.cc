/**
 * @brief - Implements logging. Currently logs to console.
 *
 * @copyright - 2023-present All rights reserved.
*/
#include <stdio.h>
#include <stdarg.h>
#include <mutex>
#include <time.h>
#include <sys/time.h>
#include <logger.h>
#include <syslog.h>

namespace firewall {

static std::mutex logger_lock;

#define INFO_STR "info: "
#define VERBOSE_STR "verbose: "
#define WARN_STR "warning: "
#define ERROR_STR "error: "
#define FATAL_STR "fatal: "

/**
 * @brief - log to syslog.
 *
 * @param [in] level - log level string
 * @param [in] msg - log message
*/
static void log_syslog(std::string level, const char *msg)
{
    if (level == INFO_STR) {
        syslog(LOG_INFO, "%s", msg);
    } else if (level == VERBOSE_STR) {
        syslog(LOG_INFO, "%s", msg);
    } else if (level == WARN_STR) {
        syslog(LOG_WARNING, "%s", msg);
    } else if (level == ERROR_STR) {
        syslog(LOG_ERR, "%s", msg);
    } else if (level == FATAL_STR) {
        syslog(LOG_CRIT, "%s", msg);
    } else {
        syslog(LOG_INFO, "%s", msg);
    }
}

void logger::log_msg(const char *fmt,
                     const char *logger_msg,
                     va_list ap)
{
    char msg[4096];
    int len;
    time_t now;
    struct tm *t;
    struct timespec ts;

    // if called in from many threads, the call might
    // manipulate msg many times and results in a buffer with
    // mixed text from various calls.
    //
    // thus, to make this function re-entrant, take a global lock and
    // manipulate buffer contents.
    logger_lock.lock();

    now = time(0);
    t = gmtime(&now);
    clock_gettime(CLOCK_REALTIME, &ts);

    len = snprintf(msg, sizeof(msg), "%04d-%02d-%02d %02d:%02d:%02d.%04lld <%s> ",
                                      t->tm_year + 1900, t->tm_mon + 1,
                                      t->tm_mday, t->tm_hour,
                                      t->tm_min, t->tm_sec,
                                      ts.tv_nsec / 1000000ULL, logger_msg);
    vsnprintf(msg + len, sizeof(msg) - len, fmt, ap);

    // write to console
    if (log_to_console_)
        fprintf(stderr, "%s", msg);

    // write to syslog
    if (log_to_syslog_)
        log_syslog(logger_msg, msg);

    // write to file
    if (log_to_file_)
        fprintf(fp_, "%s", msg);

    logger_lock.unlock();
}

void logger::info(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    log_msg(fmt, INFO_STR, ap);
    va_end(ap);
}

void logger::verbose(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    log_msg(fmt, VERBOSE_STR, ap);
    va_end(ap);
}

void logger::warn(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    log_msg(fmt, WARN_STR, ap);
    va_end(ap);
}

void logger::error(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    log_msg(fmt, ERROR_STR, ap);
    va_end(ap);
}

void logger::fatal(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    log_msg(fmt, FATAL_STR, ap);
    va_end(ap);
}

static FILE *new_file(const std::string &path)
{
    std::string filename = path + "/" + "nids_debug_log.txt";
    return fopen(filename.c_str(), "w");
}

void logger::init(bool log_to_file,
                  const std::string &log_file_path,
                  bool log_to_syslog,
                  bool log_to_console)
{
    log_to_file_ = log_to_file;
    log_file_path_ = log_file_path;
    log_to_syslog_ = log_to_syslog;
    log_to_console_ = log_to_console;

    if (log_to_file_)
        fp_ = new_file(log_file_path_);
}

}

