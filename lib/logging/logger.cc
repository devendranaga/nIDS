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

namespace firewall {

static std::mutex logger_lock;

static void log_msg(const char *fmt, const char *logger_msg, va_list ap)
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
    fprintf(stderr, "%s", msg);

    logger_lock.unlock();
}

void logger::info(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    log_msg(fmt, "info", ap);
    va_end(ap);
}

void logger::verbose(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    log_msg(fmt, "verbose", ap);
    va_end(ap);
}

void logger::warn(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    log_msg(fmt, "warn", ap);
    va_end(ap);
}

void logger::error(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    log_msg(fmt, "error", ap);
    va_end(ap);
}

void logger::fatal(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    log_msg(fmt, "fatal", ap);
    va_end(ap);
}

}

