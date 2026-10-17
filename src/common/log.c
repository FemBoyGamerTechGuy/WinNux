/* wn_log.c — logging implementation. */
#include "wn_log.h"
#include "wn_types.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static int g_level = WN_LOG_WARN;

/* Resolve a guest return address to module+rva for stub messages. */
const char *wn_module_describe_addr(const void *addr, char *buf, size_t cap);
uint32_t    wn_last_error_get(void);
void        wn_last_error_set(uint32_t e);

void wn_log_init(void)
{
    const char *s = getenv("WINNUX_LOG");
    if (s) {
        if (!strcmp(s, "error")) g_level = WN_LOG_ERR;
        else if (!strcmp(s, "warn"))  g_level = WN_LOG_WARN;
        else if (!strcmp(s, "info"))  g_level = WN_LOG_INFO;
        else if (!strcmp(s, "debug")) g_level = WN_LOG_DEBUG;
        else if (!strcmp(s, "trace")) g_level = WN_LOG_TRACE;
        else fprintf(stderr, "[winnux] WINNUX_LOG='%s' unknown, using warn\n", s);
    }
    if (getenv("WINNUX_TRACE") && !s)
        g_level = WN_LOG_TRACE;
}

int wn_log_level(void) { return g_level; }

void wn_log(int level, const char *fmt, ...)
{
    if (level > g_level)
        return;
    char ts[32];
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    struct tm tm;
    localtime_r(&now.tv_sec, &tm);
    strftime(ts, sizeof ts, "%H:%M:%S", &tm);
    long tid = syscall(SYS_gettid);
    flockfile(stderr);
    fprintf(stderr, "[winnux %s %ld] ", ts, tid);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    funlockfile(stderr);
}

void wn_stub_log(const char *dll, const char *api, const void *retaddr)
{
    char where[96] = "?";
    wn_module_describe_addr(retaddr, where, sizeof where);
    wn_log(WN_LOG_ERR, "STUB %s!%s called from %s -> returning error "
           "(GetLastError=120 ERROR_CALL_NOT_IMPLEMENTED)", dll, api, where);
    wn_last_error_set(120 /* ERROR_CALL_NOT_IMPLEMENTED */);
}
