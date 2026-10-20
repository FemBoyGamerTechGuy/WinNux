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

/* --- stub-hit dedupe -----------------------------------------------------
 * The installer flood buried the real errors: a stub hit from N call
 * sites printed N lines PER CALL, forever. Now each (dll, api, caller)
 * site logs ONCE and keeps a counter; the exit summary lists every site
 * with its total. Capped table (256 sites), mutex-guarded (trampolines
 * may hit from any thread). dll/api are interned static strings (export
 * and stub-table literals) so storing the pointers is stable. */
#define WN_STUB_SITES_MAX 256
typedef struct wn_stub_site {
    const char *dll;
    const char *api;
    char        where[96];
    uint64_t    hits;
} wn_stub_site;
static wn_stub_site g_sites[WN_STUB_SITES_MAX];
static int g_site_count;
static pthread_mutex_t g_site_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_exit_hooked;

static void wn_stub_site_summary(void)
{
    pthread_mutex_lock(&g_site_lock);
    if (g_site_count <= 0) {
        pthread_mutex_unlock(&g_site_lock);
        return;
    }
    wn_stub_site snap[WN_STUB_SITES_MAX];
    int n = g_site_count;
    uint64_t total = 0;
    for (int i = 0; i < n; i++) {
        snap[i] = g_sites[i];
        total += g_sites[i].hits;
    }
    g_site_count = 0;          /* idempotent if atexit ever runs twice */
    pthread_mutex_unlock(&g_site_lock);
    fprintf(stderr, "[winnux stub summary] %d distinct site(s), %llu hit(s)"
            " total\n", n, (unsigned long long)total);
    for (int i = 0; i < n; i++)
        fprintf(stderr, "[winnux stub summary] %llu x %s!%s from %s\n",
                (unsigned long long)snap[i].hits,
                snap[i].dll ? snap[i].dll : "?",
                snap[i].api ? snap[i].api : "?", snap[i].where);
}

/* Record a stub hit. Returns 1 when THIS call is the site's first (the
 * caller logs the incident), 0 afterwards (counter only). */
static int wn_stub_site_record(const char *dll, const char *api,
                               const char *where)
{
    pthread_mutex_lock(&g_site_lock);
    for (int i = 0; i < g_site_count; i++) {
        if (!strcmp(g_sites[i].where, where) &&
            g_sites[i].dll == dll && g_sites[i].api == api) {
            g_sites[i].hits++;
            pthread_mutex_unlock(&g_site_lock);
            return 0;
        }
    }
    if (g_site_count >= WN_STUB_SITES_MAX) {
        pthread_mutex_unlock(&g_site_lock);
        return 0;
    }
    wn_stub_site *s = &g_sites[g_site_count++];
    s->dll = dll;
    s->api = api;
    snprintf(s->where, sizeof s->where, "%s", where ? where : "?");
    s->hits = 1;
    if (!g_exit_hooked) {
        atexit(wn_stub_site_summary);
        g_exit_hooked = 1;
    }
    pthread_mutex_unlock(&g_site_lock);
    return 1;
}

/* stub.c trampoline counter hook (see the stub.c comment). */
void wn_stub_site_note(const char *dll, const char *api, const char *where)
{
    wn_stub_site_record(dll, api, where);
}

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
    wn_last_error_set(120 /* ERROR_CALL_NOT_IMPLEMENTED */);
    if (!wn_stub_site_record(dll, api, where))
        return;
    wn_log(WN_LOG_ERR, "STUB %s!%s called from %s -> returning error "
           "(GetLastError=120; further hits from this site are counted,"
           " see the stub summary at exit)", dll, api, where);
}
