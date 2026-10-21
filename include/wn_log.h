/* wn_log.h — logging: loud, honest, never silent.
 *
 * WINNUX_LOG=error|warn|info|debug|trace (default warn).
 * Unimplemented APIs must log via wn_stub_log() and return a sensible error.
 */
#ifndef WN_LOG_H
#define WN_LOG_H

enum wn_log_level {
    WN_LOG_ERR   = 0,
    WN_LOG_WARN  = 1,
    WN_LOG_INFO  = 2,
    WN_LOG_DEBUG = 3,
    WN_LOG_TRACE = 4,
};

/* Initialize from WINNUX_LOG / WINNUX_TRACE env vars. Safe to call twice. */
void wn_log_init(void);
/* One-line-per-site stub summary (atexit + crash paths) so killed/crashed
 * runs still print it — the default log is short, this is the tail. */
void wn_log_stub_summary(void);

/* Current maximum enabled level. */
int  wn_log_level(void);

/* Core logger: level-tagged, timestamped, thread-tagged, to stderr. */
void wn_log(int level, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

/* Stub report: logs dll!api as unimplemented, plus the guest call site
 * resolved to module+offset when possible. Sets last error 120. */
void wn_stub_log(const char *dll, const char *api, const void *retaddr);

/* Dedupe bookkeeping for stub hits: count a hit for (dll, api, caller
 * site) without logging (the site's first incident was already
 * printed). The exit summary lives in log.c. */
void wn_stub_site_note(const char *dll, const char *api, const char *where);

#define WN_LOGE(...) wn_log(WN_LOG_ERR,  __VA_ARGS__)
#define WN_LOGW(...) wn_log(WN_LOG_WARN, __VA_ARGS__)
#define WN_LOGI(...) wn_log(WN_LOG_INFO, __VA_ARGS__)
#define WN_LOGD(...) wn_log(WN_LOG_DEBUG,__VA_ARGS__)
#define WN_LOGT(...) wn_log(WN_LOG_TRACE,__VA_ARGS__)

#endif /* WN_LOG_H */
