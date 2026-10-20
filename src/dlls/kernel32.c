/* kernel32.c — builtin kernel32.dll: the console/file/thread/sync/memory core.
 *
 * Conventions: every export is ms_abi. Wide APIs convert to UTF-8 and call
 * the A path. Failures set TEB last-error honestly; missing sibling APIs
 * stay unimplemented and get loud stubs via the loader.
 */
#include "wn_dll.h"
#include "wn_process.h"
#include "wn_path.h"
#include "wn_files.h"
#include "wn_sync.h"
#include "wn_handle.h"
#include "wn_seh.h"
#include "wn_log.h"
#include "wn_util.h"
#include "wn_registry.h"
#include "wn_module.h"
#include "wn_wow64.h"

#include <execinfo.h>
#include <dlfcn.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <malloc.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <sys/statvfs.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Std handle values (documented global: stable pseudo handles). */
static wn_handle g_stdin_h, g_stdout_h, g_stderr_h;

void wn_files_std_init(void)
{
    wn_file *in = wn_xcalloc(1, sizeof *in);
    wn_file *out = wn_xcalloc(1, sizeof *out);
    wn_file *err = wn_xcalloc(1, sizeof *err);
    in->fd = 0;  in->std_fd = 0;  in->is_console = isatty(0);
    out->fd = 1; out->std_fd = 1; out->is_console = isatty(1);
    err->fd = 2; err->std_fd = 2; err->is_console = isatty(2);
    g_stdin_h  = wn_handle_alloc(WN_HTYPE_FILE, in);
    g_stdout_h = wn_handle_alloc(WN_HTYPE_FILE, out);
    g_stderr_h = wn_handle_alloc(WN_HTYPE_FILE, err);
    wn_handle_set_dtor(WN_HTYPE_FILE, NULL); /* fd ownership handled by close */
}

/* fd close on handle close: file dtor */
static void file_dtor(void *p)
{
    wn_file *f = p;
    if (f->fd >= 0 && f->std_fd < 0)
        close(f->fd);
}

/* Install dtor at first file API use (idempotent). */
static void ensure_file_dtor(void)
{
    static int done = 0;
    if (!done) {
        wn_handle_set_dtor(WN_HTYPE_FILE, file_dtor);
        done = 1;
    }
}

/* --- errors ---------------------------------------------------------------- */

static WN_API uint32_t k32_GetLastError(void)
{
    return wn_last_error_get();
}

static WN_API void k32_SetLastError(uint32_t e)
{
    wn_last_error_set(e);
}

/* --- console ------------------------------------------------------------------ */

static WN_API wn_handle k32_GetStdHandle(int32_t which)
{
    switch (which) {
    case -10: return g_stdin_h;
    case -11: return g_stdout_h;
    case -12: return g_stderr_h;
    default:
        wn_last_error_set(WN_ERR_INVALID_PARAMETER);
        return WN_INVALID_HANDLE_VALUE;
    }
}

static WN_API int32_t k32_SetStdHandle(int32_t which, wn_handle h)
{
    wn_log(WN_LOG_WARN, "kernel32: SetStdHandle(%d) not supported", which);
    (void)h;
    return 0;
}

static uint32_t g_console_in_mode = 0x7;
static uint32_t g_console_out_mode = 0x3;

static WN_API int32_t k32_GetConsoleMode(wn_handle h, uint32_t *mode)
{
    wn_object *o = wn_handle_get(h, WN_HTYPE_FILE);
    if (!o || ((wn_file *)o->ptr)->std_fd < 0) {
        wn_last_error_set(WN_ERR_INVALID_HANDLE);
        return 0;
    }
    wn_file *f = o->ptr;
    *mode = f->std_fd == 0 ? g_console_in_mode : g_console_out_mode;
    return 1;
}

static WN_API int32_t k32_SetConsoleMode(wn_handle h, uint32_t mode)
{
    wn_object *o = wn_handle_get(h, WN_HTYPE_FILE);
    if (!o || ((wn_file *)o->ptr)->std_fd < 0) {
        wn_last_error_set(WN_ERR_INVALID_HANDLE);
        return 0;
    }
    wn_file *f = o->ptr;
    if (f->std_fd == 0)
        g_console_in_mode = mode;
    else
        g_console_out_mode = mode;
    return 1;
}

static WN_API uint32_t k32_GetConsoleOutputCP(void) { return 65001; }
static WN_API uint32_t k32_GetConsoleCP(void) { return 65001; }
static WN_API int32_t k32_SetConsoleOutputCP(uint32_t cp)
{
    (void)cp;
    return 1;
}

/* Translate \n to \r\n for console writes. Returns bytes written via out. */
static int console_write(int fd, const char *buf, uint32_t n)
{
    wn_buf b;
    wn_buf_init(&b);
    uint32_t start = 0;
    for (uint32_t i = 0; i < n; i++) {
        if (buf[i] == '\n' && (i == 0 || buf[i - 1] != '\r')) {
            wn_buf_append(&b, buf + start, i - start);
            wn_buf_append(&b, "\r\n", 2);
            start = i + 1;
        }
    }
    if (start < n)
        wn_buf_append(&b, buf + start, n - start);
    const void *data = b.len ? (const void *)b.data : (const void *)buf;
    size_t len = b.len ? b.len : n;
    size_t off = 0;
    while (off < len) {
        ssize_t r = write(fd, (const char *)data + off, len - off);
        if (r <= 0)
            break;
        off += (size_t)r;
    }
    wn_buf_free(&b);
    return (int)off;
}

/* --- module / process ----------------------------------------------------------- */

static WN_API wn_handle k32_GetModuleHandleA(const char *name)
{
    if (!name || !*name)
        return (wn_handle)(uintptr_t)g_proc.exe->base;
    wn_module *m = wn_module_find(name);
    if (!m) {
        /* Try with .dll appended. */
        char buf[128];
        snprintf(buf, sizeof buf, "%s.dll", name);
        m = wn_module_find(buf);
    }
    if (!m) {
        wn_last_error_set(WN_ERR_MOD_NOT_FOUND);
        return NULL;
    }
    return (wn_handle)(uintptr_t)m->base;
}

static WN_API wn_handle k32_GetModuleHandleW(const uint16_t *name)
{
    if (!name) {
        wn_last_error_set(WN_ERR_INVALID_PARAMETER);
        return NULL;
    }
    size_t l = 0;
    while (name[l])
        l++;
    char *s = wn_utf16_to_utf8(name, l);
    if (!s) {
        wn_last_error_set(WN_ERR_INVALID_PARAMETER);
        return NULL;
    }
    wn_handle h = k32_GetModuleHandleA(s);
    free(s);
    return h;
}

/* GetModuleHandleEx: FROM_ADDRESS resolves a PC to its module handle. */
static WN_API int32_t k32_GetModuleHandleExW(uint32_t flags,
                                             const uint16_t *name,
                                             wn_handle *out)
{
    if (!out)
        return 0;
    if (flags & 0x4 /* GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS */) {
        wn_module *m = wn_module_from_addr(name /* the address */, NULL);
        if (!m) {
            wn_last_error_set(WN_ERR_MOD_NOT_FOUND);
            wn_wow64_out_handle(out, 0);
            return 0;
        }
        wn_wow64_out_handle(out, (uint64_t)(uintptr_t)m->base);
        return 1;
    }
    if (!name) {
        wn_wow64_out_handle(out, (uint64_t)(uintptr_t)g_proc.exe->base);
        return 1;
    }
    wn_handle r = k32_GetModuleHandleW(name);
    wn_wow64_out_handle(out, (uint64_t)(uintptr_t)r);
    return r != NULL;
}

static WN_API int32_t k32_GetModuleHandleExA(uint32_t flags, const char *name,
                                             wn_handle *out)
{
    if (!out)
        return 0;
    if (flags & 0x4) {
        wn_module *m = wn_module_from_addr((const void *)(uintptr_t)name, NULL);
        if (!m) {
            wn_last_error_set(WN_ERR_MOD_NOT_FOUND);
            wn_wow64_out_handle(out, 0);
            return 0;
        }
        wn_wow64_out_handle(out, (uint64_t)(uintptr_t)m->base);
        return 1;
    }
    if (!name) {
        wn_wow64_out_handle(out, (uint64_t)(uintptr_t)g_proc.exe->base);
        return 1;
    }
    wn_handle r = k32_GetModuleHandleA(name);
    wn_wow64_out_handle(out, (uint64_t)(uintptr_t)r);
    return r != NULL;
}

static WN_API uint32_t k32_GetModuleFileNameA(wn_handle mod, char *out, uint32_t cap)
{
    wn_module *m = mod ? wn_module_from_addr((void *)(uintptr_t)mod, NULL)
                       : g_proc.exe;
    if (mod && (void *)(uintptr_t)mod == (void *)(uintptr_t)g_proc.exe->base)
        m = g_proc.exe;
    if (!m) {
        wn_last_error_set(WN_ERR_INVALID_HANDLE);
        return 0;
    }
    char w[1100];
    wn_module_win_path(m, w, sizeof w);
    size_t n = strlen(w);
    if (cap < n + 1) {
        wn_last_error_set(WN_ERR_INSUFFICIENT_BUFFER);
        return (uint32_t)n + 1;   /* required size incl NUL */
    }
    memcpy(out, w, n + 1);
    return (uint32_t)n;
}

static WN_API uint32_t k32_GetModuleFileNameW(wn_handle mod, uint16_t *out, uint32_t cap)
{
    char a[1100];
    uint32_t r = k32_GetModuleFileNameA(mod, a, sizeof a);
    if (r == 0)
        return 0;
    uint16_t *w = wn_utf8_to_utf16(a, NULL);
    if (!w)
        return 0;
    size_t l = 0;
    while (w[l]) l++;
    if (cap < l + 1) {
        free(w);
        wn_last_error_set(WN_ERR_INSUFFICIENT_BUFFER);
        return (uint32_t)l + 1;   /* required size incl NUL */
    }
    memcpy(out, w, (l + 1) * 2);
    free(w);
    return (uint32_t)l;
}

static wn_handle load_module_by_name(const char *name, int flags)
{
    (void)flags;
    /* Apps can pass garbage (freed HMODULEs, uninitialized data); the
     * layer must never die on that - Windows would fault in the app, we
     * fail the call cleanly instead. */
    if (!name || wn_safe_strnlen(name, 260) >= 260) {
        wn_log(WN_LOG_WARN, "kernel32: LoadLibrary(bad name ptr %p) from "
               "guest %p -> ERROR_MOD_NOT_FOUND", (void *)name,
               __builtin_return_address(0));
        wn_last_error_set(WN_ERR_MOD_NOT_FOUND);
        return NULL;
    }
    /* The loader itself handles extension-less names (appends .dll),
     * full system32 paths, and case-insensitivity. No blind retry here:
     * a failed load must set ERROR_MOD_NOT_FOUND exactly once, quietly. */
    wn_module *m = wn_module_load_dll(name, NULL);
    if (!m) {
        wn_last_error_set(WN_ERR_MOD_NOT_FOUND);
        return NULL;
    }
    return (wn_handle)(uintptr_t)m->base;
}


/* --- FLS (Fiber Local Storage) ------------------------------------------------
 *
 * Implemented on the Tls index space (per-thread values already work). FLS
 * adds per-index destructors invoked on thread exit (MSDN contract); we run
 * them from wn_thread_exit. 0 = free, 1 = used-no-callback, else callback.
 */
#define WN_FLS_MAX 1088
static uint64_t g_fls_cb[WN_FLS_MAX];

static WN_API uint32_t k32_TlsAlloc(void);
static WN_API int32_t k32_TlsFree(uint32_t idx);
static WN_API void *k32_TlsGetValue(uint32_t idx);
static WN_API int32_t k32_TlsSetValue(uint32_t idx, void *v);

static WN_API uint32_t k32_FlsAlloc(wn_abiword callback)
{
    uint32_t idx = k32_TlsAlloc();
    if (idx == 0xFFFFFFFFu)
        return 0xFFFFFFFFu;
    if (idx >= WN_FLS_MAX) {
        wn_log(WN_LOG_ERR, "FlsAlloc: index %u beyond callback table", idx);
        return 0xFFFFFFFFu;
    }
    g_fls_cb[idx] = callback;
    return idx;
}

static WN_API int32_t k32_FlsFree(uint32_t idx)
{
    if (idx < WN_FLS_MAX)
        g_fls_cb[idx] = 0;
    return k32_TlsFree(idx);
}

static WN_API void *k32_FlsGetValue(uint32_t idx)
{
    return k32_TlsGetValue(idx);
}

static WN_API int32_t k32_FlsSetValue(uint32_t idx, void *v)
{
    return k32_TlsSetValue(idx, v);
}

/* Called from wn_thread_exit (thread.c) for every thread including main. */
void wn_fls_run_callbacks(void)
{
    for (uint32_t i = 0; i < WN_FLS_MAX && i < 1088u; i++) {
        if (!g_fls_cb[i])
            continue;
        void *v = k32_TlsGetValue(i);
        if (!v)
            continue;
        typedef WN_API void (*fls_cb)(void *);
        wn_log(WN_LOG_DEBUG, "FlsCallback[%u](%p)", i, v);
        ((fls_cb)(uintptr_t)g_fls_cb[i])(v);
    }
}


/* --- directory / env / locale batch (real) --------------------------------- */

static int copy_winstr(char *out, uint32_t cap, const char *src)
{
    size_t l = strlen(src);
    if (cap == 0)
        return (uint32_t)(l + 1);
    if (l + 1 > cap)
        return l + 1 > 0xFFFFFFFFu ? 0 : (uint32_t)(l + 1);
    memcpy(out, src, l + 1);
    return (uint32_t)l;
}

static WN_API uint32_t k32_GetSystemDirectoryA(char *buf, uint32_t cap)
{
    return copy_winstr(buf, cap, "C:\\windows\\system32");
}

static WN_API uint32_t k32_GetSystemDirectoryW(uint16_t *buf, uint32_t cap)
{
    uint16_t *w = wn_utf8_to_utf16("C:\\windows\\system32", NULL);
    if (!w)
        return 0;
    size_t l = 0;
    while (w[l])
        l++;
    uint32_t rv = 0;
    if (cap == 0) {
        rv = (uint32_t)(l + 1);
    } else if (l + 1 > cap) {
        rv = (uint32_t)(l + 1);
    } else {
        memcpy(buf, w, (l + 1) * 2);
        rv = (uint32_t)l;
    }
    free(w);
    return rv;
}

static WN_API uint32_t k32_GetWindowsDirectoryA(char *buf, uint32_t cap)
{
    return copy_winstr(buf, cap, "C:\\windows");
}

static WN_API uint32_t k32_GetWindowsDirectoryW(uint16_t *buf, uint32_t cap)
{
    uint16_t *w = wn_utf8_to_utf16("C:\\windows", NULL);
    if (!w)
        return 0;
    size_t l = 0;
    while (w[l])
        l++;
    uint32_t rv = 0;
    if (cap == 0 || l + 1 > cap)
        rv = (uint32_t)(l + 1);
    else {
        memcpy(buf, w, (l + 1) * 2);
        rv = (uint32_t)l;
    }
    free(w);
    return rv;
}

static WN_API uint64_t k32_GetEnvironmentStringsW(void)
{
    /* UTF-16 block: NAME=value\0 ... \0\0 (our knobs hidden). */
    wn_buf b;
    wn_buf_init(&b);
    for (char **e = environ; e && *e; e++) {
        if (wn_strcaseprefix(*e, "WINNUX_"))
            continue;
        size_t n = strlen(*e);
        uint16_t *w = wn_utf8_to_utf16_n(*e, n + 1);
        if (w) {
            wn_buf_append(&b, w, (n + 1) * 2);
            free(w);
        }
    }
    uint16_t z = 0;
    wn_buf_append(&b, &z, 2);
    wn_buf_append(&b, &z, 2);
    return (uint64_t)(uintptr_t)b.data;
}

extern char **environ;

static WN_API int32_t k32_FreeEnvironmentStringsW(uint16_t *block)
{
    free(block);
    return 1;
}

static WN_API int32_t k32_IsValidCodePage(uint32_t cp)
{
    switch (cp) {
    case 0: case 437: case 850: case 1252: case 65001: case 1200:
        return 1;
    default:
        return cp >= 1250 && cp <= 1258 ? 1 : 0;
    }
}

static WN_API void k32_InitializeSListHead(void *list)
{
    if (list)
        memset(list, 0, 16);
}

static WN_API int32_t k32_IsDBCSLeadByteEx(uint32_t cp, uint8_t b)
{
    (void)cp;
    (void)b;
    return 0;   /* all our codepages are single-byte-ish (1252/437) */
}

static WN_API uint32_t k32_GetCurrentDirectoryW(uint32_t cap, uint16_t *buf)
{
    char cwd[1100];
    wn_path_get_cwd_win(cwd, sizeof cwd);
    uint16_t *w = wn_utf8_to_utf16(cwd, NULL);
    if (!w)
        return 0;
    size_t l = 0;
    while (w[l])
        l++;
    uint32_t rv = 0;
    if (cap == 0 || l + 1 > cap)
        rv = (uint32_t)(l + 1);
    else {
        memcpy(buf, w, (l + 1) * 2);
        rv = (uint32_t)l;
    }
    free(w);
    return rv;
}

static WN_API int32_t k32_SetCurrentDirectoryW(const uint16_t *dir)
{
    if (!dir)
        return 0;
    size_t l = 0;
    while (dir[l])
        l++;
    char *a = wn_utf16_to_utf8(dir, l);
    if (!a)
        return 0;
    int32_t r = wn_path_set_cwd_win(a) == 0 ? 1 : 0;
    free(a);
    return r;
}

static WN_API void k32_OutputDebugStringW(const uint16_t *s)
{
    if (!s) {
        wn_log(WN_LOG_DEBUG, "OutputDebugString: (null)");
        return;
    }
    size_t l = 0;
    while (s[l])
        l++;
    char *a = wn_utf16_to_utf8(s, l);
    wn_log(WN_LOG_DEBUG, "OutputDebugString: %s", a ? a : "");
    free(a);
}

static WN_API int32_t k32_MulDiv(int32_t n, int32_t num, int32_t den)
{
    if (den == 0)
        return -1;
    return (int32_t)(((int64_t)n * num) / den);
}

static WN_API wn_handle k32_LoadLibraryA(const char *name)
{
    return load_module_by_name(name, 0);
}

static WN_API wn_handle k32_LoadLibraryW(const uint16_t *name)
{
    if (!name)
        return NULL;
    size_t l = 0;
    while (name[l])
        l++;
    char *a = wn_utf16_to_utf8(name, l);
    if (!a)
        return NULL;
    wn_handle h = load_module_by_name(a, 0);
    free(a);
    return h;
}

static WN_API wn_handle k32_LoadLibraryExW(const uint16_t *name, wn_handle f,
                                           uint32_t flags)
{
    if (!name)
        return NULL;
    size_t l = 0;
    while (name[l])
        l++;
    char *a = wn_utf16_to_utf8(name, l);
    if (!a)
        return NULL;
    (void)f;
    wn_handle h = load_module_by_name(a, (int)flags);
    free(a);
    return h;
}

static WN_API wn_handle k32_LoadLibraryExA(const char *name, wn_handle f, uint32_t flags)
{
    (void)f;
    return load_module_by_name(name, flags);
}

static WN_API int32_t k32_FreeLibrary(wn_handle mod)
{
    wn_module *m = wn_module_from_addr((void *)(uintptr_t)mod, NULL);
    if (!m) {
        wn_last_error_set(WN_ERR_INVALID_HANDLE);
        return 0;
    }
    wn_module_unref(m);
    return 1;
}

static WN_API void *k32_GetProcAddress(wn_handle mod, const char *name)
{
    if (!mod || !name) {
        wn_last_error_set(WN_ERR_INVALID_PARAMETER);
        return NULL;
    }
    wn_module *m = wn_module_from_addr((void *)(uintptr_t)mod, NULL);
    if (!m) {
        wn_last_error_set(WN_ERR_INVALID_HANDLE);
        return NULL;
    }
    char namebuf[160];
    const char *key = name;
    if ((uintptr_t)name & 0xFFFF0000ULL)
        key = name;
    else {
        snprintf(namebuf, sizeof namebuf, "#%u", (uint32_t)(uintptr_t)name);
        key = namebuf;
    }
    void *fn = ((uintptr_t)name & 0xFFFF0000ULL)
        ? wn_module_get_proc(m, name, 0, 0)
        : wn_module_get_proc_ordinal(m, (uint32_t)(uintptr_t)name);
    if (!fn) {
        wn_log(WN_LOG_DEBUG, "gp: %s!%s -> NULL", m->name, key);
        wn_last_error_set(WN_ERR_PROC_NOT_FOUND);
        return NULL;
    }
    wn_log(WN_LOG_DEBUG, "gp: %s!%s -> %p", m->name, key, fn);
#if defined(__x86_64__)
    if (g_wow64_active && m->kind == WN_MOD_BUILTIN) {
        /* 32-bit caller: the raw impl pointer is a 64-bit host address the
         * guest cannot call. Hand back the wow64 thunk stub. */
        return (void *)(uintptr_t)wn_wow64_thunk_for(fn, m->name, key);
    }
#endif
    return fn;
}

static WN_API int32_t k32_DisableThreadLibraryCalls(wn_handle mod)
{
    (void)mod;
    return 1;
}

/* --- process / thread -------------------------------------------------------------- */

static WN_API void k32_ExitProcess(uint32_t code)
{
    wn_process_exit((int)(int32_t)code);
}

static WN_API void k32_ExitThread(uint32_t code)
{
    wn_thread_exit(code);
}

static WN_API wn_handle k32_GetCurrentProcess(void)
{
    return WN_CURRENT_PROCESS;
}

/* Affinity: report a single CPU. 7-Zip sizes its compression thread pool
 * from this; the old stub returned 0 + ERROR_CALL_NOT_IMPLEMENTED and the
 * pool logic then dereferenced a NULL thread entry. */
static WN_API int32_t k32_GetProcessAffinityMask(wn_handle h,
                                                 wn_abiword *pmask,
                                                 wn_abiword *smask)
{
    (void)h;
    if (pmask)
        *pmask = 1;
    if (smask)
        *smask = 1;
    return 1;
}

static WN_API int32_t k32_IsWow64Process(wn_handle h, int32_t *wow64)
{
    (void)h;
    if (wow64)
        *wow64 = 0;   /* winnux32 IS a 32-bit process: not WOW64 */
    return 1;
}

static WN_API int32_t k32_GetProcessTimes(wn_handle h, void *creation,
                                          void *exit_, void *kernel,
                                          void *user)
{
    (void)h;
    uint64_t ft = g_proc.start_time_ft;
    if (creation)
        memcpy(creation, &ft, 8);
    if (exit_)
        memset(exit_, 0, 8);
    if (kernel)
        memset(kernel, 0, 8);
    if (user)
        memset(user, 0, 8);
    return 1;
}

static WN_API int32_t k32_GetSystemTimes(void *idle, void *kernel, void *user)
{
    uint64_t z = 0;
    if (idle) memcpy(idle, &z, 8);
    if (kernel) memcpy(kernel, &z, 8);
    if (user) memcpy(user, &z, 8);
    return 1;
}

static WN_API wn_handle k32_GetCurrentThread(void)
{
    return WN_CURRENT_THREAD;
}

static WN_API uint32_t k32_GetCurrentProcessId(void)
{
    return g_proc.pid;
}

static WN_API uint32_t k32_GetCurrentThreadId(void)
{
    return (uint32_t)wn_teb_current()->client_id_thread;
}

struct k32_thread_start {
    WN_API uint32_t (*fn)(void *);
    void *param;
};

static WN_API uint64_t thread_start_shim(uint64_t param)
{
    struct k32_thread_start *ts = (struct k32_thread_start *)(uintptr_t)param;
    uint32_t r = ts->fn(ts->param);
    free(ts);
    return r;
}

static WN_API wn_handle k32_CreateThread(void *sa, uint32_t stack_size,
                                         WN_API uint32_t (*fn)(void *),
                                         void *param, uint32_t flags,
                                         uint32_t *tid_out)
{
    (void)sa;
    if (tid_out)
        *tid_out = 0;
    if (!fn) {
        wn_last_error_set(WN_ERR_INVALID_PARAMETER);
        return NULL;
    }
    struct k32_thread_start *ts = wn_xmalloc(sizeof *ts);
    ts->fn = fn;
    ts->param = param;
    wn_thread *th;
    wn_handle h;
    uint64_t stack = stack_size ? stack_size : g_proc.exe->pe.stack_reserve;
    if (!wn_thread_create(stack, thread_start_shim, (uint64_t)(uintptr_t)ts,
                          (flags & 4) /* CREATE_SUSPENDED */, &th, &h))
        return NULL;
    if (tid_out)
        *tid_out = th->tid;
    return h;
}

static WN_API uint32_t k32_ResumeThread(wn_handle h)
{
    wn_object *o = wn_handle_get(h, WN_HTYPE_THREAD);
    if (!o)
        return 0xFFFFFFFF;
    return wn_thread_resume(o->ptr);
}

static WN_API uint32_t k32_SuspendThread(wn_handle h)
{
    wn_object *o = wn_handle_get(h, WN_HTYPE_THREAD);
    if (!o)
        return 0xFFFFFFFF;
    return wn_thread_suspend(o->ptr);
}

static WN_API int32_t k32_GetExitCodeThread(wn_handle h, uint32_t *code)
{
    wn_object *o = wn_handle_get(h, WN_HTYPE_THREAD);
    if (!o || !code)
        return 0;
    wn_thread *t = o->ptr;
    *code = t->exited ? t->exit_code : 259 /* STILL_ACTIVE */;
    return 1;
}

/* --- child processes ----------------------------------------------------------
 * CreateProcess: the child is a full WinNux self-relaunch (exe = a PE inside
 * the same prefix): fork + execv(/proc/self/exe, {run, exe, args...}). The
 * process object wraps the pid so WaitForSingleObject/GetExitCodeProcess
 * (used by every installer's [Run] step) work for real. */
typedef struct {
    pid_t pid;
    int    reaped;
    int    exit_code;
} wn_child_proc;

int wn_child_process_try(void *cp)
{
    wn_child_proc *c = cp;
    if (!c || c->pid < 0)
        return c && c->pid < 0 ? 0 : 0;
    if (c->reaped)
        return 1;
    int st = 0;
    pid_t r = waitpid(c->pid, &st, WNOHANG);
    if (r == c->pid) {
        c->reaped = 1;
        c->exit_code = WIFEXITED(st) ? WEXITSTATUS(st)
                    : WIFSIGNALED(st) ? 128 + WTERMSIG(st) : -1;
        return 1;
    }
    return 0;
}

/* Split a Win32 command line (quote-aware) into argv. */
static int split_cmdline(char *s, char *argv[], int max)
{
    int n = 0;
    while (s && *s && n < max - 1) {
        while (*s == ' ' || *s == '\t')
            s++;
        if (!*s)
            break;
        char *out = s, *cur = s;
        int quoted = 0;
        while (*s) {
            if (*s == '"') {
                quoted = !quoted;
                s++;
                continue;
            }
            if (!quoted && (*s == ' ' || *s == '\t'))
                break;
            /* collapse doubled quotes inside a quoted region */
            *cur++ = *s++;
        }
        (void)out;
        *cur = '\0';
        argv[n++] = out;
        if (*s)
            s++;
    }
    argv[n] = NULL;
    return n;
}

static int32_t create_process_common(const char *app_name, char *cmd_line,
                                      uint32_t creation, const char *cur_dir,
                                      const void *si, void *pi,
                                      int wide)
{
    (void)creation;
    if (!si || !pi) {
        wn_last_error_set(WN_ERR_INVALID_PARAMETER);
        return 0;
    }
    /* Resolve the image: lpApplicationName wins, else the first cmdline
     * token. */
    char exe_win[1024];
    char *tokens[128];
    int ntok = 0;
    if (cmd_line)
        ntok = split_cmdline(cmd_line, tokens, 128);
    const char *img = app_name;
    int img_tok = -1;
    if (!img) {
        if (ntok == 0) {
            wn_last_error_set(WN_ERR_FILE_NOT_FOUND);
            return 0;
        }
        img = tokens[0];
        img_tok = 0;
    }
    snprintf(exe_win, sizeof exe_win, "%s", img);

    /* Windows appends .exe when the name has no extension. */
    char host[1024];
    if (wn_path_resolve_ci(exe_win, host, sizeof host) != 0) {
        const char *dot = strrchr(exe_win, '.');
        if (!dot || strchr(dot, '\\') || strchr(dot, '/')) {
            size_t el = strlen(exe_win);
            if (el + 5 <= sizeof exe_win) {
                memcpy(exe_win + el, ".exe", 5);
                if (wn_path_resolve_ci(exe_win, host, sizeof host) != 0) {
                    wn_log(WN_LOG_WARN, "kernel32: CreateProcess '%s' not "
                           "found", exe_win);
                    wn_last_error_set(WN_ERR_FILE_NOT_FOUND);
                    return 0;
                }
            }
        } else {
            wn_log(WN_LOG_WARN, "kernel32: CreateProcess '%s' not found",
                   exe_win);
            wn_last_error_set(WN_ERR_FILE_NOT_FOUND);
            return 0;
        }
    }
    char self[512];
    /* Emulator/dev override: under qemu-user, /proc/self/exe resolves to the
     * EMULATOR, not this loader — child guest processes would exec it with
     * loader args. WINNUX_CHILD_CMD (space-separated) is exec'd instead,
     * with {run, exe, args...} appended after its tokens. run32.sh sets it
     * to 'qemu-i386 -L <sysroot> <winnux32>' so process trees work under
     * the qemu loop. Tokenized pre-fork: the child only execvs. */
    char wrapbuf[512];
    char *wrap_tok[16];
    int nwrap = 0;
    const char *wrap = getenv("WINNUX_CHILD_CMD");
    if (wrap && *wrap) {
        snprintf(wrapbuf, sizeof wrapbuf, "%s", wrap);
        for (char *t = strtok(wrapbuf, " \t"); t && nwrap < 15;
             t = strtok(NULL, " \t"))
            wrap_tok[nwrap++] = t;
    } else {
        ssize_t sl = readlink("/proc/self/exe", self, sizeof self - 1);
        if (sl <= 0) {
            wn_last_error_set(WN_ERR_GEN_FAILURE);
            return 0;
        }
        self[sl] = '\0';
    }

    char dir_host[1024];
    dir_host[0] = '\0';
    if (cur_dir) {
        if (wn_path_resolve_ci(cur_dir, dir_host, sizeof dir_host) != 0)
            dir_host[0] = '\0';
    }

    pid_t pid = fork();
    if (pid < 0) {
        wn_last_error_set(WN_ERR_GEN_FAILURE);
        return 0;
    }
    if (pid == 0) {
        /* child: chdir, then exec our own loader (or the emulator wrapper)
         * with the guest args */
        if (dir_host[0])
            chdir(dir_host);
        char *cargv[152];
        int ca = 0;
        for (int i = 0; i < nwrap; i++)
            cargv[ca++] = wrap_tok[i];
        if (!nwrap)
            cargv[ca++] = (char *)"winnux";
        cargv[ca++] = (char *)"run";
        cargv[ca++] = exe_win;
        for (int i = 0; i < ntok; i++) {
            if (img_tok == i)
                continue;   /* the image token is the exe itself */
            cargv[ca++] = tokens[i];
        }
        cargv[ca] = NULL;
        execv(nwrap ? wrap_tok[0] : self, cargv);
        _exit(127);
    }

    wn_child_proc *c = wn_xmalloc(sizeof *c);
    c->pid = pid;
    c->reaped = 0;
    c->exit_code = 0;
    wn_handle hp = wn_handle_alloc(WN_HTYPE_PROCESS, c);
    wn_child_proc *tp = wn_xmalloc(sizeof *tp);
    tp->pid = -1;
    tp->reaped = 1;
    tp->exit_code = 0;
    wn_handle ht = wn_handle_alloc(WN_HTYPE_PROCESS, tp);

    /* PROCESS_INFORMATION: caller-width layout (16 bytes for an i386
     * caller: hProcess@0, hThread@4, pid@8, tid@0xc - all dwords). */
    if (wn_wow64_guest32() || !wide) {
        uint8_t *p = pi;
        memset(p, 0, 16);
        *(uint32_t *)(p + 0) = (uint32_t)(uintptr_t)hp;
        *(uint32_t *)(p + 4) = (uint32_t)(uintptr_t)ht;
        *(uint32_t *)(p + 8) = (uint32_t)pid;
        *(uint32_t *)(p + 12) = (uint32_t)pid;
    } else {
        uint8_t *p = pi;
        memset(p, 0, 24);
        *(uint64_t *)(p + 0) = (uint64_t)(uintptr_t)hp;
        *(uint64_t *)(p + 8) = (uint64_t)(uintptr_t)ht;
        *(uint32_t *)(p + 16) = (uint32_t)pid;
        *(uint32_t *)(p + 20) = (uint32_t)pid;
    }
    wn_log(WN_LOG_INFO, "kernel32: CreateProcess('%s') pid %d", exe_win,
           (int)pid);
    return 1;
}

static WN_API int32_t k32_CreateProcessA(
    const char *app, char *cmd, void *pa, void *ta, uint32_t inherit,
    uint32_t creation, const char *env, const char *dir, const void *si,
    void *pi)
{
    (void)pa; (void)ta; (void)inherit; (void)env;
    return create_process_common(app, cmd, creation, dir, si, pi, 0);
}

static WN_API int32_t k32_CreateProcessW(
    const uint16_t *app, uint16_t *cmd, void *pa, void *ta, uint32_t inherit,
    uint32_t creation, const uint16_t *env, const uint16_t *dir,
    const void *si, void *pi)
{
    (void)pa; (void)ta; (void)inherit; (void)env;
    char *a = app ? wn_utf16_to_utf8(app, 1024) : NULL;
    char *c = cmd ? wn_utf16_to_utf8(cmd, 8192) : NULL;
    char *d = dir ? wn_utf16_to_utf8(dir, 1024) : NULL;
    int r = create_process_common(a, c, creation, d, si, pi, 1);
    free(a); free(c); free(d);
    return r;
}

static WN_API int32_t k32_GetExitCodeProcess(wn_handle h, uint32_t *code)
{
    wn_object *o = wn_handle_acquire(h, 0);
    if (!o || o->type != WN_HTYPE_PROCESS) {
        wn_last_error_set(WN_ERR_INVALID_HANDLE);
        return 0;
    }
    wn_child_proc *c = o->ptr;
    if (c->pid < 0) {
        if (code)
            *code = 0;
        wn_handle_release(o);
        return 1;
    }
    wn_child_process_try(c);
    if (code)
        *code = c->reaped ? (uint32_t)(int32_t)c->exit_code : 259;
    wn_handle_release(o);
    return 1;
}

static WN_API void k32_Sleep(uint32_t ms)
{
    struct timespec ts = { .tv_sec = ms / 1000,
                           .tv_nsec = (long)(ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

static WN_API uint32_t k32_SleepEx(uint32_t ms, uint32_t alertable)
{
    k32_Sleep(ms);
    (void)alertable;
    return 0;
}

static WN_API int32_t k32_TerminateProcess(wn_handle h, uint32_t code)
{
    if (h == WN_CURRENT_PROCESS)
        wn_process_exit((int)(int32_t)code);
    wn_log(WN_LOG_WARN, "kernel32: TerminateProcess(other) treated as exit");
    wn_process_exit((int)(int32_t)code);
}

static WN_API int32_t k32_SwitchToThread(void)
{
    return sched_yield() == 0;
}

/* --- time ------------------------------------------------------------------ */

static WN_API void k32_GetSystemTimeAsFileTime(wn_filetime *ft)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    uint64_t v = (uint64_t)ts.tv_sec * 10000000ULL + (uint64_t)ts.tv_nsec / 100
               + WN_FILETIME_UNIX_OFFSET;
    ft->lo = (uint32_t)v;
    ft->hi = (uint32_t)(v >> 32);
}

/* Local <-> UTC FILETIME: one hour offset keeps timestamps ordered; real
 * zone handling needs tzset(). CompareFileTime: -1/0/+1. */
static WN_API int32_t k32_FileTimeToLocalFileTime(const wn_filetime *in,
                                                  wn_filetime *out)
{
    if (!in || !out)
        return 0;
    uint64_t v = (uint64_t)in->lo | ((uint64_t)in->hi << 32);
    long tz = 0;
    tzset();
    tz = -timezone / 60;   /* minutes east (timezone is seconds west) */
    v += (uint64_t)(int64_t)tz * 600000000LL;
    out->lo = (uint32_t)v;
    out->hi = (uint32_t)(v >> 32);
    return 1;
}

static WN_API int32_t k32_LocalFileTimeToFileTime(const wn_filetime *in,
                                                  wn_filetime *out)
{
    if (!in || !out)
        return 0;
    uint64_t v = (uint64_t)in->lo | ((uint64_t)in->hi << 32);
    long tz = 0;
    tzset();
    tz = -timezone / 60;
    v -= (uint64_t)(int64_t)tz * 600000000LL;
    out->lo = (uint32_t)v;
    out->hi = (uint32_t)(v >> 32);
    return 1;
}

static WN_API int32_t k32_CompareFileTime(const wn_filetime *a,
                                          const wn_filetime *b)
{
    if (!a || !b)
        return 0;
    if (a->hi != b->hi)
        return a->hi < b->hi ? -1 : 1;
    if (a->lo != b->lo)
        return a->lo < b->lo ? -1 : 1;
    return 0;
}

static WN_API uint32_t k32_GetTickCount(void)
{
    return (uint32_t)(wn_monotonic_ns() / 1000000ULL);
}

static WN_API uint64_t k32_GetTickCount64(void)
{
    return wn_monotonic_ns() / 1000000ULL;
}

static WN_API int32_t k32_QueryPerformanceCounter(uint64_t *out)
{
    if (!out)
        return 0;
    *out = wn_monotonic_ns() / 100;   /* 10 MHz tick */
    return 1;
}

static WN_API int32_t k32_QueryPerformanceFrequency(uint64_t *out)
{
    if (!out)
        return 0;
    *out = 10000000ULL;
    return 1;
}

/* Fill SYSTEM_TIME (8 words). */
static WN_API void k32_GetSystemTime(uint16_t *st)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    gmtime_r(&ts.tv_sec, &tm);
    st[0] = (uint16_t)(tm.tm_year + 1900);
    st[1] = (uint16_t)(tm.tm_mon + 1);
    st[2] = (uint16_t)((tm.tm_wday + 6) % 7);  /* Windows: 0 = Sunday */
    st[3] = (uint16_t)tm.tm_mday;
    st[4] = (uint16_t)tm.tm_hour;
    st[5] = (uint16_t)tm.tm_min;
    st[6] = (uint16_t)tm.tm_sec;
    st[7] = (uint16_t)(ts.tv_nsec / 1000000);
}

/* --- memory ------------------------------------------------------------------ */

extern void *wn_virtual_alloc(void *hint, uint64_t size, uint32_t type, uint32_t prot);
extern int   wn_virtual_free(void *addr, uint64_t size, uint32_t type);
extern int   wn_virtual_protect(void *addr, uint64_t size, uint32_t newprot, uint32_t *old);
extern int   wn_virtual_query(void *addr, void *mbi);

static WN_API void *k32_VirtualAlloc(void *addr, wn_abiword size, uint32_t type,
                                     uint32_t prot)
{
    void *p = wn_virtual_alloc(addr, size, type, prot);
    if (!p)
        wn_last_error_set(WN_ERR_NOT_ENOUGH_MEMORY);
    return p;
}

static WN_API int32_t k32_VirtualFree(void *addr, wn_abiword size, uint32_t type)
{
    if (!wn_virtual_free(addr, size, type)) {
        wn_last_error_set(WN_ERR_INVALID_PARAMETER);
        return 0;
    }
    return 1;
}

static WN_API int32_t k32_VirtualProtect(void *addr, wn_abiword size, uint32_t prot,
                                         uint32_t *old)
{
    uint32_t o = 0;
    if (!wn_virtual_protect(addr, size, prot, &o)) {
        wn_last_error_set(WN_ERR_INVALID_PARAMETER);
        return 0;
    }
    if (old)
        *old = o;
    return 1;
}

static WN_API uint32_t k32_VirtualQuery(void *addr, void *mbi,
                                         uint32_t length)
{
    /* VirtualQuery(addr, mbi, dwLength) - THREE stack words. The wow64
     * thunk derives its cleanup from this arity; a mismatch corrupts the
     * 32-bit guest stack (LuaForWindows installer crash).
     * MEMORY_BASIC_INFORMATION: 48 bytes on x64, 28 on i386 (4-byte fields,
     * 7 of them). The GUEST's bitness picks the layout - detected from
     * dwLength when possible, and from the dispatch flag otherwise. */
    int guest32 = wn_wow64_guest32();
    if (length != 0 && length < (guest32 ? 28u : 48u))
        return 0;
    if (!guest32) {
        if (!wn_virtual_query(addr, mbi))
            return 0;
#if defined(__x86_64__)
        return 48;
#else
        return 28;
#endif
    }
    /* i386 caller: query into a host-layout buffer, translate down. */
    uint8_t host[48];
    if (!wn_virtual_query(addr, host))
        return 0;
    /* x64 MBI: base@0(8), alloc_base@8(8), alloc_prot@16(4), region_size
     * @24(8), state@32(4), protect@36(4), type@40(4) -> i386: 4-byte fields. */
    uint8_t *o = mbi;
    *(uint32_t *)(o + 0)  = (uint32_t)*(uint64_t *)(host + 0);
    *(uint32_t *)(o + 4)  = (uint32_t)*(uint64_t *)(host + 8);
    *(uint32_t *)(o + 8)  = *(uint32_t *)(host + 16);
    *(uint32_t *)(o + 12) = (uint32_t)*(uint64_t *)(host + 24);
    *(uint32_t *)(o + 16) = *(uint32_t *)(host + 32);
    *(uint32_t *)(o + 20) = *(uint32_t *)(host + 36);
    *(uint32_t *)(o + 24) = *(uint32_t *)(host + 40);
    return 28;
}

static WN_API wn_handle k32_GetProcessHeap(void)
{
    return g_proc.process_heap;
}

static WN_API void *k32_HeapAlloc(wn_handle heap, uint32_t flags, wn_abiword size)
{
    (void)heap;
    if (size > 0x7FFFFFFF) {
        wn_last_error_set(WN_ERR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    void *p;
    if (g_wow64_active) {
        /* 32-bit guests cannot see host addresses: the low arena heap. */
        p = wn_low_malloc((size_t)size);
        if (p && (flags & 8))
            memset(p, 0, (size_t)size);
    } else {
        p = (flags & 8) ? calloc(1, (size_t)size) : malloc((size_t)size);
    }
    if (!p)
        wn_last_error_set(WN_ERR_NOT_ENOUGH_MEMORY);
    return p;
}

static WN_API void *k32_HeapReAlloc(wn_handle heap, uint32_t flags, void *ptr,
                                    wn_abiword size)
{
    (void)heap;
    if (size > 0x7FFFFFFF) {
        wn_last_error_set(WN_ERR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    void *p;
    if (g_wow64_active) {
        p = wn_low_realloc(ptr, (size_t)size);
        if (p && (flags & 8) && ptr == NULL)
            memset(p, 0, (size_t)size);
    } else {
        p = realloc(ptr, (size_t)size);
        if (p && (flags & 8) && ptr == NULL)
            memset(p, 0, (size_t)size);
    }
    if (!p)
        wn_last_error_set(WN_ERR_NOT_ENOUGH_MEMORY);
    return p;
}

static WN_API int32_t k32_HeapFree(wn_handle heap, uint32_t flags, void *ptr)
{
    (void)heap;
    (void)flags;
    if (g_wow64_active)
        wn_low_free(ptr);
    else
        free(ptr);
    return 1;
}

static WN_API wn_handle k32_HeapCreate(uint32_t flags, wn_abiword init, wn_abiword max)
{
    (void)flags;
    (void)init;
    (void)max;
    return (wn_handle)(uintptr_t)0x00220000ULL;  /* opaque heap id */
}

static WN_API int32_t k32_HeapDestroy(wn_handle h)
{
    (void)h;
    return 1;
}

/* --- global atom table ---------------------------------------------------
 * Delphi/VCL and Inno-style installers tag window data with string atoms.
 * Returning 0 from GlobalAddAtomA read as "atom table full" and broke the
 * class registration path; keep a simple string table, atoms from 0xC000. */
#define WN_ATOMS 512
static struct {
    int    used;
    char   name[256];        /* canonical UTF-8 */
} g_atoms[WN_ATOMS];

static uint16_t atom_find_slot(const char *name)
{
    for (int i = 0; i < WN_ATOMS; i++)
        if (g_atoms[i].used && wn_strcaseeq(g_atoms[i].name, name))
            return (uint16_t)(0xC000 + i);
    return 0;
}

static WN_API uint16_t k32_GlobalAddAtomA(const char *name)
{
    if (!name || !name[0])
        return 0;
    uint16_t ex = atom_find_slot(name);
    if (ex)
        return ex;
    for (int i = 0; i < WN_ATOMS; i++) {
        if (!g_atoms[i].used) {
            g_atoms[i].used = 1;
            snprintf(g_atoms[i].name, sizeof g_atoms[i].name, "%s", name);
            return (uint16_t)(0xC000 + i);
        }
    }
    wn_log(WN_LOG_WARN, "kernel32: global atom table full");
    return 0;
}

static WN_API uint16_t k32_GlobalAddAtomW(const uint16_t *name)
{
    if (!name)
        return 0;
    char *a = wn_utf16_to_utf8(name, 256);
    if (!a)
        return 0;
    uint16_t r = k32_GlobalAddAtomA(a);
    free(a);
    return r;
}

static WN_API uint16_t k32_GlobalFindAtomA(const char *name)
{
    if (!name || !name[0])
        return 0;
    return atom_find_slot(name);
}

static WN_API uint16_t k32_GlobalFindAtomW(const uint16_t *name)
{
    if (!name)
        return 0;
    char *a = wn_utf16_to_utf8(name, 256);
    if (!a)
        return 0;
    uint16_t r = atom_find_slot(a);
    free(a);
    return r;
}

static WN_API int32_t k32_GlobalDeleteAtom(uint16_t atom)
{
    if (atom < 0xC000 || atom >= 0xC000 + WN_ATOMS)
        return 0;
    g_atoms[atom - 0xC000].used = 0;
    return 1;
}

static WN_API uint32_t k32_GetAtomNameA(uint16_t atom, char *buf, uint32_t n)
{
    if (!buf || n == 0 || atom < 0xC000 || atom >= 0xC000 + WN_ATOMS)
        return 0;
    const char *nm = g_atoms[atom - 0xC000].name;
    if (!g_atoms[atom - 0xC000].used) {
        if (n)
            buf[0] = 0;
        return 0;
    }
    snprintf(buf, n, "%s", nm);
    return (uint32_t)strlen(buf);
}

static WN_API uint32_t k32_GetAtomNameW(uint16_t atom, uint16_t *buf, uint32_t n)
{
    if (!buf || n == 0 || atom < 0xC000 || atom >= 0xC000 + WN_ATOMS)
        return 0;
    if (!g_atoms[atom - 0xC000].used) {
        buf[0] = 0;
        return 0;
    }
    uint16_t *w = wn_utf8_to_utf16_n(g_atoms[atom - 0xC000].name,
                                    sizeof g_atoms[0].name);
    if (!w) {
        buf[0] = 0;
        return 0;
    }
    uint32_t i = 0;
    for (; i + 1 < n && w[i]; i++)
        buf[i] = w[i];
    buf[i] = 0;
    free(w);
    return i;
}

/* --- Global/Local heap -----------------------------------------------------------
 * Faithful Win32 semantics:
 *  - GMEM_FIXED: the handle IS the pointer (Windows guarantee).
 *  - GMEM_MOVEABLE: an opaque handle from a registry table. GlobalLock maps
 *    handle->pointer; the HANDLE NEVER CHANGES across GlobalReAlloc — the
 *    block may move, the caller re-locks. A block with a live lock count is
 *    never moved (Windows fails such a GlobalReAlloc instead).
 * The old identity model (pointer==handle for everything) realloc'd blocks
 * under the old Delphi/BCB RTLs (Inno's engine), which hold raw pointers
 * into LOCKED blocks: moved memory corrupted their string/record heap —
 * the "Enum"-as-pointer strrchr crash under winnux32, and the 0x40a998
 * list-node write on the wow64 path, both trace to this. */
#define GH_HANDLE_BASE 0x7A000000u   /* opaque range, never dereferenced */

typedef struct {
    uint32_t handle;    /* 0 = free slot */
    void    *ptr;
    size_t   size;
    uint32_t lock;
} gh_ent;

static gh_ent g_gh[1024];
static pthread_mutex_t g_gh_mu = PTHREAD_MUTEX_INITIALIZER;

static gh_ent *gh_find_h(uint32_t h)
{
    if (h < GH_HANDLE_BASE)
        return NULL;
    uint32_t i = (h - GH_HANDLE_BASE) >> 4;
    if (i >= 1024 || g_gh[i].handle != h)
        return NULL;
    return &g_gh[i];
}

static gh_ent *gh_find_p(void *p)
{
    for (uint32_t i = 0; i < 1024; i++)
        if (g_gh[i].handle && g_gh[i].ptr == p)
            return &g_gh[i];
    return NULL;
}

static void *gh_mem(size_t size, int zero)
{
    void *p = g_wow64_active ? wn_low_malloc(size) : malloc(size);
    if (p && zero)
        memset(p, 0, size);
    return p;
}

static WN_API void *k32_GlobalAlloc(uint32_t flags, wn_abiword size)
{
    if (!(flags & 0x2 /* GMEM_MOVEABLE */)) {
        void *p = gh_mem((size_t)size, flags & 0x40 /* GMEM_ZEROINIT */);
        if (!p)
            wn_last_error_set(WN_ERR_NOT_ENOUGH_MEMORY);
        wn_log(WN_LOG_DEBUG, "gh: GlobalAlloc(FIXED fl=%x sz=%llx) -> %p",
               flags, (unsigned long long)size, p);
        return p;
    }
    pthread_mutex_lock(&g_gh_mu);
    gh_ent *e = NULL;
    for (uint32_t i = 0; i < 1024 && !e; i++)
        if (!g_gh[i].handle)
            e = &g_gh[i];
    if (!e) {
        pthread_mutex_unlock(&g_gh_mu);
        wn_last_error_set(WN_ERR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    e->ptr = gh_mem((size_t)size, flags & 0x40);
    e->size = (size_t)size;
    e->lock = 0;
    e->handle = GH_HANDLE_BASE + ((uint32_t)(e - g_gh) << 4);
    uint32_t h = e->handle;
    void *ret = e->ptr ? (void *)(uintptr_t)h : NULL;
    if (!e->ptr)
        e->handle = 0;
    pthread_mutex_unlock(&g_gh_mu);
    wn_log(WN_LOG_DEBUG, "gh: GlobalAlloc(MOVE fl=%x sz=%llx) -> h=%x ptr=%p",
           flags, (unsigned long long)size, h, e->ptr);
    if (!ret)
        wn_last_error_set(WN_ERR_NOT_ENOUGH_MEMORY);
    return ret;
}

static WN_API void *k32_GlobalLock(wn_handle h)
{
    pthread_mutex_lock(&g_gh_mu);
    gh_ent *e = gh_find_h((uint32_t)(uintptr_t)h);
    void *p = NULL;
    if (e) {
        e->lock++;
        p = e->ptr;
    } else {
        p = (void *)(uintptr_t)h;   /* GMEM_FIXED: identity */
    }
    pthread_mutex_unlock(&g_gh_mu);
    wn_log(WN_LOG_DEBUG, "gh: GlobalLock(%x) -> %p",
           (uint32_t)(uintptr_t)h, p);
    return p;
}

static WN_API int32_t k32_GlobalUnlock(wn_handle h)
{
    pthread_mutex_lock(&g_gh_mu);
    gh_ent *e = gh_find_h((uint32_t)(uintptr_t)h);
    int32_t r = 1;
    if (e) {
        if (e->lock)
            e->lock--;
        r = e->lock ? 1 : 0;   /* FALSE on the final unlock (Win32 semantics) */
    }
    pthread_mutex_unlock(&g_gh_mu);
    return r;
}

static WN_API uint64_t k32_GlobalSize(wn_handle h)
{
    pthread_mutex_lock(&g_gh_mu);
    gh_ent *e = gh_find_h((uint32_t)(uintptr_t)h);
    uint64_t r;
    if (e) {
        r = (uint64_t)e->size;
    } else if (g_wow64_active) {
        r = (uint64_t)wn_low_usable((void *)(uintptr_t)h);
    } else {
        r = (uint64_t)malloc_usable_size((void *)(uintptr_t)h);
    }
    pthread_mutex_unlock(&g_gh_mu);
    return r;
}

static WN_API wn_handle k32_GlobalFree(wn_handle h)
{
    pthread_mutex_lock(&g_gh_mu);
    gh_ent *e = gh_find_h((uint32_t)(uintptr_t)h);
    if (e) {
        if (g_wow64_active)
            wn_low_free(e->ptr);
        else
            free(e->ptr);
        e->handle = 0;
        e->ptr = NULL;
        e->size = 0;
        e->lock = 0;
        pthread_mutex_unlock(&g_gh_mu);
        return 0;
    }
    pthread_mutex_unlock(&g_gh_mu);
    /* Foreign-handle guard: opaque handle-table values (HRSRC etc.) and
     * garbage land here; Windows rejects them with ERROR_INVALID_HANDLE —
     * freeing them would eat recycled chunks (see LoadResource note). */
    if ((uint32_t)(uintptr_t)h < 0x08000000) {
        wn_log(WN_LOG_WARN, "GlobalFree: %x is not a heap handle — "
               "rejecting", (unsigned)(uintptr_t)h);
        wn_last_error_set(WN_ERR_INVALID_HANDLE);
        return h;   /* Windows: nonzero return on failure */
    }
    if (g_wow64_active)
        wn_low_free((void *)(uintptr_t)h);
    else
        free((void *)(uintptr_t)h);
    return 0;
}

static WN_API wn_handle k32_GlobalHandle(void *p)
{
    if (!p)
        return 0;
    pthread_mutex_lock(&g_gh_mu);
    gh_ent *e = gh_find_p(p);
    wn_handle h = e ? (wn_handle)(uintptr_t)e->handle
                    : (wn_handle)(uintptr_t)p;   /* GMEM_FIXED: identity */
    pthread_mutex_unlock(&g_gh_mu);
    return h;
}

static WN_API wn_handle k32_GlobalReAlloc(wn_handle h, wn_abiword size,
                                          uint32_t flags)
{
    /* NULL handle: a plain allocation (Windows semantics). */
    if (!h)
        return (wn_handle)(uintptr_t)k32_GlobalAlloc(flags, size);

    pthread_mutex_lock(&g_gh_mu);
    gh_ent *e = gh_find_h((uint32_t)(uintptr_t)h);
    if (!e) {
        /* GMEM_FIXED grow: the caller adopts the RETURNED pointer (the
         * old handle dies — same as Windows). */
        pthread_mutex_unlock(&g_gh_mu);
        if (size == 0)
            return h;
        if ((uint32_t)(uintptr_t)h < 0x08000000) {
            wn_log(WN_LOG_WARN, "GlobalReAlloc: %x is not a heap handle "
                   "— rejecting", (unsigned)(uintptr_t)h);
            wn_last_error_set(WN_ERR_INVALID_HANDLE);
            return 0;
        }
        void *p = (void *)(uintptr_t)h;
        size_t old = g_wow64_active ? wn_low_usable(p)
                                    : malloc_usable_size(p);
        void *np = g_wow64_active ? wn_low_realloc(p, (size_t)size)
                                  : realloc(p, (size_t)size);
        if (!np) {
            wn_last_error_set(WN_ERR_NOT_ENOUGH_MEMORY);
            return 0;
        }
        if ((flags & 0x40 /* GMEM_ZEROINIT */) && (size_t)size > old)
            memset((uint8_t *)np + old, 0, (size_t)size - old);
        return (wn_handle)(uintptr_t)np;
    }

    /* GMEM_MOVEABLE: the HANDLE never changes across the realloc. */
    if (size == 0) {
        pthread_mutex_unlock(&g_gh_mu);
        return h;   /* GMEM_MODIFY convert / GMEM_DISCARD probe: no-op */
    }
    if (e->lock) {
        uint32_t lc = e->lock;
        pthread_mutex_unlock(&g_gh_mu);
        wn_log(WN_LOG_WARN, "GlobalReAlloc: moveable handle %x still "
               "locked (lock=%u) — refusing to move the block",
               (unsigned)(uintptr_t)h, lc);
        wn_last_error_set(WN_ERR_NOT_ENOUGH_MEMORY);
        return 0;
    }
    size_t old = e->size;
    void *old_ptr_for_log = e->ptr;
    void *np = g_wow64_active ? wn_low_realloc(e->ptr, (size_t)size)
                              : realloc(e->ptr, (size_t)size);
    if (!np) {
        pthread_mutex_unlock(&g_gh_mu);
        wn_last_error_set(WN_ERR_NOT_ENOUGH_MEMORY);
        return 0;
    }
    e->ptr = np;
    e->size = (size_t)size;
    if ((flags & 0x40 /* GMEM_ZEROINIT */) && (size_t)size > old)
        memset((uint8_t *)np + old, 0, (size_t)size - old);
    pthread_mutex_unlock(&g_gh_mu);
    wn_log(WN_LOG_DEBUG, "gh: GlobalReAlloc(h=%x sz=%llx fl=%x) -> h=%x "
           "ptr=%p (was %p)", (uint32_t)(uintptr_t)h,
           (unsigned long long)size, flags, (uint32_t)(uintptr_t)h,
           np, old_ptr_for_log);
    return h;
}

static WN_API void *k32_LocalAlloc(uint32_t flags, wn_abiword size)
{
    return k32_GlobalAlloc(flags, size);
}

static WN_API wn_handle k32_LocalFree(wn_handle h)
{
    return k32_GlobalFree(h);
}

static WN_API wn_handle k32_LocalHandle(void *p)
{
    return k32_GlobalHandle(p);
}

static WN_API wn_handle k32_LocalReAlloc(wn_handle h, wn_abiword size,
                                        uint32_t flags)
{
    return k32_GlobalReAlloc(h, size, flags);
}

static WN_API void *k32_LocalLock(wn_handle h)
{
    return k32_GlobalLock(h);
}

static WN_API int32_t k32_LocalUnlock(wn_handle h)
{
    return k32_GlobalUnlock(h);
}

static WN_API uint64_t k32_LocalSize(wn_handle h)
{
    return k32_GlobalSize(h);
}

/* --- TLS ------------------------------------------------------------------------ */

/* Global TLS index bitmap (documented global): bit i set = index i allocated.
 * Static-TLS indices from the PE loader occupy 1..n already; TlsAlloc picks
 * from the upper range to stay out of their way. */
static uint64_t g_tls_bitmap[8];

static WN_API uint32_t k32_TlsAlloc(void)
{
    for (uint32_t i = 256; i < 512; i++) {
        if (!(g_tls_bitmap[i >> 6] & (1ULL << (i & 63)))) {
            g_tls_bitmap[i >> 6] |= 1ULL << (i & 63);
            return i;
        }
    }
    wn_last_error_set(WN_ERR_NO_MORE_ITEMS);
    return 0xFFFFFFFF;
}

static WN_API int32_t k32_TlsFree(uint32_t idx)
{
    if (idx >= 512 || !(g_tls_bitmap[idx >> 6] & (1ULL << (idx & 63)))) {
        wn_last_error_set(WN_ERR_INVALID_PARAMETER);
        return 0;
    }
    g_tls_bitmap[idx >> 6] &= ~(1ULL << (idx & 63));
    return 1;
}

static WN_API void *k32_TlsGetValue(uint32_t idx)
{
    wn_teb *teb = wn_teb_current();
    if (idx >= 512) {
        wn_last_error_set(WN_ERR_INVALID_PARAMETER);
        return NULL;
    }
    void *v = (void *)(uintptr_t)teb->tls_array[idx];
    if (!v)
        wn_last_error_set(WN_ERR_SUCCESS);
    return v;
}

static WN_API int32_t k32_TlsSetValue(uint32_t idx, void *v)
{
    wn_teb *teb = wn_teb_current();
    if (idx >= 512) {
        wn_last_error_set(WN_ERR_INVALID_PARAMETER);
        return 0;
    }
    teb->tls_array[idx] = (wn_abiptr)(uintptr_t)v;
    return 1;
}

/* --- files ----------------------------------------------------------------------- */

static WN_API wn_handle k32_CreateFileA(const char *name, uint32_t access,
                                        uint32_t share, void *sa,
                                        uint32_t disposition, uint32_t flags,
                                        void *tmpl)
{
    ensure_file_dtor();
    (void)sa;
    (void)flags;
    (void)tmpl;
    if (!name) {
        wn_last_error_set(WN_ERR_INVALID_PARAMETER);
        return WN_INVALID_HANDLE_VALUE;
    }
    wn_log(WN_LOG_DEBUG, "kernel32: CreateFileA('%s') disp=%u", name,
           disposition);
    wn_file *f = wn_xcalloc(1, sizeof *f);
    if (!wn_file_open(name, access, disposition, share, f)) {
        free(f);
        return WN_INVALID_HANDLE_VALUE;
    }
    return wn_handle_alloc(WN_HTYPE_FILE, f);
}

static WN_API wn_handle k32_CreateFileW(const uint16_t *name, uint32_t access,
                                        uint32_t share, void *sa,
                                        uint32_t disposition, uint32_t flags,
                                        void *tmpl)
{
    if (!name) {
        wn_last_error_set(WN_ERR_INVALID_PARAMETER);
        return WN_INVALID_HANDLE_VALUE;
    }
    char *a = wn_utf16_to_utf8(name, 4096);
    if (!a) {
        wn_last_error_set(WN_ERR_INVALID_NAME);
        return WN_INVALID_HANDLE_VALUE;
    }
    wn_handle h = k32_CreateFileA(a, access, share, sa, disposition, flags, tmpl);
    free(a);
    return h;
}

static WN_API int32_t k32_ReadFile(wn_handle h, void *buf, uint32_t n,
                                   uint32_t *done, void *overlapped)
{
    if (overlapped) {
        wn_last_error_set(WN_ERR_NOT_SUPPORTED);
        return 0;
    }
    wn_object *o = wn_handle_get(h, WN_HTYPE_FILE);
    if (!o)
        return 0;
    wn_file *f = o->ptr;
    if (f->std_fd == 0) {
        ssize_t r = read(0, buf, n);
        if (r < 0) {
            wn_last_error_set(WN_ERR_READ_FAULT);
            return 0;
        }
        if (done) *done = (uint32_t)r;
        return 1;
    }
    int r = wn_file_read(f, buf, n);
    if (r < 0)
        return 0;
    if (n >= 4096 || r == 0 || (uint32_t)r != n)
        wn_log(WN_LOG_DEBUG, "kernel32: ReadFile n=%u r=%u pos=%lld",
               n, (uint32_t)r,
               (long long)lseek(f->fd >= 0 ? f->fd : -1, 0, SEEK_CUR));
    if (done)
        *done = (uint32_t)r;
    return 1;
}

static WN_API int32_t k32_WriteFile(wn_handle h, const void *buf, uint32_t n,
                                    uint32_t *done, void *overlapped)
{
    if (overlapped) {
        wn_last_error_set(WN_ERR_NOT_SUPPORTED);
        return 0;
    }
    wn_object *o = wn_handle_get(h, WN_HTYPE_FILE);
    if (!o)
        return 0;
    wn_file *f = o->ptr;
    if (f->std_fd == 1 || f->std_fd == 2) {
        /* Console semantics: translate \n only for real consoles; a
         * redirected stream is a file and passes bytes through. */
        int w;
        if (f->is_console) {
            w = console_write(f->std_fd, buf, n);
        } else {
            w = wn_file_write(f, buf, n);
        }
        if (w < 0) {
            wn_last_error_set(WN_ERR_WRITE_FAULT);
            return 0;
        }
        if (done)
            *done = (uint32_t)w;
        return 1;
    }
    int r = wn_file_write(f, buf, n);
    if (r < 0)
        return 0;
    if (done)
        *done = (uint32_t)r;
    return 1;
}

static WN_API int32_t k32_WriteConsoleA(wn_handle h, const void *buf, uint32_t n,
                                        uint32_t *done, void *res)
{
    (void)res;
    wn_object *o = wn_handle_get(h, WN_HTYPE_FILE);
    if (!o)
        return 0;
    wn_file *f = o->ptr;
    int fd = f->std_fd >= 0 ? f->std_fd : f->fd;
    int w = console_write(fd, buf, n);
    if (done)
        *done = (uint32_t)(w > 0 ? w : 0);
    return w >= 0;
}

static WN_API int32_t k32_WriteConsoleW(wn_handle h, const uint16_t *w, uint32_t n,
                                        uint32_t *done, void *res)
{
    char *a = wn_utf16_to_utf8(w, n);
    if (!a) {
        wn_last_error_set(WN_ERR_INVALID_PARAMETER);
        return 0;
    }
    uint32_t d = 0;
    int32_t r = k32_WriteConsoleA(h, a, (uint32_t)strlen(a), &d, res);
    free(a);
    if (done)
        *done = d;
    return r;
}

static WN_API int32_t k32_ReadConsoleA(wn_handle h, void *buf, uint32_t n,
                                       uint32_t *done, void *res)
{
    (void)res;
    wn_object *o = wn_handle_get(h, WN_HTYPE_FILE);
    if (!o)
        return 0;
    wn_file *f = o->ptr;
    ssize_t r = read(f->std_fd == 0 ? 0 : f->fd, buf, n);
    if (r < 0)
        return 0;
    if (done)
        *done = (uint32_t)r;
    return 1;
}

static WN_API int32_t k32_CloseHandle(wn_handle h)
{
    uint64_t v = (uint64_t)(uintptr_t)h;
    if (v == 0 || v >= (1ULL << 63))  /* pseudo handles */
        return 0;
    return wn_handle_close(h);
}

static WN_API uint32_t k32_SetFilePointer(wn_handle h, int32_t dist, int32_t *hi,
                                          uint32_t method)
{
    wn_object *o = wn_handle_get(h, WN_HTYPE_FILE);
    if (!o)
        return 0xFFFFFFFF;
    wn_file *f = o->ptr;
    int64_t base = 0;
    switch (method) {
    case 0: base = 0; break;
    case 1: base = lseek(f->fd, 0, SEEK_CUR); break;
    case 2: base = lseek(f->fd, 0, SEEK_END); break;
    default:
        wn_last_error_set(WN_ERR_INVALID_PARAMETER);
        return 0xFFFFFFFF;
    }
    int64_t off = base + (int64_t)(((uint64_t)(uint32_t)dist) |
                 (hi ? ((uint64_t)(uint32_t)*hi << 32) : 0));
    /* sign-extend dist properly */
    if (!hi)
        off = base + dist;
    int64_t r = lseek(f->fd, off, SEEK_SET);
    if (r < 0) {
        wn_last_error_set(WN_ERR_INVALID_PARAMETER);
        return 0xFFFFFFFF;
    }
    if (hi)
        *hi = (int32_t)(r >> 32);
    return (uint32_t)r;
}

static WN_API int32_t k32_SetFilePointerEx(wn_handle h, int64_t dist, int64_t *out,
                                           uint32_t method)
{
    wn_object *o = wn_handle_get(h, WN_HTYPE_FILE);
    if (!o)
        return 0;
    wn_file *f = o->ptr;
    int whence = method == 0 ? SEEK_SET : method == 1 ? SEEK_CUR : SEEK_END;
    int64_t r = lseek(f->fd, dist, whence);
    if (r < 0) {
        wn_last_error_set(WN_ERR_INVALID_PARAMETER);
        return 0;
    }
    if (out)
        *out = r;
    return 1;
}

static WN_API uint32_t k32_GetFileSize(wn_handle h, uint32_t *hi)
{
    wn_object *o = wn_handle_get(h, WN_HTYPE_FILE);
    if (!o)
        return 0xFFFFFFFF;
    wn_file *f = o->ptr;
    int64_t cur = lseek(f->fd, 0, SEEK_CUR);
    int64_t end = lseek(f->fd, 0, SEEK_END);
    lseek(f->fd, cur, SEEK_SET);
    if (end < 0)
        return 0xFFFFFFFF;
    if (hi)
        *hi = (uint32_t)((uint64_t)end >> 32);
    return (uint32_t)(uint64_t)end;
}

static WN_API int32_t k32_GetFileSizeEx(wn_handle h, int64_t *out)
{
    uint32_t hi;
    uint32_t lo = k32_GetFileSize(h, &hi);
    if (lo == 0xFFFFFFFF)
        return 0;
    *out = (int64_t)(((uint64_t)hi << 32) | lo);
    return 1;
}

static WN_API int32_t k32_FlushFileBuffers(wn_handle h)
{
    wn_object *o = wn_handle_get(h, WN_HTYPE_FILE);
    if (!o)
        return 0;
    wn_file *f = o->ptr;
    if (f->std_fd >= 0) {
        fflush(f->std_fd == 1 ? stdout : stderr);
        return 1;
    }
    if (fsync(f->fd) != 0 && errno != EINVAL) {
        wn_last_error_set(WN_ERR_GEN_FAILURE);
        return 0;
    }
    return 1;
}

static WN_API int32_t k32_SetEndOfFile(wn_handle h)
{
    wn_object *o = wn_handle_get(h, WN_HTYPE_FILE);
    if (!o)
        return 0;
    wn_file *f = o->ptr;
    off_t cur = lseek(f->fd, 0, SEEK_CUR);
    if (ftruncate(f->fd, cur) != 0) {
        wn_last_error_set(WN_ERR_GEN_FAILURE);
        return 0;
    }
    return 1;
}

static WN_API uint32_t k32_GetFileType(wn_handle h)
{
    wn_object *o = wn_handle_get(h, WN_HTYPE_FILE);
    if (!o)
        return 0;
    wn_file *f = o->ptr;
    if (f->std_fd >= 0)
        return f->is_console ? 2 /* CHAR */ : 3 /* PIPE */;
    struct stat st;
    if (fstat(f->fd, &st) != 0)
        return 0;
    if (S_ISCHR(st.st_mode)) return 2;
    if (S_ISFIFO(st.st_mode)) return 3;
    return 1; /* DISK */
}

/* Debug-only forensics: WINNUX_KEEP_TEMP=1 makes guest deletes of files
 * under the temp tree no-ops (success is still reported) so crashed-run
 * artifacts — Inno's extracted engine, for disassembly — stay on disk.
 * Set by scripts/dev runs when dissecting installer behavior. */
static int keep_temp_hit(const char *host)
{
    if (!getenv("WINNUX_KEEP_TEMP"))
        return 0;
    return strstr(host, "/windows/temp/") != NULL || strstr(host, "\\Temp\\") != NULL;
}

static WN_API int32_t k32_DeleteFileA(const char *name)
{
    char host[1024];
    if (wn_path_resolve_ci(name, host, sizeof host) != 0) {
        wn_last_error_set(WN_ERR_FILE_NOT_FOUND);
        return 0;
    }
    if (keep_temp_hit(host)) {
        wn_log(WN_LOG_DEBUG, "kernel32: DeleteFileA('%s') KEPT "
               "(WINNUX_KEEP_TEMP)", name);
        return 1;
    }
    if (unlink(host) != 0) {
        wn_last_error_set(errno == ENOENT ? WN_ERR_FILE_NOT_FOUND
                                          : WN_ERR_ACCESS_DENIED);
        return 0;
    }
    return 1;
}

static WN_API int32_t k32_DeleteFileW(const uint16_t *name)
{
    char *a = wn_utf16_to_utf8(name, 4096);
    if (!a) {
        wn_last_error_set(WN_ERR_INVALID_NAME);
        return 0;
    }
    int32_t r = k32_DeleteFileA(a);
    free(a);
    return r;
}

static WN_API int32_t k32_MoveFileA(const char *from, const char *to)
{
    char hf[1024], ht[1024];
    if (wn_path_resolve_ci(from, hf, sizeof hf) != 0 ||
        wn_path_win_to_host(to, ht, sizeof ht) != 0) {
        wn_last_error_set(WN_ERR_FILE_NOT_FOUND);
        return 0;
    }
    if (rename(hf, ht) != 0) {
        wn_last_error_set(WN_ERR_ACCESS_DENIED);
        return 0;
    }
    return 1;
}

static WN_API int32_t k32_MoveFileExA(const char *from, const char *to,
                                      uint32_t flags)
{
    if (!to) {
        /* MOVEFILE_DELAY...: not supported; DELETE_ON_WRITE-through is
         * approximated by unlink (installers use it for restart-delete). */
        char hf[1024];
        if (wn_path_resolve_ci(from, hf, sizeof hf) != 0)
            return 0;
        return unlink(hf) == 0;
    }
    char hf[1024], ht[1024];
    if (wn_path_resolve_ci(from, hf, sizeof hf) != 0 ||
        wn_path_win_to_host(to, ht, sizeof ht) != 0) {
        wn_last_error_set(WN_ERR_FILE_NOT_FOUND);
        return 0;
    }
    if (!(flags & 0x1 /* MOVEFILE_REPLACE_EXISTING */))
        if (access(ht, F_OK) == 0) {
            wn_last_error_set(WN_ERR_ALREADY_EXISTS);
            return 0;
        }
    if (rename(hf, ht) != 0) {
        wn_last_error_set(WN_ERR_ACCESS_DENIED);
        return 0;
    }
    return 1;
}

static WN_API int32_t k32_MoveFileExW(const uint16_t *from, const uint16_t *to,
                                      uint32_t flags)
{
    char *f = from ? wn_utf16_to_utf8(from, 4096) : NULL;
    char *t = to ? wn_utf16_to_utf8(to, 4096) : NULL;
    int32_t r = k32_MoveFileExA(f, t, flags);
    free(f); free(t);
    return r;
}

static WN_API int32_t k32_CopyFileA(const char *from, const char *to,
                                    int32_t fail_exists)
{
    char hf[1024], ht[1024];
    if (wn_path_resolve_ci(from, hf, sizeof hf) != 0 ||
        wn_path_win_to_host(to, ht, sizeof ht) != 0) {
        wn_last_error_set(WN_ERR_FILE_NOT_FOUND);
        return 0;
    }
    if (fail_exists && access(ht, F_OK) == 0) {
        wn_last_error_set(WN_ERR_FILE_EXISTS);
        return 0;
    }
    int in = open(hf, O_RDONLY | O_CLOEXEC);
    if (in < 0) {
        wn_last_error_set(WN_ERR_FILE_NOT_FOUND);
        return 0;
    }
    int out = open(ht, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    if (out < 0) {
        close(in);
        wn_last_error_set(WN_ERR_ACCESS_DENIED);
        return 0;
    }
    char buf[65536];
    ssize_t r;
    while ((r = read(in, buf, sizeof buf)) > 0) {
        ssize_t off = 0;
        while (off < r) {
            ssize_t w = write(out, buf + off, (size_t)(r - off));
            if (w <= 0) {
                close(in);
                close(out);
                wn_last_error_set(WN_ERR_WRITE_FAULT);
                return 0;
            }
            off += w;
        }
    }
    close(in);
    close(out);
    return 1;
}

static WN_API int32_t k32_CreateDirectoryA(const char *name, void *sa)
{
    (void)sa;
    wn_log(WN_LOG_DEBUG, "mkdir A: \"%s\"", name ? name : "(null)");
    char host[1024];
    if (wn_path_resolve_ci(name, host, sizeof host) == 0) {
        wn_last_error_set(WN_ERR_ALREADY_EXISTS);
        return 0;
    }
    char fullhost[4200];
    if (wn_path_win_to_host(name, fullhost, sizeof fullhost) != 0) {
        wn_last_error_set(WN_ERR_INVALID_NAME);
        return 0;
    }
    size_t dl;
    const char *base = wn_path_basename(fullhost, &dl);
    char dirpart[4100];
    memcpy(dirpart, fullhost, dl);
    dirpart[dl] = '\0';
    char full[4200];
    snprintf(full, sizeof full, "%s/%s", dl ? dirpart : ".", base);
    if (mkdir(full, 0777) != 0) {
        wn_last_error_set(errno == EEXIST ? WN_ERR_ALREADY_EXISTS
                                          : WN_ERR_ACCESS_DENIED);
        return 0;
    }
    return 1;
}

static WN_API int32_t k32_RemoveDirectoryA(const char *name)
{
    char host[1024];
    if (wn_path_resolve_ci(name, host, sizeof host) != 0) {
        wn_last_error_set(WN_ERR_FILE_NOT_FOUND);
        return 0;
    }
    if (keep_temp_hit(host)) {
        wn_log(WN_LOG_DEBUG, "kernel32: RemoveDirectoryA('%s') KEPT "
               "(WINNUX_KEEP_TEMP)", name);
        return 1;
    }
    if (rmdir(host) != 0) {
        wn_last_error_set(WN_ERR_DIR_NOT_EMPTY);
        return 0;
    }
    return 1;
}

static WN_API uint32_t k32_GetFileAttributesA(const char *name)
{
    char host[1024];
    if (wn_path_resolve_ci(name, host, sizeof host) != 0) {
        wn_log(WN_LOG_DEBUG, "gfa A miss: \"%s\" -> %u", name ? name : "(null)",
               wn_last_error_get());
        wn_last_error_set(WN_ERR_FILE_NOT_FOUND);
        return 0xFFFFFFFF;
    }
    struct stat st;
    if (stat(host, &st) != 0) {
        wn_log(WN_LOG_DEBUG, " gfa A stat-fail \"%s\"", name ? name : "(null)");
        wn_last_error_set(WN_ERR_ACCESS_DENIED);
        return 0xFFFFFFFF;
    }
    uint32_t a = 0;
    if (S_ISDIR(st.st_mode)) a |= WN_FILE_ATTRIBUTE_DIRECTORY;
    if (access(host, W_OK) != 0 && errno == EACCES) a |= WN_FILE_ATTRIBUTE_READONLY;
    const char *bs = strrchr(host, '/');
    if (bs && bs[1] == '.') a |= WN_FILE_ATTRIBUTE_HIDDEN;
    if (!a) a = WN_FILE_ATTRIBUTE_NORMAL;
    return a;
}

static WN_API uint32_t k32_GetFileAttributesW(const uint16_t *name)
{
    char *a = wn_utf16_to_utf8(name, 4096);
    if (!a)
        return 0xFFFFFFFF;
    uint32_t r = k32_GetFileAttributesA(a);
    free(a);
    return r;
}

static WN_API int32_t k32_SetFileAttributesA(const char *name, uint32_t attrs)
{
    char host[1024];
    if (wn_path_resolve_ci(name, host, sizeof host) != 0)
        return 0;
    if (attrs & WN_FILE_ATTRIBUTE_READONLY)
        chmod(host, S_IRUSR | S_IRGRP | S_IROTH);
    else
        chmod(host, 0666);
    return 1;
}

static WN_API uint32_t k32_GetCurrentDirectoryA(uint32_t cap, char *buf)
{
    char cwd[1024];
    wn_path_get_cwd_win(cwd, sizeof cwd);
    size_t n = strlen(cwd);
    if (!buf || cap < n + 1) {
        wn_last_error_set(WN_ERR_INSUFFICIENT_BUFFER);
        return (uint32_t)n + 1;   /* required size incl NUL */
    }
    memcpy(buf, cwd, n + 1);
    return (uint32_t)n;
}

static WN_API int32_t k32_SetCurrentDirectoryA(const char *dir)
{
    if (wn_path_set_cwd_win(dir) != 0) {
        wn_last_error_set(WN_ERR_PATH_NOT_FOUND);
        return 0;
    }
    return 1;
}

/* GetFullPathName: caller-side path normalization (NO filesystem access on
 * Windows — but we resolve case-insensitively when possible so lookups
 * succeed). Unicode apps (7-Zip!) build every open path through this. */
static uint32_t full_path_name(const char *name, uint32_t cap, char *buf,
                               char **part)
{
    if (!name || !*name) {
        wn_last_error_set(WN_ERR_INVALID_PARAMETER);
        return 0;
    }
    char out[2048];
    if ((name[0] >= 'A' && name[0] <= 'Z' && name[1] == ':') ||
        (name[0] >= 'a' && name[0] <= 'z' && name[1] == ':') ||
        name[0] == '\\' || name[0] == '/') {
        snprintf(out, sizeof out, "%s", name);
    } else {
        char cwd[1024];
        wn_path_get_cwd_win(cwd, sizeof cwd);
        size_t cl = strlen(cwd);
        if (cl && cwd[cl - 1] != '\\')
            snprintf(out, sizeof out, "%s\\%s", cwd, name);
        else
            snprintf(out, sizeof out, "%s%s", cwd, name);
    }
    /* slashes -> backslashes */
    for (char *p = out; *p; p++)
        if (*p == '/')
            *p = '\\';
    /* strip .\ and resolve .\ ..\ lexically */
    char clean[2048];
    size_t oi = 0;
    const char *p = out;
    if (p[0] && p[1] == ':') {
        clean[oi++] = p[0];
        clean[oi++] = ':';
        p += 2;
        if (*p == '\\')
            p++;
        clean[oi++] = '\\';
    } else if (p[0] == '\\') {
        clean[oi++] = '\\';
        p++;
    }
    while (*p) {
        if (p[0] == '.' && (p[1] == '\\' || !p[1])) {
            p += p[1] ? 2 : 1;
            continue;
        }
        if (p[0] == '.' && p[1] == '.' && (p[2] == '\\' || !p[2])) {
            /* pop last component from clean */
            while (oi > 1 && clean[oi - 1] != '\\')
                oi--;
            if (oi > 1)
                oi--;          /* drop the backslash too */
            p += p[2] ? 3 : 2;
            continue;
        }
        while (*p && *p != '\\')
            clean[oi++] = *p++;
        if (*p == '\\') {
            if (oi && clean[oi - 1] != '\\')
                clean[oi++] = '\\';
            p++;
        }
    }
    if (oi && clean[oi - 1] == '\\' && oi > 3)
        oi--;      /* no trailing slash (keep X:\ root form) */
    clean[oi] = 0;

    /* The Windows contract: if the buffer is too small, return the needed
     * size INCLUDING the terminating null (success returns it WITHOUT).
     * Returning the no-null length here is indistinguishable from success
     * and left Inno Setup's temp-dir walk with an empty path. */
    size_t need = oi + 1;
    if (!buf || cap < need) {
        wn_log(WN_LOG_DEBUG, " gfpn TOO-SMALL need=%u cap=%u buf=%p",
               (unsigned)need, cap, buf);
        wn_last_error_set(WN_ERR_INSUFFICIENT_BUFFER);
        return (uint32_t)need;
    }
    memcpy(buf, clean, need);
    if (part) {
        char *last = strrchr(buf, '\\');
        char *val = last ? last + 1 : buf;
        /* lpFilePart is a POINTER out-param: write it with the CALLER's
         * pointer width. A 32-bit guest passes &lpFilePart adjacent to
         * its buffer (Inno: part == buf-4); the 8-byte host write smashes
         * the first 4 buffer bytes with the high zero dword, turning the
         * normalized path into an empty string. */
        if (wn_wow64_guest32())
            *(uint32_t *)(void *)part = (uint32_t)(uintptr_t)val;
        else
            *part = val;
    }
    return (uint32_t)oi;
}

static WN_API uint32_t k32_GetFullPathNameA(const char *name, uint32_t cap,
                                            char *buf, char **part)
{
    uint32_t r = full_path_name(name, cap, buf, part);
    wn_log(WN_LOG_DEBUG, " gfpn A name=%p cap=%u buf=%p part=%p -> "
           "hex=%02x%02x%02x%02x \"%s\" (r=%u)", name, cap, buf, part,
           buf ? (uint8_t)buf[0] : 0, buf ? (uint8_t)buf[1] : 0,
           buf ? (uint8_t)buf[2] : 0, buf ? (uint8_t)buf[3] : 0,
           buf ? buf : "", r);
    return r;
}

static WN_API uint32_t k32_GetFullPathNameW(const uint16_t *name, uint32_t cap,
                                            uint16_t *buf, uint16_t **part)
{
    if (!name) {
        wn_last_error_set(WN_ERR_INVALID_PARAMETER);
        return 0;
    }
    char *a = wn_utf16_to_utf8(name, 4096);
    if (!a) {
        wn_last_error_set(WN_ERR_INVALID_NAME);
        return 0;
    }
    char abuf[2048];
    uint32_t r = full_path_name(a, sizeof abuf, abuf, NULL);
    free(a);
    if (r == 0)
        return 0;
    uint16_t *w = wn_utf8_to_utf16(abuf, NULL);
    if (!w)
        return 0;
    size_t units = 0;
    while (w[units])
        units++;
    if (!buf || cap < units + 1) {
        free(w);
        wn_last_error_set(WN_ERR_INSUFFICIENT_BUFFER);
        return (uint32_t)units;
    }
    memcpy(buf, w, (units + 1) * 2);
    free(w);
    if (part) {
        uint16_t *last = buf;
        for (uint16_t *q = buf; *q; q++)
            if (*q == '\\')
                last = q + 1;
        /* Caller-width pointer store (see the A variant note). */
        if (wn_wow64_guest32())
            *(uint32_t *)(void *)part = (uint32_t)(uintptr_t)last;
        else
            *part = last;
    }
    return (uint32_t)units;
}

static WN_API uint32_t k32_GetTempPathA(uint32_t cap, char *buf)
{
    const char *t = "C:\\windows\\temp\\";
    size_t n = strlen(t);
    if (cap < n + 1) {
        wn_last_error_set(WN_ERR_INSUFFICIENT_BUFFER);
        return (uint32_t)n + 1;   /* required size incl NUL */
    }
    memcpy(buf, t, n + 1);
    return (uint32_t)n;
}

static WN_API uint32_t k32_GetLogicalDriveStringsA(uint32_t cap, char *buf)
{
    size_t n = 8;   /* two entries incl NULs + final NUL: "C:\\\0Z:\\\0\0" */
    const char full[] = "C:\\\0Z:\\\0\0";
    if (cap < n) {
        wn_last_error_set(WN_ERR_INSUFFICIENT_BUFFER);
        return (uint32_t)(n - 1);
    }
    memcpy(buf, full, n);
    return (uint32_t)(n - 1);
}

static WN_API uint32_t k32_GetDriveTypeA(const char *root)
{
    if (root && (root[0] == 'Z' || root[0] == 'z'))
        return 3; /* DRIVE_FIXED (bridge to /) */
    return 3;
}

static WN_API int32_t k32_GetDiskFreeSpaceExA(const char *path, uint64_t *avail,
                                              uint64_t *total, uint64_t *free_)
{
    char host[2100];
    if (!path || wn_path_win_to_host(path, host, sizeof host) != 0)
        snprintf(host, sizeof host, "%s/drive_c", g_proc.prefix);
    struct statvfs st;
    if (statvfs(host, &st) != 0) {
        wn_last_error_set(WN_ERR_ACCESS_DENIED);
        return 0;
    }
    if (avail) *avail = (uint64_t)st.f_bavail * st.f_frsize;
    if (total) *total = (uint64_t)st.f_blocks * st.f_frsize;
    if (free_) *free_ = (uint64_t)st.f_bfree * st.f_frsize;
    return 1;
}

static WN_API int32_t k32_GetVolumeInformationA(const char *root, char *name,
                                                uint32_t name_cap, uint32_t *serial,
                                                uint32_t *maxcomp, uint32_t *flags,
                                                char *fsname, uint32_t fs_cap)
{
    (void)root;
    if (name && name_cap) snprintf(name, name_cap, "WinNux");
    if (fsname && fs_cap) snprintf(fsname, fs_cap, "WNFS");
    if (serial) *serial = 0x574E4E58;
    if (maxcomp) *maxcomp = 255;
    if (flags) *flags = 0x00040000 /* FILE_CASE_PRESERVED... approx */;
    return 1;
}

/* --- FindFirstFile ---------------------------------------------------------------- */

typedef struct { wn_find f; } k32_find;

static void find_dtor(void *p)
{
    k32_find *k = p;
    wn_find_close(&k->f);
}

/* WIN32_FIND_DATAA x64 layout (320 bytes):
 * attrs@0, ftCreation@4, ftAccess@12, ftWrite@20 (FILETIME is 4-aligned),
 * sizeHigh@28, sizeLow@32, reserved0@36, reserved1@40,
 * cFileName@44[260], cAlternateFileName@304[14]. */
static int fill_find_data(k32_find *k, void *data)
{
    uint8_t *d = data;
    char name[256];
    uint32_t attrs;
    uint64_t size;
    if (!wn_find_next(&k->f, name, sizeof name, &attrs, &size))
        return 0;
    memset(d, 0, 320);
    *(uint32_t *)(d + 0) = attrs;
    *(uint32_t *)(d + 28) = (uint32_t)(size >> 32);
    *(uint32_t *)(d + 32) = (uint32_t)size;
    snprintf((char *)(d + 44), 260, "%s", name);
    return 1;
}

static WN_API wn_handle k32_FindFirstFileA(const char *pattern, void *data)
{
    if (!pattern || !data) {
        wn_last_error_set(WN_ERR_INVALID_PARAMETER);
        return WN_INVALID_HANDLE_VALUE;
    }
    k32_find *k = wn_xcalloc(1, sizeof *k);
    if (!wn_find_open(pattern, &k->f)) {
        free(k);
        wn_last_error_set(WN_ERR_FILE_NOT_FOUND);
        return WN_INVALID_HANDLE_VALUE;
    }
    if (!fill_find_data(k, data)) {
        wn_find_close(&k->f);
        free(k);
        wn_last_error_set(WN_ERR_NO_MORE_FILES);
        return WN_INVALID_HANDLE_VALUE;
    }
    wn_handle_set_dtor(WN_HTYPE_FIND, find_dtor);
    return wn_handle_alloc(WN_HTYPE_FIND, k);
}

static WN_API int32_t k32_FindNextFileA(wn_handle h, void *data)
{
    wn_object *o = wn_handle_get(h, WN_HTYPE_FIND);
    if (!o)
        return 0;
    if (!fill_find_data(o->ptr, data)) {
        wn_last_error_set(WN_ERR_NO_MORE_FILES);
        return 0;
    }
    return 1;
}

/* WIN32_FIND_DATAW layout: same header offsets as A, but cFileName@44 is
 * 260 UTF-16 units and cAlternateFileName@304 is 14 units (592 bytes total).
 * 7-Zip i386 and every unicode-aware 32-bit app walks directories via W. */
static int fill_find_data_w(k32_find *k, void *data)
{
    uint8_t *d = data;
    char name[256];
    uint32_t attrs;
    uint64_t size;
    if (!wn_find_next(&k->f, name, sizeof name, &attrs, &size))
        return 0;
    memset(d, 0, 592);
    *(uint32_t *)(d + 0) = attrs;
    *(uint32_t *)(d + 28) = (uint32_t)(size >> 32);
    *(uint32_t *)(d + 32) = (uint32_t)size;
    uint16_t *w = wn_utf8_to_utf16(name, NULL);
    if (w) {
        for (int i = 0; w[i] && i < 259; i++)
            *(uint16_t *)(d + 44 + 2 * i) = w[i];
        free(w);
    }
    return 1;
}

static WN_API wn_handle k32_FindFirstFileW(const uint16_t *pattern, void *data)
{
    if (!pattern || !data) {
        wn_last_error_set(WN_ERR_INVALID_PARAMETER);
        return WN_INVALID_HANDLE_VALUE;
    }
    char *a = wn_utf16_to_utf8(pattern, 4096);
    if (!a) {
        wn_last_error_set(WN_ERR_INVALID_PARAMETER);
        return WN_INVALID_HANDLE_VALUE;
    }
    k32_find *k = wn_xcalloc(1, sizeof *k);
    if (!wn_find_open(a, &k->f)) {
        free(a);
        free(k);
        wn_last_error_set(WN_ERR_FILE_NOT_FOUND);
        return WN_INVALID_HANDLE_VALUE;
    }
    free(a);
    if (!fill_find_data_w(k, data)) {
        wn_find_close(&k->f);
        free(k);
        wn_last_error_set(WN_ERR_NO_MORE_FILES);
        return WN_INVALID_HANDLE_VALUE;
    }
    wn_handle_set_dtor(WN_HTYPE_FIND, find_dtor);
    return wn_handle_alloc(WN_HTYPE_FIND, k);
}

static WN_API int32_t k32_FindNextFileW(wn_handle h, void *data)
{
    wn_object *o = wn_handle_get(h, WN_HTYPE_FIND);
    if (!o)
        return 0;
    if (!fill_find_data_w(o->ptr, data)) {
        wn_last_error_set(WN_ERR_NO_MORE_FILES);
        return 0;
    }
    return 1;
}

static WN_API int32_t k32_FindClose(wn_handle h)
{
    return wn_handle_close(h);
}

/* --- FormatMessage ---------------------------------------------------------- */
/* Subset that covers the error-display paths real apps take:
 * FROM_SYSTEM (table of common Win32 errors), FROM_STRING (verbatim format
 * copy — insert sequences are passed through when IGNORE_INSERTS is set,
 * which is the combination Inno Setup uses), and ALLOCATE_MEMORY. */

static const char *system_message_for(uint32_t id)
{
    switch (id) {
    case 0:    return "The operation completed successfully.";
    case 2:    return "The system cannot find the file specified.";
    case 3:    return "The system cannot find the path specified.";
    case 5:    return "Access is denied.";
    case 6:    return "The handle is invalid.";
    case 8:    return "Not enough memory resources are available to process this command.";
    case 14:   return "Not enough storage is available to complete this operation.";
    case 15:   return "The system cannot find the drive specified.";
    case 32:   return "The process cannot access the file because it is being used by another process.";
    case 87:   return "The parameter is incorrect.";
    case 112:  return "There is not enough space on the disk.";
    case 120:  return "This function is not supported on this system.";
    case 122:  return "The data area passed to a system call is too small.";
    case 123:  return "The filename, directory name, or volume label syntax is incorrect.";
    case 126:  return "The specified module could not be found.";
    case 127:  return "The specified procedure could not be found.";
    case 145:  return "The directory is not empty.";
    case 183:  return "Cannot create a file when that file already exists.";
    case 1814: return "The specified resource type cannot be found in the image file.";
    case 1816: return "Not enough quota is available to process this command.";
    default:   return NULL;
    }
}

static WN_API wn_abiword k32_FormatMessageA(uint32_t flags, const char *source,
                                            uint32_t msg_id, uint32_t lang,
                                            char *buf, wn_abiword size,
                                            const void *args)
{
    (void)lang;
    (void)args;   /* inserts unprocessed: callers here use IGNORE_INSERTS */
    const char *msg = NULL;
    if (flags & 0x400 /* FORMAT_MESSAGE_FROM_STRING */) {
        msg = source ? source : "";
    } else if (flags & 0x1000 /* FROM_SYSTEM */) {
        msg = system_message_for(msg_id);
        if (!msg) {
            wn_last_error_set(317 /* ERROR_MR_MID_NOT_FOUND */);
            return 0;
        }
    } else {
        wn_log(WN_LOG_WARN, "kernel32: FormatMessageA flags 0x%x unsupported",
               flags);
        wn_last_error_set(WN_ERR_CALL_NOT_IMPLEMENTED);
        return 0;
    }
    size_t need = strlen(msg) + 1;
    if (flags & 0x100 /* ALLOCATE_MEMORY */) {
        char *m = wn_xmalloc(need);
        memcpy(m, msg, need);
        *(char **)buf = m;      /* caller frees with LocalFree */
        return (wn_abiword)(need - 1);
    }
    if (!buf || (wn_abiword)size < need) {
        wn_last_error_set(WN_ERR_INSUFFICIENT_BUFFER);
        return 0;
    }
    memcpy(buf, msg, need);
    return (wn_abiword)(need - 1);
}

static WN_API wn_abiword k32_FormatMessageW(uint32_t flags, const uint16_t *source,
                                            uint32_t msg_id, uint32_t lang,
                                            uint16_t *buf, wn_abiword size,
                                            const void *args)
{
    (void)lang;
    (void)args;
    const char *msg = NULL;
    if (flags & 0x400) {
        char *a = source ? wn_utf16_to_utf8(source, 4096) : NULL;
        msg = a ? a : "";
    } else if (flags & 0x1000) {
        msg = system_message_for(msg_id);
        if (!msg) {
            wn_last_error_set(317);
            return 0;
        }
    } else {
        wn_log(WN_LOG_WARN, "kernel32: FormatMessageW flags 0x%x unsupported",
               flags);
        wn_last_error_set(WN_ERR_CALL_NOT_IMPLEMENTED);
        return 0;
    }
    uint16_t *w = wn_utf8_to_utf16(msg, NULL);
    if (flags & 0x400)
        free((void *)(uintptr_t)msg);
    if (!w)
        return 0;
    size_t units = 0;
    while (w[units])
        units++;
    size_t need = units + 1;
    if (flags & 0x100) {
        *(uint16_t **)buf = w;
        return units;
    }
    if (!buf || (wn_abiword)size < need) {
        free(w);
        wn_last_error_set(WN_ERR_INSUFFICIENT_BUFFER);
        return 0;
    }
    memcpy(buf, w, need * 2);
    free(w);
    return units;
}

static WN_API void k32_SetFileApisToOEM(void)
{
    /* ANSI/OEM codepage selection: we present a single UTF-8-flavored
     * ANSI codepage; nothing to switch. */
}

/* --- sync objects ------------------------------------------------------------------ */

static WN_API wn_handle k32_CreateEventA(void *sa, int32_t manual, int32_t initial,
                                         const char *name)
{
    (void)sa;
    if (name)
        wn_log(WN_LOG_DEBUG, "kernel32: named event '%s' (single namespace)", name);
    wn_event *e = wn_xcalloc(1, sizeof *e);
    wn_event_init(e, manual, initial);
    return wn_handle_alloc(WN_HTYPE_EVENT, e);
}

static WN_API wn_handle k32_CreateEventW(void *sa, int32_t manual, int32_t initial,
                                         const uint16_t *name)
{
    (void)name;
    return k32_CreateEventA(sa, manual, initial, NULL);
}

static WN_API int32_t k32_SetEvent(wn_handle h)
{
    wn_object *o = wn_handle_get(h, WN_HTYPE_EVENT);
    if (!o)
        return 0;
    wn_event_set(o->ptr);
    return 1;
}

static WN_API int32_t k32_ResetEvent(wn_handle h)
{
    wn_object *o = wn_handle_get(h, WN_HTYPE_EVENT);
    if (!o)
        return 0;
    wn_event_reset(o->ptr);
    return 1;
}

static WN_API wn_handle k32_CreateMutexA(void *sa, int32_t initial_owner,
                                         const char *name)
{
    (void)sa;
    (void)name;
    wn_mutex *m = wn_xcalloc(1, sizeof *m);
    wn_mutex_init(m);
    if (initial_owner) {
        wn_mutex_try(m);
    }
    return wn_handle_alloc(WN_HTYPE_MUTEX, m);
}

static WN_API wn_handle k32_CreateMutexW(void *sa, int32_t owner, const uint16_t *name)
{
    (void)name;
    return k32_CreateMutexA(sa, owner, NULL);
}

static WN_API int32_t k32_ReleaseMutex(wn_handle h)
{
    wn_object *o = wn_handle_get(h, WN_HTYPE_MUTEX);
    if (!o)
        return 0;
    if (!wn_mutex_release(o->ptr)) {
        wn_last_error_set(WN_ERR_NOT_OWNER);
        return 0;
    }
    return 1;
}

static WN_API wn_handle k32_CreateSemaphoreA(void *sa, int32_t initial,
                                             int32_t max, const char *name)
{
    (void)sa;
    (void)name;
    if (initial < 0 || max <= 0 || initial > max) {
        wn_last_error_set(WN_ERR_INVALID_PARAMETER);
        return NULL;
    }
    wn_semaphore *s = wn_xcalloc(1, sizeof *s);
    wn_sem_init(s, (uint32_t)initial, (uint32_t)max);
    return wn_handle_alloc(WN_HTYPE_SEMAPHORE, s);
}

static WN_API int32_t k32_ReleaseSemaphore(wn_handle h, int32_t count,
                                           int32_t *prev)
{
    wn_object *o = wn_handle_get(h, WN_HTYPE_SEMAPHORE);
    if (!o)
        return 0;
    uint32_t p = 0;
    if (!wn_sem_release(o->ptr, (uint32_t)count, &p)) {
        wn_last_error_set(WN_ERR_INVALID_PARAMETER);
        return 0;
    }
    if (prev)
        *prev = (int32_t)p;
    return 1;
}

static WN_API uint32_t k32_WaitForSingleObject(wn_handle h, uint32_t ms)
{
    return wn_wait_single(h, ms);
}

static WN_API uint32_t k32_WaitForSingleObjectEx(wn_handle h, uint32_t ms,
                                                 uint32_t alertable)
{
    (void)alertable;
    return wn_wait_single(h, ms);
}

static WN_API uint32_t k32_WaitForMultipleObjects(uint32_t count,
                                                  const void *hs_raw,
                                                  uint32_t wait_all, uint32_t ms)
{
    /* The handle ARRAY is DWORD-sized for 32-bit callers (QWORD for x64):
     * reading 64-bit entries from a 32-bit array handed the sync engine
     * garbage handles — the Inno parent never saw its child exit and
     * hung forever (found via the un-reaped zombie). */
    wn_handle hs[64];
    if (count > 64)
        count = 64;
    if (wn_wow64_guest32()) {
        const uint32_t *p = hs_raw;
        for (uint32_t i = 0; i < count; i++)
            hs[i] = (wn_handle)(uintptr_t)p[i];
    } else {
        const wn_handle *p = hs_raw;
        for (uint32_t i = 0; i < count; i++)
            hs[i] = (wn_handle)(uintptr_t)p[i];
    }
    return wn_wait_multiple(count, hs, (int)wait_all, ms);
}

static WN_API uint32_t k32_WaitForMultipleObjectsEx(uint32_t count,
                                                    const void *hs_raw,
                                                    uint32_t wait_all, uint32_t ms,
                                                    uint32_t alertable)
{
    (void)alertable;
    wn_handle hs[64];
    if (count > 64)
        count = 64;
    if (wn_wow64_guest32()) {
        const uint32_t *p = hs_raw;
        for (uint32_t i = 0; i < count; i++)
            hs[i] = (wn_handle)(uintptr_t)p[i];
    } else {
        const wn_handle *p = hs_raw;
        for (uint32_t i = 0; i < count; i++)
            hs[i] = (wn_handle)(uintptr_t)p[i];
    }
    return wn_wait_multiple(count, hs, (int)wait_all, ms);
}

static WN_API void k32_InitializeCriticalSection(wn_critsect *cs)
{
    if (g_wow64_active)
        wn_critsect32_init(cs, 0);
    else
        wn_critsect_init(cs, 0);
}

static WN_API int32_t k32_InitializeCriticalSectionAndSpinCount(wn_critsect *cs,
                                                                uint32_t spin)
{
    if (g_wow64_active)
        wn_critsect32_init(cs, spin);
    else
        wn_critsect_init(cs, spin);
    return 1;
}

static WN_API void k32_EnterCriticalSection(wn_critsect *cs)
{
    if (g_wow64_active)
        wn_critsect32_enter(cs);
    else
        wn_critsect_enter(cs);
}

static WN_API void k32_LeaveCriticalSection(wn_critsect *cs)
{
    if (g_wow64_active)
        wn_critsect32_leave(cs);
    else
        wn_critsect_leave(cs);
}

static WN_API int32_t k32_TryEnterCriticalSection(wn_critsect *cs)
{
    return g_wow64_active ? wn_critsect32_try(cs) : wn_critsect_try(cs);
}

static WN_API void k32_DeleteCriticalSection(wn_critsect *cs)
{
    if (g_wow64_active)
        wn_critsect32_delete(cs);
    else
        wn_critsect_delete(cs);
}

/* --- strings / codepages ------------------------------------------------------------ */

static WN_API uint32_t k32_GetACP(void) { return 1252; }
static WN_API uint32_t k32_GetOEMCP(void) { return 437; }

static WN_API int32_t k32_GetCPInfo(uint32_t cp, void *info)
{
    /* CPINFO: MaxCharSize (UINT), LeadByte[12] (BYTE). */
    uint8_t *p = info;
    memset(p, 0, 16);
    *(uint32_t *)p = 1;
    if (cp == 0 || cp == 1 || cp == 1252 || cp == 437 || cp == 65001)
        return 1;
    wn_last_error_set(WN_ERR_INVALID_PARAMETER);
    return 0;
}

static WN_API int32_t k32_IsDBCSLeadByte(uint8_t c)
{
    (void)c;
    return 0;
}

static WN_API int32_t k32_lstrlenA(const char *s)
{
    return s ? (int32_t)strlen(s) : 0;
}

static WN_API int32_t k32_lstrlenW(const uint16_t *s)
{
    if (!s)
        return 0;
    int32_t n = 0;
    while (s[n])
        n++;
    return n;
}

static WN_API int32_t k32_lstrcmpA(const char *a, const char *b)
{
    int r = strcmp(a ? a : "", b ? b : "");
    return (r > 0) - (r < 0);
}

/* CompareStringA(Locale, dwCmpFlags, s1, cch1, s2, cch2): CSTR_EQUAL 2,
 * CSTR_LESS_THAN 1, CSTR_GREATER_THAN 3. Inno compares paths/versions. */
static WN_API int32_t k32_CompareStringA(uint32_t locale, uint32_t flags,
                                         const char *s1, int32_t n1,
                                         const char *s2, int32_t n2)
{
    (void)locale;
    if (n1 < 0)
        n1 = s1 ? (int32_t)strlen(s1) : 0;
    if (n2 < 0)
        n2 = s2 ? (int32_t)strlen(s2) : 0;
    size_t n = (size_t)(n1 < n2 ? n1 : n2);
    for (size_t i = 0; i < n; i++) {
        int ca = (unsigned char)s1[i], cb = (unsigned char)s2[i];
        if (flags & 0x1 /* NORM_IGNORECASE */) {
            ca = tolower(ca);
            cb = tolower(cb);
        }
        if (ca != cb)
            return ca < cb ? 1 : 3;
    }
    if (n1 == n2)
        return 2;
    return n1 < n2 ? 1 : 3;
}

static WN_API int32_t k32_CompareStringW(uint32_t locale, uint32_t flags,
                                         const uint16_t *s1, int32_t n1,
                                         const uint16_t *s2, int32_t n2)
{
    (void)locale;
    if (n1 < 0) {
        n1 = 0;
        if (s1)
            while (s1[n1])
                n1++;
    }
    if (n2 < 0) {
        n2 = 0;
        if (s2)
            while (s2[n2])
                n2++;
    }
    size_t n = (size_t)(n1 < n2 ? n1 : n2);
    for (size_t i = 0; i < n; i++) {
        int ca = s1[i], cb = s2[i];
        if (flags & 0x1) {
            ca = tolower(ca);
            cb = tolower(cb);
        }
        if (ca != cb)
            return ca < cb ? 1 : 3;
    }
    if (n1 == n2)
        return 2;
    return n1 < n2 ? 1 : 3;
}

/* OpenProcess: the child-wait surface needs a usable pseudo handle. */
static WN_API wn_handle k32_OpenProcess(uint32_t access, int32_t inherit,
                                        uint32_t pid)
{
    (void)access; (void)inherit;
    wn_child_proc *c = wn_xmalloc(sizeof *c);
    c->pid = (pid_t)pid;
    c->reaped = 0;
    c->exit_code = 0;
    return wn_handle_alloc(WN_HTYPE_PROCESS, c);
}

static WN_API int32_t k32_lstrcmpiA(const char *a, const char *b)
{
    for (const char *p = a ? a : "", *q = b ? b : ""; ; p++, q++) {
        int d = tolower((unsigned char)*p) - tolower((unsigned char)*q);
        if (d || !*p)
            return (d > 0) - (d < 0);
    }
}

/* --- locale / Unicode (real implementations over generated BMP tables) ------ */

#include "wn_unicode.h"

static WN_API int32_t k32_lstrcmpW(const uint16_t *a, const uint16_t *b)
{
    a = a ? a : (const uint16_t *)L""; b = b ? b : (const uint16_t *)L"";
    while (*a && *a == *b) { a++; b++; }
    return (int32_t)*a - (int32_t)*b;
}

static WN_API int32_t k32_lstrcmpiW(const uint16_t *a, const uint16_t *b)
{
    a = a ? a : (const uint16_t *)L""; b = b ? b : (const uint16_t *)L"";
    for (;;) {
        uint32_t ca = wn_uni_to_lower(*a), cb = wn_uni_to_lower(*b);
        if (ca != cb || !*a)
            return (int32_t)ca - (int32_t)cb;
        a++; b++;
    }
}

/* GetStringTypeW: per-character Windows classes. info[] gets one WORD per
 * character (not flags-ORed together - see MSDN: "array of 16-bit values").
 *
 * ABI FACT (verified against mingw-w64's winnls.h and real kernel32.dll):
 * the PLAIN GetStringTypeW has NO Locale parameter - only the A and Ex
 * variants are locale-first (the W one works on code points, so the SDK
 * ships a 4-parameter prototype). A 5-parameter implementation here
 * shifted every argument right by one slot: info_type received the lpSrcStr
 * POINTER, count received the lpCharType pointer, and callers read untouched
 * buffers (t15: every ctype check failed). Locale-first callers must use
 * GetStringTypeExW below - that is what the SDK's Ex names are for. */
static WN_API int32_t k32_GetStringTypeW(uint32_t info_type,
                                         const uint16_t *src, int32_t count,
                                         uint16_t *info)
{
    if (!src || !info || count < -1)
        return 0;
    size_t n = count < 0 ? (size_t)k32_lstrlenW(src) : (size_t)count;
    for (size_t i = 0; i < n; i++) {
        uint32_t cp = src[i];
        switch (info_type) {
        case 1 /*CT_CTYPE1*/:
            info[i] = (uint16_t)wn_uni_ctype1(cp);
            break;
        case 2 /*CT_CTYPE2*/:
            info[i] = (uint16_t)wn_uni_ctype2(cp);
            break;
        case 3 /*CT_CTYPE3*/:
            info[i] = (uint16_t)wn_uni_ctype3(cp);
            break;
        default:
            wn_log(WN_LOG_WARN, "kernel32: GetStringTypeW type %u unsupported",
                   info_type);
            wn_last_error_set(WN_ERR_INVALID_PARAMETER);
            return 0;
        }
    }
    return 1;
}

/* GetStringTypeExW/A: the locale-first, SDK-recommended spellings
 * (Locale, dwInfoType, lpSrcStr, cchSrc, lpCharType). W ignores Locale
 * (code points); A needs it only for the code page, which we do not use. */
static WN_API int32_t k32_GetStringTypeExW(uint32_t locale,
                                           uint32_t info_type,
                                           const uint16_t *src, int32_t count,
                                           uint16_t *info)
{
    (void)locale;
    return k32_GetStringTypeW(info_type, src, count, info);
}

static WN_API int32_t k32_GetStringTypeA(uint32_t locale, uint32_t info_type,
                                         const char *src, int32_t count,
                                         uint16_t *info)
{
    (void)locale;
    if (!src || !info || count < -1)
        return 0;
    size_t n = count < 0 ? strlen(src) : (size_t)count;
    for (size_t i = 0; i < n; i++) {
        uint32_t cp = (unsigned char)src[i];
        switch (info_type) {
        case 1: info[i] = (uint16_t)wn_uni_ctype1(cp); break;
        case 2: info[i] = (uint16_t)wn_uni_ctype2(cp); break;
        case 3: info[i] = (uint16_t)wn_uni_ctype3(cp); break;
        default:
            wn_last_error_set(WN_ERR_INVALID_PARAMETER);
            return 0;
        }
    }
    return 1;
}

#define LCMAP_LOWERCASE          0x00000100
#define LCMAP_UPPERCASE          0x00000200
#define LCMAP_SORTKEY            0x00000400
#define LCMAP_BYTEREV            0x00000800
#define LCMAP_HIRAGANA           0x00100000
#define LCMAP_KATAKANA           0x00200000
#define LCMAP_HALFWIDTH          0x00400000
#define LCMAP_FULLWIDTH          0x00800000

/* LCMapStringW: case mapping + Win32-style sort keys.
 * Sortkey layout (approximation of WinNls, deterministic):
 *   primary weights (2 bytes BE, case-folded) | 0x01
 *   case weights (0x12 upper / 0x22 lower)     | 0x01 0x00
 * gives correct case-insensitive ordering and stable case ordering. */
static size_t lc_map_case(const uint16_t *src, size_t n, uint16_t *dst,
                          size_t cap, int upper)
{
    for (size_t i = 0; i < n; i++) {
        uint32_t m = upper ? wn_uni_to_upper(src[i]) : wn_uni_to_lower(src[i]);
        if (dst) {
            if (i >= cap)
                return 0;
            dst[i] = (uint16_t)m;
        }
    }
    return n;
}

static size_t lc_sortkey(const uint16_t *src, size_t n, char *dst, size_t cap)
{
    size_t need = 1;   /* trailing 0x01 0x00 handled below */
    for (size_t i = 0; i < n; i++) {
        uint32_t p = wn_uni_to_lower(src[i]);
        uint32_t w = p < 0x100 ? 0x100 + p : p;   /* weights start above 0xFF */
        need += 2;
        if (!dst)
            continue;
        if (need + 2 > cap)
            return 0;                       /* too small */
        size_t o = i * 2;
        dst[o] = (char)(w >> 8);
        dst[o + 1] = (char)(w & 0xFF);
    }
    if (!dst)
        return need + n + 2;
    if (need + n + 2 > cap)
        return 0;
    size_t o = n * 2;
    dst[o++] = 0x01;
    for (size_t i = 0; i < n; i++) {
        uint32_t c1 = wn_uni_ctype1(src[i]);
        dst[o++] = (c1 & 0x0001) /*C1_UPPER*/ ? 0x12 : 0x22;
    }
    dst[o++] = 0x01;
    dst[o++] = 0x00;
    return o;
}

static WN_API int32_t k32_LCMapStringW(uint32_t locale, uint32_t flags,
                                       const uint16_t *src, int32_t srclen,
                                       uint16_t *dst, int32_t dstlen)
{
    (void)locale;    /* single-locale system; LOCALE_INVARIANT et al. accepted */
    if (!src || srclen < -1)
        return 0;
    size_t n = srclen < 0 ? (size_t)k32_lstrlenW(src) : (size_t)srclen;
    if (n == 0) {
        if (dst && dstlen > 0)
            dst[0] = 0;
        return dst || dstlen ? 1 : 0;
    }
    if (flags & LCMAP_SORTKEY) {
        /* MSDN: with LCMAP_SORTKEY, cchDest is the buffer size in BYTES. */
        size_t k = lc_sortkey(src, n, dst ? (char *)dst : NULL,
                              dst ? (size_t)dstlen : 0);
        if (!k) {
            wn_last_error_set(WN_ERR_INSUFFICIENT_BUFFER);
            return 0;
        }
        return (int32_t)k;
    }
    if (flags & (LCMAP_HIRAGANA | LCMAP_KATAKANA | LCMAP_HALFWIDTH |
                 LCMAP_FULLWIDTH)) {
        wn_log(WN_LOG_WARN, "kernel32: LCMapStringW kana/width mapping "
               "flags 0x%x not supported (identity)", flags);
    }
    int upper = (flags & LCMAP_UPPERCASE) != 0;
    if ((flags & (LCMAP_LOWERCASE | LCMAP_UPPERCASE)) == 0) {
        wn_log(WN_LOG_WARN, "kernel32: LCMapStringW unsupported flags 0x%x",
               flags);
        wn_last_error_set(WN_ERR_INVALID_PARAMETER);
        return 0;
    }
    if (!dst) {                      /* size query */
        size_t need = n + 1;
        return need > 0x7FFFFFFF ? 0 : (int32_t)need;
    }
    if ((size_t)dstlen < n + 1) {
        wn_last_error_set(WN_ERR_INSUFFICIENT_BUFFER);
        return 0;
    }
    if (flags & LCMAP_BYTEREV)
        wn_log(WN_LOG_WARN, "kernel32: LCMapStringW BYTEREV combined with "
               "case mapping (applied after mapping)");
    size_t r = lc_map_case(src, n, dst, (size_t)dstlen, upper);
    if (!r) {
        wn_last_error_set(WN_ERR_INSUFFICIENT_BUFFER);
        return 0;
    }
    dst[n] = 0;
    if (flags & LCMAP_BYTEREV) {
        for (size_t i = 0; i < n; i++) {
            uint16_t v = dst[i];
            dst[i] = (uint16_t)((v >> 8) | (v << 8));
        }
    }
    return (int32_t)(n + 1);
}

static WN_API int32_t k32_LCMapStringA(uint32_t locale, uint32_t flags,
                                       const char *src, int32_t srclen,
                                       char *dst, int32_t dstlen)
{
    if (!src)
        return 0;
    size_t n = srclen < 0 ? strlen(src) : (size_t)srclen;
    uint16_t *w = wn_utf8_to_utf16_n(src, n);
    if (!w)
        return 0;
    uint16_t tmp[1024];
    uint16_t *out = (size_t)dstlen > 1024 ? wn_xmalloc((size_t)dstlen * 2) : tmp;
    int32_t r = k32_LCMapStringW(locale, flags, w, (int32_t)n, out,
                                 (int32_t)dstlen);
    free(w);
    if (r && dst && !(flags & LCMAP_SORTKEY)) {
        /* ASCII-safe narrow copy */
        size_t m = (size_t)r - 1;
        for (size_t i = 0; i < m; i++)
            dst[i] = (char)out[i];
        dst[m] = '\0';
    }
    if (out != tmp)
        free(out);
    return r;
}

/* Rtl* unwinding exports (implemented in seh.c) */
extern void wn_rtl_capture_context(void *);   /* raw asm symbol */
extern void *seh_RtlLookupFunctionEntry(uint64_t, uint64_t *, void *);
extern void *seh_RtlPcToFileHeader(uint64_t, uint64_t *);
extern void *seh_RtlVirtualUnwind(uint32_t, uint64_t, uint64_t, void *,
                                  void *, void **, uint32_t *, void *);
extern void  seh_RtlUnwind(uint64_t, uint64_t, void *, uint64_t);

static void k32_RtlCaptureContext(void *ctx) { wn_rtl_capture_context(ctx); }
static void *k32_RtlLookupFunctionEntry(uint64_t pc, uint64_t *base, void *h)
{ return seh_RtlLookupFunctionEntry(pc, base, h); }
static void *k32_RtlPcToFileHeader(uint64_t pc, uint64_t *base)
{ return seh_RtlPcToFileHeader(pc, base); }
static void *k32_RtlVirtualUnwind(uint32_t t, uint64_t ib, uint64_t tip,
                                  void *fe, void *ctx, void **hd,
                                  uint32_t *ef, void *cp)
{ return seh_RtlVirtualUnwind(t, ib, tip, fe, ctx, hd, ef, cp); }
static void k32_RtlUnwind(uint64_t tf, uint64_t tip, void *er, uint64_t rv)
{
    if (wn_wow64_guest32()) {
        /* i386 caller: frame-based unwind (see seh.c). The args are the
         * guest's 32-bit values (frame address, target ip, record ptr,
         * ReturnValue) — never returns when an SEH walk is active. */
        wn_seh_rtl_unwind_32((uint32_t)tf, (uint32_t)tip,
                            (uint32_t)(uintptr_t)er, (uint32_t)rv);
        return;
    } seh_RtlUnwind(tf, tip, er, rv); }

static WN_API char *k32_lstrcpyA(char *dst, const char *src)
{
    if (!dst || !src)
        return dst;
    return strcpy(dst, src);
}

static WN_API char *k32_lstrcpynA(char *dst, const char *src, int32_t n)
{
    if (!dst || !src || n <= 0)
        return dst;
    size_t l = strlen(src);
    if (l >= (size_t)n)
        l = (size_t)n - 1;
    memcpy(dst, src, l);
    dst[l] = '\0';
    return dst;
}

static WN_API int32_t k32_MultiByteToWideChar(uint32_t cp, uint32_t flags,
                                              const char *src, int32_t srclen,
                                              uint16_t *dst, int32_t dstcap)
{
    (void)cp;
    (void)flags;   /* invalid-char flags: we always map best-effort */
    if (!src)
        return 0;
    size_t slen = srclen < 0 ? strlen(src) : (size_t)srclen;
    uint16_t *w = wn_utf8_to_utf16_n(src, slen);
    if (!w) {
        /* Fall back to latin1 for non-UTF-8 (cp1252-ish) input. */
        w = wn_xmalloc((slen + 1) * 2);
        for (size_t i = 0; i < slen; i++)
            w[i] = (uint8_t)src[i];
        w[slen] = 0;
    }
    size_t wlen = 0;
    while (w[wlen])
        wlen++;
    int32_t ret;
    if (!dst || dstcap == 0) {
        ret = (int32_t)wlen;
    } else if ((size_t)dstcap < wlen + (srclen < 0 ? 1 : 0)) {
        wn_last_error_set(WN_ERR_INSUFFICIENT_BUFFER);
        ret = 0;
    } else {
        memcpy(dst, w, wlen * 2);
        if (srclen < 0)
            dst[wlen] = 0;
        ret = (int32_t)wlen;
    }
    free(w);
    return ret;
}

static WN_API int32_t k32_WideCharToMultiByte(uint32_t cp, uint32_t flags,
                                              const uint16_t *src, int32_t srclen,
                                              char *dst, int32_t dstcap,
                                              const void *def, int32_t *used_def)
{
    (void)cp;
    (void)flags;
    (void)def;
    if (used_def)
        *used_def = 0;
    if (!src)
        return 0;
    size_t wlen = srclen < 0 ? (size_t)k32_lstrlenW(src) : (size_t)srclen;
    char *a = wn_utf16_to_utf8(src, wlen);
    if (!a) {
        wn_last_error_set(WN_ERR_INVALID_PARAMETER);
        return 0;
    }
    size_t alen = strlen(a);
    if (srclen < 0)
        alen += 1;   /* include NUL */
    int32_t ret;
    if (!dst || dstcap == 0) {
        ret = (int32_t)strlen(a) + (srclen < 0 ? 0 : 0);
        /* Windows returns required size WITHOUT NUL for srclen<0? It returns
         * size incl NUL when srclen == -1. Keep exact: incl NUL. */
        ret = (int32_t)(srclen < 0 ? strlen(a) + 1 : strlen(a));
    } else if (alen > (size_t)dstcap) {
        wn_last_error_set(WN_ERR_INSUFFICIENT_BUFFER);
        ret = 0;
    } else {
        memcpy(dst, a, alen);
        ret = (int32_t)(srclen < 0 ? alen : alen - (alen && srclen >= 0 ? 0 : 0));
        ret = (int32_t)alen;
        if (srclen >= 0 && alen && a[alen - 1] == '\0')
            ret = (int32_t)alen;
    }
    free(a);
    if (srclen >= 0)
        ret = ret;   /* length of converted bytes */
    return ret;
}

/* --- environment ---------------------------------------------------------------- */

static WN_API char *k32_GetCommandLineA(void)
{
    if (g_wow64_active)
        return (char *)(uintptr_t)g_wow64_cmdline_a32;   /* low mirror */
    return g_proc.cmdline_utf8;
}

static WN_API const uint16_t *k32_GetCommandLineW(void)
{
    if (g_wow64_active)
        return (const uint16_t *)(uintptr_t)g_wow64_cmdline_w32;
    return g_proc.cmdline_utf16;
}

static char *env_lookup(const char *name)
{
    for (char **e = g_proc.env_utf8; e && *e; e++) {
        const char *eq = strchr(*e, '=');
        if (!eq)
            continue;
        size_t nl = strlen(name);
        if ((size_t)(eq - *e) == nl && !strncasecmp(*e, name, nl))
            return *e + nl + 1;
    }
    return NULL;
}

static WN_API uint32_t k32_GetEnvironmentVariableA(const char *name, char *buf,
                                                   uint32_t cap)
{
    char *v = env_lookup(name);
    wn_log(WN_LOG_DEBUG, " getenv A \"%s\" -> %s", name ? name : "(null)",
           v ? v : "(missing)");
    if (!v) {
        wn_last_error_set(203 /* ERROR_ENVVAR_NOT_FOUND */);
        return 0;
    }
    size_t n = strlen(v);
    if (!buf || cap < n + 1) {
        wn_last_error_set(WN_ERR_INSUFFICIENT_BUFFER);
        return (uint32_t)n + 1;   /* required size incl NUL */
    }
    memcpy(buf, v, n + 1);
    return (uint32_t)n;
}

static WN_API int32_t k32_SetEnvironmentVariableA(const char *name, const char *val)
{
    if (!name)
        return 0;
    size_t n = 0;
    for (char **e = g_proc.env_utf8; e && *e; e++)
        n++;
    char **ne = wn_xmalloc((n + 3) * sizeof(char *));
    size_t j = 0;
    for (char **e = g_proc.env_utf8; e && *e; e++) {
        const char *eq = strchr(*e, '=');
        size_t nl = strlen(name);
        if (eq && (size_t)(eq - *e) == nl && !strncasecmp(*e, name, nl))
            continue;
        ne[j++] = *e;
    }
    if (val) {
        char *kv = wn_xmalloc(strlen(name) + strlen(val) + 2);
        sprintf(kv, "%s=%s", name, val);
        ne[j++] = kv;
    }
    ne[j] = NULL;
    free(g_proc.env_utf8);
    g_proc.env_utf8 = ne;
    return 1;
}

/* --- misc ------------------------------------------------------------------------- */

static WN_API void k32_GetStartupInfoA(void *si)
{
    /* STARTUPINFOA x64: 104 bytes. */
    memset(si, 0, 104);
    *(uint32_t *)si = 104;
    *(uint16_t *)((uint8_t *)si + 0x40) = 1; /* SW_SHOWNORMAL */
}

static WN_API void k32_GetStartupInfoW(void *si)
{
    /* STARTUPINFOW x64: same layout but wide strings (unused). */
    k32_GetStartupInfoA(si);
}

static WN_API void *k32_SetUnhandledExceptionFilter(void *filter)
{
    return wn_seh_set_unhandled_filter(filter);
}

static WN_API int64_t k32_UnhandledExceptionFilter(void *exception_pointers)
{
    return wn_seh_call_unhandled_filter(exception_pointers);
}

static WN_API void k32_OutputDebugStringA(const char *s)
{
    if (s && *s && wn_log_level() >= WN_LOG_DEBUG)
        wn_log(WN_LOG_DEBUG, "OutputDebugString: %s", s);
}

static WN_API int32_t k32_IsDebuggerPresent(void)
{
    return 0;
}

static WN_API void *k32_EncodePointer(void *p) { return p; }
static WN_API void *k32_DecodePointer(void *p) { return p; }

static WN_API int32_t k32_SetErrorMode(uint32_t m)
{
    (void)m;
    return 0;
}

static WN_API int32_t k32_GetThreadPriority(wn_handle h)
{
    (void)h;
    return 0;   /* THREAD_PRIORITY_NORMAL */
}

static WN_API int32_t k32_SetThreadPriority(wn_handle h, int32_t prio)
{
    (void)h;
    (void)prio;
    return 1;   /* accepted; host scheduling unaffected (documented) */
}

static WN_API uint32_t k32_SetThreadAffinityMask(wn_handle h, wn_abiword mask)
{
    (void)h;
    (void)mask;
    wn_log(WN_LOG_WARN, "kernel32: SetThreadAffinityMask ignored (no-op)");
    return (uint32_t)-1 & 0xFFFFFFFF;
}

static WN_API void k32_GetSystemInfo(void *si)
{
    /* Layout depends on the CALLER's bitness, not the host build: the
     * in-process wow64 layer serves i386 guests from this x86-64 binary
     * (LuaForWindows installer: the x64 layout overflowed the 36-byte
     * guest struct and misaligned every field after dwPageSize). */
    if (wn_wow64_guest32()) {
        /* SYSTEM_INFO i386: 36 bytes, pointers 4.
         * oemId@0, pageSize@4, lpMin@8, lpMax@12, mask@16, nprocs@20,
         * procType@24, granularity@28, level@32, rev@34. */
        memset(si, 0, 36);
        uint8_t *p = si;
        *(uint32_t *)(p + 0) = 0;               /* arch 0 = x86           */
        *(uint32_t *)(p + 4) = 4096;            /* dwPageSize             */
        *(uint32_t *)(p + 8) = 0x10000;         /* lpMinimumAppAddress    */
        *(uint32_t *)(p + 12) = 0x7FFEFFFF;     /* lpMaximumAppAddress    */
        *(uint32_t *)(p + 16) = 1;              /* dwActiveProcessorMask  */
        *(uint32_t *)(p + 20) = 1;              /* dwNumberOfProcessors   */
        *(uint32_t *)(p + 24) = 586;            /* PROCESSOR_INTEL_PENTIUM */
        *(uint32_t *)(p + 28) = 0x10000;        /* granularity            */
        *(uint16_t *)(p + 32) = 6;              /* wProcessorLevel        */
        *(uint16_t *)(p + 34) = 0;              /* wProcessorRevision     */
        return;
    }
#if defined(__x86_64__)
    /* SYSTEM_INFO x64: 48 bytes, pointers 8.
     * arch@0, pageSize@4, lpMin@8, lpMax@16, mask@24, nprocs@32,
     * procType@36, granularity@40, level@44, rev@46. */
    memset(si, 0, 48);
    uint8_t *p = si;
    *(uint16_t *)(p + 0) = 9;                 /* PROCESSOR_ARCHITECTURE_AMD64 */
    *(uint32_t *)(p + 4) = 4096;              /* dwPageSize                   */
    *(uint64_t *)(p + 8) = 0x10000;           /* lpMinimumApplicationAddress  */
    *(uint64_t *)(p + 16) = 0x7FFFFFFEFFFFULL;/* lpMaximumApplicationAddress  */
    *(uint64_t *)(p + 24) = (1ULL << g_proc.peb->number_of_processors) - 1;
    *(uint32_t *)(p + 32) = g_proc.peb->number_of_processors;
    *(uint32_t *)(p + 36) = 8664;             /* PROCESSOR_AMD_X8664         */
    *(uint32_t *)(p + 40) = 0x10000;          /* allocation granularity      */
#else
    memset(si, 0, 36);
    uint8_t *p = si;
    *(uint32_t *)(p + 4) = 4096;
    *(uint32_t *)(p + 8) = 0x10000;
    *(uint32_t *)(p + 12) = 0x7FFEFFFF;
    *(uint32_t *)(p + 16) = 1;
    *(uint32_t *)(p + 20) = 1;
    *(uint32_t *)(p + 24) = 586;
    *(uint32_t *)(p + 28) = 0x10000;
    *(uint16_t *)(p + 32) = 6;
    *(uint16_t *)(p + 34) = 0;
#endif
}

static WN_API uint32_t k32_GetVersion(void)
{
    /* DWORD layout: build<<16 | minor<<8 | major. NT never sets bit 31
     * (that was the Win9x platform flag). Matches GetVersionExA: 10.0
     * build 19045. */
    return (19045u << 16) | (0u << 8) | 10u;
}

static WN_API int32_t k32_GetVersionExW(void *vi)
{
    /* OSVERSIONINFOW: 276 bytes, OSVERSIONINFOEXW: 284 (same fields as A
     * but szCSDVersion is 128 UTF-16 units). */
    uint32_t cb = *(uint32_t *)vi;
    if (cb != 276 && cb != 284) {
        wn_last_error_set(WN_ERR_INVALID_PARAMETER);
        return 0;
    }
    memset(vi, 0, cb);
    *(uint32_t *)vi = cb;
    uint8_t *p = vi;
    *(uint32_t *)(p + 4) = 10;     /* major */
    *(uint32_t *)(p + 8) = 0;      /* minor */
    *(uint32_t *)(p + 12) = 19045; /* build */
    *(uint32_t *)(p + 16) = 2;     /* VER_PLATFORM_WIN32_NT */
    return 1;
}

static WN_API int32_t k32_GetVersionExA(void *vi)
{
    /* OSVERSIONINFOA: 148 bytes. */
    uint32_t cb = *(uint32_t *)vi;
    if (cb != 148 && cb != 156 /* OSVERSIONINFOEXA */ ) {
        wn_last_error_set(WN_ERR_INVALID_PARAMETER);
        return 0;
    }
    memset(vi, 0, cb);
    *(uint32_t *)vi = cb;
    uint8_t *p = vi;
    *(uint32_t *)(p + 4) = 10;     /* major */
    *(uint32_t *)(p + 8) = 0;      /* minor */
    *(uint32_t *)(p + 12) = 19045; /* build */
    *(uint32_t *)(p + 16) = 2;     /* VER_PLATFORM_WIN32_NT */
    return 1;
}

static WN_API int32_t k32_IsProcessorFeaturePresent(uint32_t f)
{
    switch (f) {
    case 0:  return 0; /* PF_FLOATING_POINT_PRECISION_ERRATA */
    case 1:  return 0; /* PF_FLOATING_POINT_EMULATED         */
    case 23: return 0; /* PF_FASTFAIL_AVAILABLE: we do not service int 0x29 */
    default:
        /* Everything else the baseline x86-64 has: MMX/SSE/SSE2/SSE3,
         * cmpxchg, RDTSC, 3DNow-free, etc. */
        return 1;
    }
}


/* ========================================================================== */
/* Resources: .rsrc directory walking (RT_* by id or name)                     */
/* ========================================================================== */

typedef struct wn_res_handle {
    uint64_t  magic;      /* 'WNRH' */
    wn_module *mod;
    uint32_t  rva;
    uint32_t  size;
} wn_res_handle;

#define WN_RES_MAGIC 0x574E5248ULL

/* One resource directory node: 16-byte header + entries. */
static const uint8_t *res_dir_base(wn_module *m)
{
    if (m->kind != WN_MOD_PE)
        return NULL;
    /* Arch-correct data directories: PE32 (i386) and PE32+ (x64) optional
     * headers place the dirs array at different offsets — the old hardcoded
     * optional_header64 overlay walked garbage on 32-bit images. */
    const wn_image_data_directory *d = &wn_pe_dirs(&m->pe)[WN_IMAGE_DIR_RESOURCE];
    if (!d->virtual_address || !d->size)
        return NULL;
    return wn_pe_rva(&m->pe, d->virtual_address, 16);
}

/* Match an entry name/id against the caller's LPCSTR (id in low word or
 * string). Returns 1 on match. */
static int res_entry_matches(wn_module *m, const uint8_t *dirbase,
                             uint32_t name_field, const char *want)
{
    (void)m;
    (void)dirbase;
    if (!want)
        return 0;
    if (name_field & 0x80000000u) {
        /* named entry: UTF-16 string at offset (relative to dir base) */
        const uint8_t *sp = dirbase + (name_field & 0x7FFFFFFFu);
        uint16_t len;
        memcpy(&len, sp, 2);
        const uint16_t *w = (const uint16_t *)(const void *)(sp + 2);
        /* string compare with the ANSI want (case-insensitive) */
        for (uint16_t i = 0; i < len; i++) {
            uint32_t c1 = w[i];
            char a = want[i] ? want[i] : 0;
            uint32_t c2 = (uint8_t)a;
            if (c1 < 128)
                c1 = (uint32_t)toupper((int)c1);
            if (c2 < 128)
                c2 = (uint32_t)toupper((int)c2);
            if (c1 != c2)
                return 0;
            if (want[i] == 0)
                return i + 1 == len;   /* exact length match required */
        }
        return want[len] == 0;
    }
    /* id entry: compare against MAKEINTRESOURCE id (low 16 bits) or the
     * numeric string form ("123"). */
    uint32_t id = name_field & 0xFFFF;
    if (((uintptr_t)want >> 16) == 0)
        return id == (uint32_t)(uintptr_t)want;
    char num[16];
    snprintf(num, sizeof num, "%u", id);
    return wn_strcaseeq(num, want);
}

/* Walk one level: find the entry matching want. dir = absolute pointer to
 * the directory. Returns the entry's offset field, or 0. */
static uint32_t res_find_in_dir(wn_module *m, const uint8_t *dirbase,
                                const uint8_t *dir, const char *want)
{
    uint16_t nnamed, nid;
    memcpy(&nnamed, dir + 12, 2);
    memcpy(&nid, dir + 14, 2);
    uint32_t n = (uint32_t)nnamed + nid;
    const uint8_t *ent = dir + 16;
    for (uint32_t i = 0; i < n && i < 4096; i++) {
        uint32_t name_field, offset;
        memcpy(&name_field, ent + 0, 4);
        memcpy(&offset, ent + 4, 4);
        if (res_entry_matches(m, dirbase, name_field, want)) {
            if (!(offset & 0x80000000u))
                return 0;   /* leaf pointer must be a data entry */
            return offset & 0x7FFFFFFFu;   /* subdir offset */
        }
        ent += 8;
    }
    return 0;
}

static wn_res_handle *res_make(wn_module *m, uint32_t rva, uint32_t size)
{
    /* HRSRC is an OPAQUE wn_handle-table value (see FindResourceA): the
     * guest never sees this pointer, so plain host malloc is right in
     * every build (the old low-arena scheme handed raw pointers out and
     * old RTLs could pass them to the Global heap — see LoadResource). */
    wn_res_handle *h = wn_xmalloc(sizeof *h);
    if (!h)
        return NULL;
    h->magic = WN_RES_MAGIC;
    h->mod = m;
    h->rva = rva;
    h->size = size;
    return h;
}

/* HRSRC resolution: FindResource hands out opaque WN_HTYPE_RES handles;
 * accept the legacy raw wn_res_handle* too (never handed out anymore, kept
 * for one-build migrations). */
static wn_res_handle *res_lookup(wn_abiword hres)
{
    wn_object *o = wn_handle_get((wn_handle)(uintptr_t)hres, WN_HTYPE_RES);
    if (o)
        return o->ptr;
    wn_res_handle *rh = (wn_res_handle *)(uintptr_t)hres;
    if ((uintptr_t)rh > 0x10000 && rh->magic == WN_RES_MAGIC)
        return rh;
    return NULL;
}

static wn_module *mod_or_exe(uint64_t hmod)
{
    if (!hmod)
        return g_proc.exe;
    return wn_module_from_addr((const void *)(uintptr_t)hmod, NULL);
}

WN_API uint64_t k32_FindResourceA(wn_abiword hmod, const char *name,
                                         const char *type)
{
    wn_module *m = mod_or_exe(hmod);
    const uint8_t *base = m ? res_dir_base(m) : NULL;
    if (!base || !name || !type) {
        wn_last_error_set(1814 /* ERROR_RESOURCE_TYPE_NOT_FOUND */);
        return 0;
    }
    /* level 1: type */
    uint32_t off = res_find_in_dir(m, base, base, type);
    if (!off) {
        wn_last_error_set(1813 /* ERROR_RESOURCE_NAME_NOT_FOUND */);
        return 0;
    }
    /* level 2: name */
    off = res_find_in_dir(m, base, base + off, name);
    if (!off) {
        wn_last_error_set(1813);
        return 0;
    }
    /* level 3: language - take the first entry */
    {
        const uint8_t *dir = base + off;
        uint16_t nnamed, nid;
        memcpy(&nnamed, dir + 12, 2);
        memcpy(&nid, dir + 14, 2);
        uint32_t n = (uint32_t)nnamed + nid;
        if (n == 0) {
            wn_last_error_set(1813);
            return 0;
        }
        uint32_t leaf_off;
        memcpy(&leaf_off, dir + 16 + 4, 4);
        if (leaf_off & 0x80000000u) {
            wn_last_error_set(1812 /* ERROR_INVALID_RESOURCE_DATA_TYPE */);
            return 0;
        }
        const uint8_t *leaf = base + leaf_off;
        uint32_t rva, size;
        memcpy(&rva, leaf + 0, 4);
        memcpy(&size, leaf + 4, 4);
        if (!wn_pe_rva(&m->pe, rva, size > 0xFFFF ? 0xFFFF : size)) {
            wn_last_error_set(1812);
            return 0;
        }
        wn_res_handle *rh = res_make(m, rva, size);
        if (!rh)
            return 0;
        /* Opaque table handle: never expose the wn_res_handle* to the guest. */
        return (uint64_t)(uintptr_t)wn_handle_alloc(WN_HTYPE_RES, rh);
    }
}

static WN_API uint64_t k32_LoadResource(wn_abiword hmod, wn_abiword hres)
{
    (void)hmod;
    wn_res_handle *rh = res_lookup(hres);
    if (!rh) {
        wn_last_error_set(WN_ERR_INVALID_HANDLE);
        return 0;
    }
    /* LoadResource returns an HGLOBAL — a REAL Global-heap block. Old
     * Delphi/BCB RTLs (Inno's engine) pass it to GlobalLock/GlobalSize and
     * sometimes GlobalFree; raw wn_res_handle pointers there made those
     * calls free/realloc FOREIGN chunks and corrupt the heap (the winnux32
     * "Enum"-as-path crash walked exactly that recycling). */
    void *hblk = k32_GlobalAlloc(0x2 /* GMEM_MOVEABLE */, rh->size);
    if (!hblk)
        return 0;
    uint8_t *dst = k32_GlobalLock((wn_handle)(uintptr_t)hblk);
    const void *src = wn_pe_rva(&rh->mod->pe, rh->rva, rh->size);
    if (!dst || !src) {
        k32_GlobalFree((wn_handle)(uintptr_t)hblk);
        wn_last_error_set(WN_ERR_INVALID_HANDLE);
        return 0;
    }
    memcpy(dst, src, rh->size);
    k32_GlobalUnlock((wn_handle)(uintptr_t)hblk);
    wn_log(WN_LOG_DEBUG, "kernel32: LoadResource hres=%llx -> hglobal %p "
           "(%u bytes)", (unsigned long long)hres, hblk, rh->size);
    return (uint64_t)(uintptr_t)hblk;
}

WN_API void *k32_LockResource(wn_abiword hres)
{
    /* LoadResource's HGLOBAL: a Global-heap handle. */
    pthread_mutex_lock(&g_gh_mu);
    gh_ent *e = gh_find_h((uint32_t)(uintptr_t)hres);
    void *p = e ? e->ptr : NULL;
    pthread_mutex_unlock(&g_gh_mu);
    if (p)
        return p;
    /* FindResource's HRSRC: map straight to the image bytes (Windows
     * accepts LockResource(hFindResource) from 16-bit-era code). */
    wn_res_handle *rh = res_lookup(hres);
    if (!rh)
        return NULL;
    void *ip = wn_pe_rva(&rh->mod->pe, rh->rva,
                        rh->size > 0xFFFF ? 0xFFFF : rh->size);
    if (!ip)
        wn_log(WN_LOG_WARN, "kernel32: resource rva 0x%x out of image",
               rh->rva);
    return ip;
}

static WN_API uint32_t k32_SizeofResource(wn_abiword hmod, wn_abiword hres)
{
    (void)hmod;
    pthread_mutex_lock(&g_gh_mu);
    gh_ent *e = gh_find_h((uint32_t)(uintptr_t)hres);
    uint32_t sz = e ? (uint32_t)e->size : 0;
    pthread_mutex_unlock(&g_gh_mu);
    if (sz)
        return sz;
    wn_res_handle *rh = res_lookup(hres);
    if (rh)
        return rh->size;
    wn_last_error_set(WN_ERR_INVALID_HANDLE);
    return 0;
}

static WN_API int32_t k32_Beep(uint32_t freq, uint32_t dur)
{
    (void)freq;
    (void)dur;
    return 1;
}

/* --- Interlocked family -------------------------------------------------------
 * The 32-bit (LONG) variants operate on 4-byte objects regardless of the
 * guest's bitness; the *Pointer variants are pointer-sized (4 bytes for an
 * i386 caller even on this x86-64 host build). NSIS calls Interlocked*
 * for its init-once/CRC guards and REQUIRES the real old-value semantics. */
static WN_API int32_t k32_InterlockedIncrement(int32_t *p)
{
    return __atomic_add_fetch(p, 1, __ATOMIC_SEQ_CST);
}

static WN_API int32_t k32_InterlockedDecrement(int32_t *p)
{
    return __atomic_sub_fetch(p, 1, __ATOMIC_SEQ_CST);
}

static WN_API int32_t k32_InterlockedExchange(int32_t *p, int32_t v)
{
    int32_t old;
    __atomic_exchange(p, &v, &old, __ATOMIC_SEQ_CST);
    return old;
}

static WN_API int32_t k32_InterlockedExchangeAdd(int32_t *p, int32_t v)
{
    return __atomic_fetch_add(p, v, __ATOMIC_SEQ_CST);
}

static WN_API int32_t k32_InterlockedCompareExchange(int32_t *p, int32_t exch,
                                                     int32_t comp)
{
    int32_t expected = comp;
    __atomic_compare_exchange(p, &expected, &exch, 0,
                              __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    return expected;
}

/* 64-bit variants (also serve *Pointer for 64-bit callers). */
static WN_API int64_t k32_InterlockedExchange64(int64_t *p, int64_t v)
{
    int64_t old;
    __atomic_exchange(p, &v, &old, __ATOMIC_SEQ_CST);
    return old;
}

static WN_API int64_t k32_InterlockedCompareExchange64(int64_t *p,
                                                       int64_t exch,
                                                       int64_t comp)
{
    int64_t expected = comp;
    __atomic_compare_exchange(p, &expected, &exch, 0,
                              __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    return expected;
}

static WN_API int64_t k32_InterlockedIncrement64(int64_t *p)
{
    return __atomic_add_fetch(p, 1, __ATOMIC_SEQ_CST);
}

static WN_API int64_t k32_InterlockedDecrement64(int64_t *p)
{
    return __atomic_sub_fetch(p, 1, __ATOMIC_SEQ_CST);
}

static WN_API int64_t k32_InterlockedExchangeAdd64(int64_t *p, int64_t v)
{
    return __atomic_fetch_add(p, v, __ATOMIC_SEQ_CST);
}

/* Interlocked[Compare]Exchange[Add]Pointer: pointer-sized - an i386 caller
 * gets 4-byte semantics even on the x86-64 host build (wow64 in-process). */
static WN_API wn_abiword k32_InterlockedExchangePointer(wn_abiword *p,
                                                        wn_abiword v)
{
    if (wn_wow64_guest32()) {
        int32_t *p32 = (int32_t *)(uintptr_t)p, old;
        int32_t v32 = (int32_t)v;
        __atomic_exchange(p32, &v32, &old, __ATOMIC_SEQ_CST);
        return (wn_abiword)(uint32_t)old;
    }
    wn_abiword old;
    __atomic_exchange(p, &v, &old, __ATOMIC_SEQ_CST);
    return old;
}

static WN_API wn_abiword k32_InterlockedCompareExchangePointer(
    wn_abiword *p, wn_abiword exch, wn_abiword comp)
{
    if (wn_wow64_guest32()) {
        int32_t *p32 = (int32_t *)(uintptr_t)p, expected = (int32_t)comp,
                 exch32 = (int32_t)exch;
        __atomic_compare_exchange(p32, &expected, &exch32, 0,
                                  __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
        return (wn_abiword)(uint32_t)expected;
    }
    wn_abiword expected = comp;
    __atomic_compare_exchange(p, &expected, &exch, 0,
                              __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    return expected;
}

/* --- locale ----------------------------------------------------------------- */
/* en-US defaults: the guest's world is Windows-shaped, and Inno/Delphi
 * query these constantly for number/date formatting (0x44 = abbreviated
 * month name "Jan" was the first one Inno Setup asked for). */

static WN_API uint16_t k32_GetUserDefaultLangID(void)  { return 0x0409; }
static WN_API uint16_t k32_GetSystemDefaultLangID(void) { return 0x0409; }
static WN_API uint32_t k32_GetUserDefaultLCID(void)    { return 0x0409; }
static WN_API uint32_t k32_GetSystemDefaultLCID(void)  { return 0x0409; }
static WN_API uint32_t k32_GetThreadLocale(void)       { return 0x0409; }

static const char *locale_day_name(uint32_t t)
{
    static const char *days[7] = { "Monday","Tuesday","Wednesday","Thursday",
                                   "Friday","Saturday","Sunday" };
    static const char *abbr[7] = { "Mon","Tue","Wed","Thu","Fri","Sat","Sun" };
    if (t >= 0x2A && t <= 0x30) return days[t - 0x2A];   /* SDAYNAME1..7    */
    if (t >= 0x31 && t <= 0x37) return abbr[t - 0x31];   /* SABBREVDAY1..7  */
    return NULL;
}

static const char *locale_month_name(uint32_t t)
{
    static const char *mon[12] = { "January","February","March","April",
                                   "May","June","July","August",
                                   "September","October","November","December" };
    static const char *abbr[12] = { "Jan","Feb","Mar","Apr","May","Jun",
                                    "Jul","Aug","Sep","Oct","Nov","Dec" };
    if (t >= 0x38 && t <= 0x43) return mon[t - 0x38];
    if (t >= 0x44 && t <= 0x4F) return abbr[t - 0x44];
    return NULL;
}

static const char *locale_str_for(uint32_t t)
{
    switch (t) {
    case 0x01: return "9";                   /* LOCALE_ILANGUAGE      */
    case 0x02: return "English (United States)"; /* LOCALE_SLANGUAGE   */
    case 0x04: return "English";             /* LOCALE_SNATIVELANGNAME*/
    case 0x05: return "1";                   /* LOCALE_ICOUNTRY        */
    case 0x06: return "United States";       /* LOCALE_SCOUNTRY        */
    case 0x08: return "United States";       /* LOCALE_SNATIVECTRYNAME */
    case 0x0C: return ";";                   /* LOCALE_SLIST           */
    case 0x0D: return "0";                   /* LOCALE_IMEASURE        */
    case 0x0E: return ".";                   /* LOCALE_SDECIMAL        */
    case 0x0F: return ",";                   /* LOCALE_STHOUSAND       */
    case 0x10: return "3;0";                 /* LOCALE_SGROUPING       */
    case 0x11: return "2";                   /* LOCALE_IDIGITS         */
    case 0x12: return "1";                   /* LOCALE_ILZERO          */
    case 0x1010: return "1";                 /* LOCALE_INEGNUMBER      */
    case 0x13: return "0123456789";          /* LOCALE_SNATIVEDIGITS   */
    case 0x14: return "$";                   /* LOCALE_SCURRENCY       */
    case 0x15: return "USD";                 /* LOCALE_SINTLSYMBOL     */
    case 0x16: return ".";                   /* LOCALE_SMONDECIMALSEP  */
    case 0x17: return ",";                   /* LOCALE_SMONTHOUSANDSEP */
    case 0x18: return "3;0";                 /* LOCALE_SMONGROUPING    */
    case 0x19: return "2";                   /* LOCALE_ICURRDIGITS     */
    case 0x1A: return "2";                   /* LOCALE_IINTLCURRDIGITS */
    case 0x1B: return "0";                   /* LOCALE_ICURRENCY       */
    case 0x1C: return "1";                   /* LOCALE_INEGCURR        */
    case 0x1D: return "/";                   /* LOCALE_SDATE           */
    case 0x1E: return ":";                   /* LOCALE_STIME           */
    case 0x1F: return "M/d/yyyy";            /* LOCALE_SSHORTDATE      */
    case 0x20: return "dddd, MMMM d, yyyy";  /* LOCALE_SLONGDATE       */
    case 0x21: return "0";                   /* LOCALE_IDATE           */
    case 0x22: return "0";                   /* LOCALE_ILDATE          */
    case 0x23: return "0";                   /* LOCALE_ITIME (12h)     */
    case 0x24: return "0";                   /* LOCALE_ICENTURY        */
    case 0x25: return "1";                   /* LOCALE_ITLZERO         */
    case 0x26: return "0";                   /* LOCALE_IDAYLZERO       */
    case 0x27: return "0";                   /* LOCALE_IMONLZERO       */
    case 0x28: return "AM";                  /* LOCALE_S1159           */
    case 0x29: return "PM";                  /* LOCALE_S2359           */
    case 0x50: return "";                    /* LOCALE_SPOSITIVESIGN   */
    case 0x51: return "-";                   /* LOCALE_SNEGATIVESIGN   */
    case 0x1001: return "English";           /* LOCALE_SENGLANGUAGE    */
    case 0x1002: return "United States";     /* LOCALE_SENGCOUNTRY     */
    case 0x1003: return "h:mm:ss tt";        /* LOCALE_STIMEFORMAT     */
    case 0x1004: return "1252";              /* LOCALE_IDEFAULTANSICODEPAGE */
    case 0x1005: return "0";                 /* LOCALE_ITIMEMARKPOSN   */
    case 0x1006: return "MMMM yyyy";         /* LOCALE_SYEARMONTH      */
    default: {
        const char *s = locale_day_name(t);
        if (s) return s;
        return locale_month_name(t);
    }
    }
}

static WN_API int32_t k32_GetLocaleInfoA(uint32_t lcid, uint32_t lctype,
                                         char *buf, int32_t cch)
{
    (void)lcid;
    uint32_t t = lctype & 0xFFFF;             /* strip NOUSEROVERRIDE etc. */
    if (lctype & 0x20000000u /* LOCALE_RETURN_NUMBER */) {
        if (!buf)
            return 4;
        if (cch < 4) {
            wn_last_error_set(WN_ERR_INSUFFICIENT_BUFFER);
            return 0;
        }
        const char *s = locale_str_for(t);
        uint32_t v = s ? (uint32_t)strtoul(s, NULL, 10) : 0;
        memcpy(buf, &v, 4);
        return 4;
    }
    const char *s = locale_str_for(t);
    if (!s) {
        wn_log(WN_LOG_WARN, "kernel32: GetLocaleInfoA: lctype 0x%x "
               "unsupported", lctype);
        wn_last_error_set(WN_ERR_INVALID_PARAMETER);
        return 0;
    }
    int32_t need = (int32_t)strlen(s) + 1;
    if (!buf || cch == 0)
        return need;
    int32_t copy = need < cch ? need : cch;
    memcpy(buf, s, (size_t)copy);
    buf[copy - 1] = 0;
    return copy;
}

static WN_API int32_t k32_GetLocaleInfoW(uint32_t lcid, uint32_t lctype,
                                         uint16_t *buf, int32_t cch)
{
    (void)lcid;
    uint32_t t = lctype & 0xFFFF;
    const char *s = locale_str_for(t);
    if (lctype & 0x20000000u) {
        if (!buf)
            return 4;
        if (cch < 2) {
            wn_last_error_set(WN_ERR_INSUFFICIENT_BUFFER);
            return 0;
        }
        uint32_t v = s ? (uint32_t)strtoul(s, NULL, 10) : 0;
        memcpy(buf, &v, 4);
        return 4;
    }
    if (!s) {
        wn_log(WN_LOG_WARN, "kernel32: GetLocaleInfoW: lctype 0x%x "
               "unsupported", lctype);
        wn_last_error_set(WN_ERR_INVALID_PARAMETER);
        return 0;
    }
    int32_t need = (int32_t)strlen(s) + 1;
    if (!buf || cch == 0)
        return need;
    uint16_t *w = wn_utf8_to_utf16(s, NULL);
    if (!w)
        return 0;
    int32_t copy = need < cch ? need : cch;
    for (int32_t i = 0; i < copy - 1; i++)
        buf[i] = w[i];
    buf[copy - 1] = 0;
    free(w);
    return copy;
}

static WN_API void k32_RaiseException(uint32_t code, uint32_t flags,
                                      uint32_t nparams, const void *params)
{
    /* The ExceptionInformation array is DWORD-sized for 32-bit callers
     * (Delphi passes the exception object + address there) and QWORD-
     * sized for x64 callers. */
    uint64_t p[15] = { 0 };
    if (params && nparams) {
        uint32_t n = nparams > 15 ? 15 : nparams;
        if (wn_wow64_guest32()) {
            const uint32_t *p32 = params;
            for (uint32_t i = 0; i < n; i++)
                p[i] = p32[i];
        } else {
            const uint64_t *p64 = params;
            for (uint32_t i = 0; i < n; i++)
                p[i] = p64[i];
        }
    }
    wn_seh_raise(code, flags, nparams, p);
}

static WN_API int32_t k32_DuplicateHandle(wn_handle src_proc, wn_handle src,
                                          wn_handle tgt_proc, wn_handle *out,
                                          uint32_t access, int32_t inherit,
                                          uint32_t options)
{
    (void)src_proc;
    (void)tgt_proc;
    (void)access;
    (void)inherit;
    if (!out) {
        wn_last_error_set(WN_ERR_INVALID_PARAMETER);
        return 0;
    }
    if ((intptr_t)(uintptr_t)src == -1) {        /* current process */
        static int proc_obj;
        *out = wn_handle_alloc(WN_HTYPE_PROCESS, &proc_obj);
        return 1;
    }
    if ((intptr_t)(uintptr_t)src == -2) {        /* current thread */
        wn_thread *th = wn_thread_current();
        if (!th) {
            wn_last_error_set(WN_ERR_INVALID_HANDLE);
            return 0;
        }
        *out = wn_handle_alloc(WN_HTYPE_THREAD, th);
        return 1;
    }
    wn_object *o = wn_handle_acquire(src, 0);
    if (!o)
        return 0;
    if (options & 1 /* DUPLICATE_CLOSE_SOURCE */)
        wn_handle_close(src);
    *out = src;    /* share the same handle value; refcount protects it */
    return 1;
}

/* --- export table ------------------------------------------------------------------ */


/* Console ctrl handlers: registration is real (stored); host -> guest event
 * forwarding (SIGINT -> CTRL_C_EVENT) is a documented TODO. */
static uint64_t g_ctrl_handlers[16];
static int32_t g_ctrl_handler_count;

static WN_API int32_t k32_SetConsoleCtrlHandler(wn_abiword handler, int32_t add)
{
    if (!add) {
        for (int i = 0; i < g_ctrl_handler_count; i++)
            if (g_ctrl_handlers[i] == handler) {
                g_ctrl_handlers[i] = 0;
                return 1;
            }
        wn_last_error_set(WN_ERR_INVALID_PARAMETER);
        return 0;
    }
    if (g_ctrl_handler_count >= 16) {
        wn_last_error_set(WN_ERR_NOT_ENOUGH_MEMORY);
        return 0;
    }
    g_ctrl_handlers[g_ctrl_handler_count++] = handler;
    return 1;
}

const wn_export_entry wn_kernel32_exports[] = {
    { "Beep", k32_Beep },
    { "GetFullPathNameA", k32_GetFullPathNameA },
    { "GetFullPathNameW", k32_GetFullPathNameW },
    { "FormatMessageA", k32_FormatMessageA },
    { "FormatMessageW", k32_FormatMessageW },
    { "SetFileApisToOEM", k32_SetFileApisToOEM },
    { "SetFileApisToANSI", k32_SetFileApisToOEM },
    { "GetUserDefaultLangID", k32_GetUserDefaultLangID },
    { "GetSystemDefaultLangID", k32_GetSystemDefaultLangID },
    { "GetUserDefaultLCID", k32_GetUserDefaultLCID },
    { "GetSystemDefaultLCID", k32_GetSystemDefaultLCID },
    { "GetThreadLocale", k32_GetThreadLocale },
    { "GetLocaleInfoA", k32_GetLocaleInfoA },
    { "GetLocaleInfoW", k32_GetLocaleInfoW },
    { "CloseHandle", k32_CloseHandle },
    { "CopyFileA", k32_CopyFileA },
    { "CreateDirectoryA", k32_CreateDirectoryA },
    { "CreateEventA", k32_CreateEventA },
    { "CreateEventW", k32_CreateEventW },
    { "CreateFileA", k32_CreateFileA },
    { "CreateFileW", k32_CreateFileW },
    { "CreateMutexA", k32_CreateMutexA },
    { "CreateMutexW", k32_CreateMutexW },
    { "CreateProcessA", k32_CreateProcessA },
    { "CompareFileTime", k32_CompareFileTime },
    { "CompareStringA", k32_CompareStringA },
    { "CompareStringW", k32_CompareStringW },
    { "FileTimeToLocalFileTime", k32_FileTimeToLocalFileTime },
    { "LocalFileTimeToFileTime", k32_LocalFileTimeToFileTime },
    { "MoveFileExA", k32_MoveFileExA },
    { "MoveFileExW", k32_MoveFileExW },
    { "OpenProcess", k32_OpenProcess },
    { "CreateProcessW", k32_CreateProcessW },
    { "CreateSemaphoreA", k32_CreateSemaphoreA },
    { "CreateThread", k32_CreateThread },
    { "DecodePointer", k32_DecodePointer },
    { "DeleteCriticalSection", k32_DeleteCriticalSection },
    { "DeleteFileA", k32_DeleteFileA },
    { "DeleteFileW", k32_DeleteFileW },
    { "DisableThreadLibraryCalls", k32_DisableThreadLibraryCalls },
    { "DuplicateHandle", k32_DuplicateHandle },
    { "EncodePointer", k32_EncodePointer },
    { "EnterCriticalSection", k32_EnterCriticalSection },
    { "ExitProcess", k32_ExitProcess },
    { "ExitThread", k32_ExitThread },
    { "FindClose", k32_FindClose },
    { "FindFirstFileA", k32_FindFirstFileA },
    { "FindFirstFileW", k32_FindFirstFileW },
    { "FindNextFileA", k32_FindNextFileA },
    { "FindNextFileW", k32_FindNextFileW },
    { "FlushFileBuffers", k32_FlushFileBuffers },
    { "FreeLibrary", k32_FreeLibrary },
    { "GetACP", k32_GetACP },
    { "GetCPInfo", k32_GetCPInfo },
    { "GetCommandLineA", k32_GetCommandLineA },
    { "GetCommandLineW", k32_GetCommandLineW },
    { "GetConsoleCP", k32_GetConsoleCP },
    { "GetConsoleMode", k32_GetConsoleMode },
    { "GetConsoleOutputCP", k32_GetConsoleOutputCP },
    { "GetCurrentDirectoryA", k32_GetCurrentDirectoryA },
    { "GetCurrentProcess", k32_GetCurrentProcess },
    { "GetProcessAffinityMask", k32_GetProcessAffinityMask },
    { "IsWow64Process", k32_IsWow64Process },
    { "GetProcessTimes", k32_GetProcessTimes },
    { "GetSystemTimes", k32_GetSystemTimes },
    { "GetCurrentProcessId", k32_GetCurrentProcessId },
    { "GetCurrentThread", k32_GetCurrentThread },
    { "GetCurrentThreadId", k32_GetCurrentThreadId },
    { "GetDiskFreeSpaceExA", k32_GetDiskFreeSpaceExA },
    { "GetDriveTypeA", k32_GetDriveTypeA },
    { "GetEnvironmentVariableA", k32_GetEnvironmentVariableA },
    { "GetExitCodeProcess", k32_GetExitCodeProcess },
    { "GetExitCodeThread", k32_GetExitCodeThread },
    { "GetFileAttributesA", k32_GetFileAttributesA },
    { "GetFileAttributesW", k32_GetFileAttributesW },
    { "GetFileSize", k32_GetFileSize },
    { "GetFileSizeEx", k32_GetFileSizeEx },
    { "GetFileType", k32_GetFileType },
    { "GetLastError", k32_GetLastError },
    { "GetLogicalDriveStringsA", k32_GetLogicalDriveStringsA },
    { "GetModuleFileNameA", k32_GetModuleFileNameA },
    { "GetModuleFileNameW", k32_GetModuleFileNameW },
    { "GetModuleHandleA", k32_GetModuleHandleA },
    { "GetModuleHandleW", k32_GetModuleHandleW },
    { "GetModuleHandleExW", k32_GetModuleHandleExW },
    { "GetModuleHandleExA", k32_GetModuleHandleExA },
    { "GetOEMCP", k32_GetOEMCP },
    { "GetProcAddress", k32_GetProcAddress },
    { "GetProcessHeap", k32_GetProcessHeap },
    { "GetStartupInfoA", k32_GetStartupInfoA },
    { "GetStartupInfoW", k32_GetStartupInfoW },
    { "GetStdHandle", k32_GetStdHandle },
    { "GetSystemInfo", k32_GetSystemInfo },
    { "GetSystemTime", k32_GetSystemTime },
    { "GetSystemTimeAsFileTime", k32_GetSystemTimeAsFileTime },
    { "GetThreadPriority", k32_GetThreadPriority },
    { "GetTempPathA", k32_GetTempPathA },
    { "GetTickCount", k32_GetTickCount },
    { "GetTickCount64", k32_GetTickCount64 },
    { "InterlockedCompareExchange", k32_InterlockedCompareExchange },
    { "InterlockedCompareExchange64", k32_InterlockedCompareExchange64 },
    { "InterlockedCompareExchangePointer", k32_InterlockedCompareExchangePointer },
    { "InterlockedDecrement", k32_InterlockedDecrement },
    { "InterlockedDecrement64", k32_InterlockedDecrement64 },
    { "InterlockedExchange", k32_InterlockedExchange },
    { "InterlockedExchange64", k32_InterlockedExchange64 },
    { "InterlockedExchangeAdd", k32_InterlockedExchangeAdd },
    { "InterlockedExchangeAdd64", k32_InterlockedExchangeAdd64 },
    { "InterlockedExchangePointer", k32_InterlockedExchangePointer },
    { "InterlockedIncrement", k32_InterlockedIncrement },
    { "InterlockedIncrement64", k32_InterlockedIncrement64 },
    { "GetVersion", k32_GetVersion },
    { "GetVersionExA", k32_GetVersionExA },
    { "GetVersionExW", k32_GetVersionExW },
    { "GetVolumeInformationA", k32_GetVolumeInformationA },
    { "GlobalAlloc", k32_GlobalAlloc },
    { "GlobalFree", k32_GlobalFree },
    { "GlobalHandle", k32_GlobalHandle },
    { "GlobalLock", k32_GlobalLock },
    { "GlobalReAlloc", k32_GlobalReAlloc },
    { "GlobalSize", k32_GlobalSize },
    { "GlobalUnlock", k32_GlobalUnlock },
    { "GlobalAddAtomA", k32_GlobalAddAtomA },
    { "GlobalAddAtomW", k32_GlobalAddAtomW },
    { "GlobalFindAtomA", k32_GlobalFindAtomA },
    { "GlobalFindAtomW", k32_GlobalFindAtomW },
    { "GlobalDeleteAtom", k32_GlobalDeleteAtom },
    { "GetAtomNameA", k32_GetAtomNameA },
    { "GetAtomNameW", k32_GetAtomNameW },
    { "HeapAlloc", k32_HeapAlloc },
    { "HeapCreate", k32_HeapCreate },
    { "HeapDestroy", k32_HeapDestroy },
    { "HeapFree", k32_HeapFree },
    { "HeapReAlloc", k32_HeapReAlloc },
    { "InitializeCriticalSection", k32_InitializeCriticalSection },
    { "InitializeCriticalSectionAndSpinCount", k32_InitializeCriticalSectionAndSpinCount },
    { "IsDBCSLeadByte", k32_IsDBCSLeadByte },
    { "IsDebuggerPresent", k32_IsDebuggerPresent },
    { "IsProcessorFeaturePresent", k32_IsProcessorFeaturePresent },
    { "LeaveCriticalSection", k32_LeaveCriticalSection },
    { "RtlCaptureContext", k32_RtlCaptureContext },
    { "RtlLookupFunctionEntry", k32_RtlLookupFunctionEntry },
    { "RtlPcToFileHeader", k32_RtlPcToFileHeader },
    { "RtlUnwind", k32_RtlUnwind },
    { "RtlVirtualUnwind", k32_RtlVirtualUnwind },
    { "LoadLibraryA", k32_LoadLibraryA },
    { "LoadLibraryExA", k32_LoadLibraryExA },
    { "LoadLibraryExW", k32_LoadLibraryExW },
    { "LoadLibraryW", k32_LoadLibraryW },
    { "LocalAlloc", k32_LocalAlloc },
    { "LocalFree", k32_LocalFree },
    { "LocalHandle", k32_LocalHandle },
    { "LocalLock", k32_LocalLock },
    { "LocalReAlloc", k32_LocalReAlloc },
    { "LocalSize", k32_LocalSize },
    { "LocalUnlock", k32_LocalUnlock },
    { "lstrcmpA", k32_lstrcmpA },
    { "lstrcmpiA", k32_lstrcmpiA },
    { "lstrcmpiW", k32_lstrcmpiW },
    { "lstrcmpW", k32_lstrcmpW },
    { "GetStringTypeA", k32_GetStringTypeA },
    { "GetStringTypeExA", k32_GetStringTypeA },
    { "GetStringTypeExW", k32_GetStringTypeExW },
    { "GetStringTypeW", k32_GetStringTypeW },
    { "LCMapStringA", k32_LCMapStringA },
    { "LCMapStringW", k32_LCMapStringW },
    { "lstrcpyA", k32_lstrcpyA },
    { "lstrcpynA", k32_lstrcpynA },
    { "lstrlenA", k32_lstrlenA },
    { "lstrlenW", k32_lstrlenW },
    { "MoveFileA", k32_MoveFileA },
    { "MultiByteToWideChar", k32_MultiByteToWideChar },
    { "QueryPerformanceCounter", k32_QueryPerformanceCounter },
    { "QueryPerformanceFrequency", k32_QueryPerformanceFrequency },
    { "RaiseException", k32_RaiseException },
    { "ReadConsoleA", k32_ReadConsoleA },
    { "ReadFile", k32_ReadFile },
    { "ReleaseMutex", k32_ReleaseMutex },
    { "ReleaseSemaphore", k32_ReleaseSemaphore },
    { "RemoveDirectoryA", k32_RemoveDirectoryA },
    { "ResetEvent", k32_ResetEvent },
    { "ResumeThread", k32_ResumeThread },
    { "SetConsoleMode", k32_SetConsoleMode },
    { "SetConsoleOutputCP", k32_SetConsoleOutputCP },
    { "SetCurrentDirectoryA", k32_SetCurrentDirectoryA },
    { "SetEndOfFile", k32_SetEndOfFile },
    { "SetEnvironmentVariableA", k32_SetEnvironmentVariableA },
    { "SetErrorMode", k32_SetErrorMode },
    { "SetEvent", k32_SetEvent },
    { "SetFileAttributesA", k32_SetFileAttributesA },
    { "SetFilePointer", k32_SetFilePointer },
    { "SetFilePointerEx", k32_SetFilePointerEx },
    { "SetLastError", k32_SetLastError },
    { "SetStdHandle", k32_SetStdHandle },
    { "SetThreadAffinityMask", k32_SetThreadAffinityMask },
    { "SetThreadPriority", k32_SetThreadPriority },
    { "SetThreadPriority", k32_SetThreadPriority },
    { "SetUnhandledExceptionFilter", k32_SetUnhandledExceptionFilter },
    { "UnhandledExceptionFilter", k32_UnhandledExceptionFilter },
    { "RaiseException", k32_RaiseException },
    { "Sleep", k32_Sleep },
    { "SleepEx", k32_SleepEx },
    { "SuspendThread", k32_SuspendThread },
    { "SwitchToThread", k32_SwitchToThread },
    { "TerminateProcess", k32_TerminateProcess },
    { "FlsAlloc", k32_FlsAlloc },
    { "FlsFree", k32_FlsFree },
    { "FlsGetValue", k32_FlsGetValue },
    { "FlsSetValue", k32_FlsSetValue },
    { "TlsAlloc", k32_TlsAlloc },
    { "TlsFree", k32_TlsFree },
    { "TlsGetValue", k32_TlsGetValue },
    { "TlsSetValue", k32_TlsSetValue },
    { "TryEnterCriticalSection", k32_TryEnterCriticalSection },
    { "VirtualAlloc", k32_VirtualAlloc },
    { "VirtualFree", k32_VirtualFree },
    { "VirtualProtect", k32_VirtualProtect },
    { "VirtualQuery", k32_VirtualQuery },
    { "WaitForMultipleObjects", k32_WaitForMultipleObjects },
    { "WaitForMultipleObjectsEx", k32_WaitForMultipleObjectsEx },
    { "WaitForSingleObject", k32_WaitForSingleObject },
    { "WaitForSingleObjectEx", k32_WaitForSingleObjectEx },
    { "WideCharToMultiByte", k32_WideCharToMultiByte },
    { "WriteConsoleA", k32_WriteConsoleA },
    { "WriteConsoleW", k32_WriteConsoleW },
    { "WriteFile", k32_WriteFile },
    { "SetConsoleCtrlHandler", k32_SetConsoleCtrlHandler },
    { "GetSystemDirectoryA", k32_GetSystemDirectoryA },
    { "GetSystemDirectoryW", k32_GetSystemDirectoryW },
    { "GetWindowsDirectoryA", k32_GetWindowsDirectoryA },
    { "GetWindowsDirectoryW", k32_GetWindowsDirectoryW },
    { "GetEnvironmentStringsW", k32_GetEnvironmentStringsW },
    { "FreeEnvironmentStringsW", k32_FreeEnvironmentStringsW },
    { "IsValidCodePage", k32_IsValidCodePage },
    { "InitializeSListHead", k32_InitializeSListHead },
    { "IsDBCSLeadByteEx", k32_IsDBCSLeadByteEx },
    { "GetCurrentDirectoryA", k32_GetCurrentDirectoryA },
    { "GetCurrentDirectoryW", k32_GetCurrentDirectoryW },
    { "SetCurrentDirectoryA", k32_SetCurrentDirectoryA },
    { "SetCurrentDirectoryW", k32_SetCurrentDirectoryW },
    { "OutputDebugStringA", k32_OutputDebugStringA },
    { "OutputDebugStringW", k32_OutputDebugStringW },
    { "MulDiv", k32_MulDiv },
    { "FindResourceA", k32_FindResourceA },
    { "LoadResource", k32_LoadResource },
    { "LockResource", k32_LockResource },
    { "SizeofResource", k32_SizeofResource },
    { NULL, NULL },
};
