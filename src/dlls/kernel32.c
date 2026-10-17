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

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <malloc.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <sys/statvfs.h>
#include <sys/stat.h>
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
        wn_last_error_set(WN_ERR_FILE_NOT_FOUND);
        return NULL;
    }
    return (wn_handle)(uintptr_t)m->base;
}

static WN_API wn_handle k32_GetModuleHandleW(const uint16_t *name)
{
    char a[256];
    if (!name) {
        a[0] = '\0';
    } else {
        char *s = wn_utf16_to_utf8(name, 4096);
        if (!s) {
            wn_last_error_set(WN_ERR_INVALID_PARAMETER);
            return NULL;
        }
        snprintf(a, sizeof a, "%s", s);
        free(s);
    }
    return k32_GetModuleHandleA(name ? a : NULL);
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
        return (uint32_t)n;
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
        return (uint32_t)l;
    }
    memcpy(out, w, (l + 1) * 2);
    free(w);
    return (uint32_t)l;
}

static wn_handle load_module_by_name(const char *name, int flags)
{
    (void)flags;
    wn_module *m = wn_module_load_dll(name, NULL);
    if (!m) {
        char buf[128];
        snprintf(buf, sizeof buf, "%s.dll", name);
        m = wn_module_load_dll(buf, NULL);
    }
    if (!m)
        return NULL;
    return (wn_handle)(uintptr_t)m->base;
}

static WN_API wn_handle k32_LoadLibraryA(const char *name)
{
    return load_module_by_name(name, 0);
}

static WN_API wn_handle k32_LoadLibraryW(const uint16_t *name)
{
    char *a = wn_utf16_to_utf8(name, 4096);
    if (!a)
        return NULL;
    wn_handle h = load_module_by_name(a, 0);
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
    void *fn;
    if ((uintptr_t)name & 0xFFFF0000ULL)
        fn = wn_module_get_proc(m, name, 0, 0);
    else
        fn = wn_module_get_proc_ordinal(m, (uint32_t)(uintptr_t)name);
    if (!fn) {
        wn_last_error_set(WN_ERR_PROC_NOT_FOUND);
        return NULL;
    }
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

static WN_API int32_t k32_GetExitCodeProcess(wn_handle h, uint32_t *code)
{
    (void)h;
    if (!code)
        return 0;
    *code = 259;
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
        exit((int)(int32_t)code);
    wn_log(WN_LOG_WARN, "kernel32: TerminateProcess(other) treated as exit");
    exit((int)(int32_t)code);
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

static WN_API void *k32_VirtualAlloc(void *addr, uint64_t size, uint32_t type,
                                     uint32_t prot)
{
    void *p = wn_virtual_alloc(addr, size, type, prot);
    if (!p)
        wn_last_error_set(WN_ERR_NOT_ENOUGH_MEMORY);
    return p;
}

static WN_API int32_t k32_VirtualFree(void *addr, uint64_t size, uint32_t type)
{
    if (!wn_virtual_free(addr, size, type)) {
        wn_last_error_set(WN_ERR_INVALID_PARAMETER);
        return 0;
    }
    return 1;
}

static WN_API int32_t k32_VirtualProtect(void *addr, uint64_t size, uint32_t prot,
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

static WN_API uint32_t k32_VirtualQuery(void *addr, void *mbi)
{
    return wn_virtual_query(addr, mbi) ? (uint32_t)sizeof(void *) * 6 : 0;
}

static WN_API wn_handle k32_GetProcessHeap(void)
{
    return g_proc.process_heap;
}

static WN_API void *k32_HeapAlloc(wn_handle heap, uint32_t flags, uint64_t size)
{
    (void)heap;
    if (size > 0x7FFFFFFF) {
        wn_last_error_set(WN_ERR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    void *p = (flags & 8 /* HEAP_ZERO_MEMORY */) ? calloc(1, (size_t)size)
                                                 : malloc((size_t)size);
    if (!p)
        wn_last_error_set(WN_ERR_NOT_ENOUGH_MEMORY);
    return p;
}

static WN_API void *k32_HeapReAlloc(wn_handle heap, uint32_t flags, void *ptr,
                                    uint64_t size)
{
    (void)heap;
    if (size > 0x7FFFFFFF) {
        wn_last_error_set(WN_ERR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    void *p = realloc(ptr, (size_t)size);
    if (p && (flags & 8) && ptr == NULL) {
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
    free(ptr);
    return 1;
}

static WN_API wn_handle k32_HeapCreate(uint32_t flags, uint64_t init, uint64_t max)
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

/* Global/Local: fixed allocations only (documented limitation). */
static WN_API void *k32_GlobalAlloc(uint32_t flags, uint64_t size)
{
    void *p = (flags & 0x40 /* GMEM_ZEROINIT */) ? calloc(1, (size_t)size)
                                                 : malloc((size_t)size);
    if (!p)
        wn_last_error_set(WN_ERR_NOT_ENOUGH_MEMORY);
    return p;
}

static WN_API void *k32_GlobalLock(wn_handle h)
{
    return (void *)(uintptr_t)h;
}

static WN_API int32_t k32_GlobalUnlock(wn_handle h)
{
    (void)h;
    return 1;
}

static WN_API uint64_t k32_GlobalSize(wn_handle h)
{
    return malloc_usable_size((void *)(uintptr_t)h);
}

static WN_API wn_handle k32_GlobalFree(wn_handle h)
{
    free((void *)(uintptr_t)h);
    return 0;
}

static WN_API void *k32_LocalAlloc(uint32_t flags, uint64_t size)
{
    return k32_GlobalAlloc(flags, size);
}

static WN_API wn_handle k32_LocalFree(wn_handle h)
{
    return k32_GlobalFree(h);
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
    teb->tls_array[idx] = (uint64_t)(uintptr_t)v;
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

static WN_API int32_t k32_DeleteFileA(const char *name)
{
    char host[1024];
    if (wn_path_resolve_ci(name, host, sizeof host) != 0) {
        wn_last_error_set(WN_ERR_FILE_NOT_FOUND);
        return 0;
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
        wn_last_error_set(WN_ERR_FILE_NOT_FOUND);
        return 0xFFFFFFFF;
    }
    struct stat st;
    if (stat(host, &st) != 0) {
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
        return (uint32_t)n;
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

static WN_API uint32_t k32_GetTempPathA(uint32_t cap, char *buf)
{
    const char *t = "C:\\windows\\temp\\";
    size_t n = strlen(t);
    if (cap < n + 1) {
        wn_last_error_set(WN_ERR_INSUFFICIENT_BUFFER);
        return (uint32_t)n;
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

static WN_API int32_t k32_FindClose(wn_handle h)
{
    return wn_handle_close(h);
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
                                                  const wn_handle *hs,
                                                  uint32_t wait_all, uint32_t ms)
{
    return wn_wait_multiple(count, hs, (int)wait_all, ms);
}

static WN_API uint32_t k32_WaitForMultipleObjectsEx(uint32_t count,
                                                    const wn_handle *hs,
                                                    uint32_t wait_all, uint32_t ms,
                                                    uint32_t alertable)
{
    (void)alertable;
    return wn_wait_multiple(count, hs, (int)wait_all, ms);
}

static WN_API void k32_InitializeCriticalSection(wn_critsect *cs)
{
    wn_critsect_init(cs, 0);
}

static WN_API int32_t k32_InitializeCriticalSectionAndSpinCount(wn_critsect *cs,
                                                                uint32_t spin)
{
    wn_critsect_init(cs, spin);
    return 1;
}

static WN_API void k32_EnterCriticalSection(wn_critsect *cs)
{
    wn_critsect_enter(cs);
}

static WN_API void k32_LeaveCriticalSection(wn_critsect *cs)
{
    wn_critsect_leave(cs);
}

static WN_API int32_t k32_TryEnterCriticalSection(wn_critsect *cs)
{
    return wn_critsect_try(cs);
}

static WN_API void k32_DeleteCriticalSection(wn_critsect *cs)
{
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

static WN_API int32_t k32_lstrcmpiA(const char *a, const char *b)
{
    for (const char *p = a ? a : "", *q = b ? b : ""; ; p++, q++) {
        int d = tolower((unsigned char)*p) - tolower((unsigned char)*q);
        if (d || !*p)
            return (d > 0) - (d < 0);
    }
}

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
    return g_proc.cmdline_utf8;
}

static WN_API const uint16_t *k32_GetCommandLineW(void)
{
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
    if (!v) {
        wn_last_error_set(203 /* ERROR_ENVVAR_NOT_FOUND */);
        return 0;
    }
    size_t n = strlen(v);
    if (!buf || cap < n + 1) {
        wn_last_error_set(WN_ERR_INSUFFICIENT_BUFFER);
        return (uint32_t)n;
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

static WN_API uint32_t k32_SetThreadAffinityMask(wn_handle h, uint64_t mask)
{
    (void)h;
    (void)mask;
    wn_log(WN_LOG_WARN, "kernel32: SetThreadAffinityMask ignored (no-op)");
    return (uint32_t)-1 & 0xFFFFFFFF;
}

static WN_API void k32_GetSystemInfo(void *si)
{
    /* SYSTEM_INFO x64: 48 bytes. */
    memset(si, 0, 48);
    uint8_t *p = si;
    *(uint32_t *)(p + 0) = 4096;
    *(uint64_t *)(p + 8) = 0x10000;
    *(uint64_t *)(p + 16) = 0x7FFFFFFEFFFFULL;
    *(uint64_t *)(p + 24) = (1ULL << g_proc.peb->number_of_processors) - 1;
    *(uint32_t *)(p + 32) = g_proc.peb->number_of_processors;
    *(uint32_t *)(p + 36) = 8664;      /* PROCESSOR_AMD_X8664 */
    *(uint32_t *)(p + 40) = 0x10000;   /* allocation granularity */
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
    (void)f;
    return 1;   /* optimistic for common features; honest caveat in STATUS */
}

static WN_API int32_t k32_Beep(uint32_t freq, uint32_t dur)
{
    (void)freq;
    (void)dur;
    return 1;
}

static WN_API void k32_RaiseException(uint32_t code, uint32_t flags,
                                      uint32_t nparams, const uint64_t *params)
{
    wn_seh_raise(code, flags, nparams, params);
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
    if ((int64_t)(uintptr_t)src == -1) {        /* current process */
        static int proc_obj;
        *out = wn_handle_alloc(WN_HTYPE_PROCESS, &proc_obj);
        return 1;
    }
    if ((int64_t)(uintptr_t)src == -2) {        /* current thread */
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

const wn_export_entry wn_kernel32_exports[] = {
    { "Beep", k32_Beep },
    { "CloseHandle", k32_CloseHandle },
    { "CopyFileA", k32_CopyFileA },
    { "CreateDirectoryA", k32_CreateDirectoryA },
    { "CreateEventA", k32_CreateEventA },
    { "CreateEventW", k32_CreateEventW },
    { "CreateFileA", k32_CreateFileA },
    { "CreateFileW", k32_CreateFileW },
    { "CreateMutexA", k32_CreateMutexA },
    { "CreateMutexW", k32_CreateMutexW },
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
    { "FindNextFileA", k32_FindNextFileA },
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
    { "GetVersionExA", k32_GetVersionExA },
    { "GetVolumeInformationA", k32_GetVolumeInformationA },
    { "GlobalAlloc", k32_GlobalAlloc },
    { "GlobalFree", k32_GlobalFree },
    { "GlobalLock", k32_GlobalLock },
    { "GlobalSize", k32_GlobalSize },
    { "GlobalUnlock", k32_GlobalUnlock },
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
    { "LoadLibraryA", k32_LoadLibraryA },
    { "LoadLibraryExA", k32_LoadLibraryExA },
    { "LoadLibraryW", k32_LoadLibraryW },
    { "LocalAlloc", k32_LocalAlloc },
    { "LocalFree", k32_LocalFree },
    { "lstrcmpA", k32_lstrcmpA },
    { "lstrcmpiA", k32_lstrcmpiA },
    { "lstrcpyA", k32_lstrcpyA },
    { "lstrcpynA", k32_lstrcpynA },
    { "lstrlenA", k32_lstrlenA },
    { "lstrlenW", k32_lstrlenW },
    { "MoveFileA", k32_MoveFileA },
    { "MultiByteToWideChar", k32_MultiByteToWideChar },
    { "OutputDebugStringA", k32_OutputDebugStringA },
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
    { "Sleep", k32_Sleep },
    { "SleepEx", k32_SleepEx },
    { "SuspendThread", k32_SuspendThread },
    { "SwitchToThread", k32_SwitchToThread },
    { "TerminateProcess", k32_TerminateProcess },
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
    { NULL, NULL },
};
