/* wn_process.c — process context: PEB/TEB, command line, environment, LDR
 * lists, futex helpers, process exit.
 */
#include "wn_process.h"
#include "wn_module.h"
#include "wn_log.h"
#include "wn_util.h"
#include "wn_path.h"
#include "wn_registry.h"

#include <errno.h>
#include <stdio.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

/* Documented global: the single process context. */
wn_process g_proc;

/* Magic opaque value returned by GetProcessHeap/PEB->ProcessHeap. HeapAlloc
 * etc. treat it as "the process heap" (backed by malloc). */
#define WN_PROCESS_HEAP_HANDLE ((void *)(uintptr_t)0x00110000ULL)

/* --- TEB -------------------------------------------------------------------- */

wn_teb *wn_teb_attach(void)
{
    /* TEB (0x400 bytes) + TLS pointer array (512 slots) in one mapping. */
    uint8_t *mem = mmap(NULL, 0x2000, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        wn_log(WN_LOG_ERR, "teb: mmap failed");
        abort();
    }
    wn_teb *teb = (wn_teb *)mem;
    memset(teb, 0, 0x400);
    teb->self = (uint64_t)(uintptr_t)teb;
    teb->tls_array = (uint64_t *)(mem + 0x1000);
    teb->exception_list = 0;
    teb->peb = g_proc.peb;
    teb->client_id_process = getpid();
    teb->client_id_thread = wn_alloc_tid();
    if (syscall(SYS_arch_prctl, 0x1001 /* ARCH_SET_GS */, teb) != 0) {
        wn_log(WN_LOG_ERR, "teb: ARCH_SET_GS failed: %s", strerror(errno));
        abort();
    }
    return teb;
}

wn_teb *wn_teb_current(void)
{
    wn_teb *t;
    __asm__ volatile ("movq %%gs:0x30, %0" : "=r"(t));
    return t;
}

wn_thread *wn_thread_current(void)
{
    return (wn_thread *)(uintptr_t)wn_teb_current()->wn_thread;
}

uint32_t wn_last_error_get(void)  { return wn_teb_current()->last_error; }
void wn_last_error_set(uint32_t e) { wn_teb_current()->last_error = e; }

uint32_t wn_alloc_tid(void)
{
    return (uint32_t)syscall(SYS_gettid) ? (uint32_t)syscall(SYS_gettid)
                                         : ++g_proc.next_tid;
}

/* --- futex wrappers --------------------------------------------------------- */

int wn_futex_wait(uint32_t *addr, uint32_t expected, const struct timespec *abs_ts)
{
    long op;
    struct timespec rel;
    if (abs_ts) {
        op = 9 /* FUTEX_WAIT_BITSET */ | 256 /* FUTEX_CLOCK_MONOTONIC */;
        return (int)syscall(SYS_futex, addr, op, expected, abs_ts, NULL,
                            0xFFFFFFFFu);
    }
    op = 0 /* FUTEX_WAIT */;
    return (int)syscall(SYS_futex, addr, op, expected, &rel, NULL, 0);
}

int wn_futex_wake(uint32_t *addr, int n)
{
    return (int)syscall(SYS_futex, addr, 1 /* FUTEX_WAKE */, n, NULL, NULL, 0);
}

/* --- process create --------------------------------------------------------- */

uint32_t wn_process_create(const char *prefix, const char *exe_display_name)
{
    memset(&g_proc, 0, sizeof g_proc);
    g_proc.pid = getpid();
    g_proc.process_heap = WN_PROCESS_HEAP_HANDLE;

    /* Prefix: WINNUX_PREFIX, else ~/.winnux/default. */
    const char *p = prefix;
    char def[1024];
    if (!p || !*p) {
        const char *home = getenv("HOME");
        snprintf(def, sizeof def, "%s/.winnux/default", home ? home : "/tmp");
        p = def;
    }
    snprintf(g_proc.prefix, sizeof g_proc.prefix, "%s", p);

    /* Time basis. */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    g_proc.start_time_ft = (uint64_t)ts.tv_sec * 10000000ULL
                           + (uint64_t)ts.tv_nsec / 100 + WN_FILETIME_UNIX_OFFSET;

    /* PEB + params + LDR skeletons. */
    g_proc.peb = wn_xcalloc(1, sizeof(wn_peb));
    g_proc.params = wn_xcalloc(1, sizeof(wn_rtl_user_process_parameters));
    g_proc.ldr = wn_xcalloc(1, sizeof(wn_peb_ldr_data));
    g_proc.peb_lock = wn_xcalloc(1, sizeof(wn_critsect));
    g_proc.peb_lock->lock_count = -1;

    g_proc.peb->being_debugged = 0;
    g_proc.peb->ldr = g_proc.ldr;
    g_proc.peb->process_parameters = g_proc.params;
    g_proc.peb->process_heap = (uint64_t)(uintptr_t)WN_PROCESS_HEAP_HANDLE;
    g_proc.peb->fast_peb_lock = g_proc.peb_lock;
    g_proc.peb->number_of_processors =
        (uint32_t)(sysconf(_SC_NPROCESSORS_ONLN) > 0 ? sysconf(_SC_NPROCESSORS_ONLN) : 1);
    g_proc.peb->nt_global_flag = 0;

    g_proc.ldr->length = sizeof(wn_peb_ldr_data);
    g_proc.ldr->initialized = 1;
    for (int i = 0; i < 3; i++) {
        uint64_t *heads[] = { g_proc.ldr->in_load_order,
                              g_proc.ldr->in_memory_order,
                              g_proc.ldr->in_init_order };
        for (int j = 0; j < 2; j++)
            heads[i][j] = (uint64_t)(uintptr_t)&heads[i][0];
    }

    g_proc.params->maximum_length = sizeof(wn_rtl_user_process_parameters);
    g_proc.params->length = sizeof(wn_rtl_user_process_parameters);
    g_proc.params->flags = 0x4001; /* RTL_USER_PROC_PARAMS_NORMALIZED-ish */

    /* Environment block (UTF-16) + UTF-8 copy. */
    extern char **environ;
    static const char *defaults[] = {
        "SystemRoot=C:\\windows",
        "SystemDrive=C:",
        "TEMP=C:\\windows\\temp",
        "TMP=C:\\windows\\temp",
        "PATHEXT=.COM;.EXE;.BAT;.CMD",
        NULL,
    };
    wn_buf env16;
    wn_buf_init(&env16);
    for (int d = 0; defaults[d]; d++) {
        uint16_t *w = wn_utf8_to_utf16(defaults[d], NULL);
        if (w) {
            size_t l = 0;
            while (w[l]) l++;
            wn_buf_append(&env16, w, (l + 1) * 2);
            free(w);
        }
    }
    size_t nenv = 0;
    for (char **e = environ; e && *e; e++) nenv++;
    char **v = wn_xmalloc((nenv + 8) * sizeof(char *));
    size_t i = 0;
    for (int d = 0; defaults[d]; d++)
        v[i++] = (char *)defaults[d];
    for (char **e = environ; e && *e; e++) {
        if (!wn_strcaseprefix(*e, "WINNUX_")) {  /* hide our own knobs */
            v[i++] = *e;
            uint16_t *w = wn_utf8_to_utf16(*e, NULL);
            if (w) {
                size_t l = 0;
                while (w[l]) l++;
                wn_buf_append(&env16, w, (l + 1) * 2);
                free(w);
            }
        }
    }
    v[i] = NULL;
    wn_buf_append(&env16, "\0\0", 2);
    g_proc.env_utf16 = (uint16_t *)env16.data;
    g_proc.env_utf8 = v;
    g_proc.params->environment = g_proc.env_utf16;

    /* Set this (launcher) thread up with a TEB so early logging/stub code
     * can always use TEB fields. The guest runs on threads created later. */
    wn_teb_attach();
    (void)exe_display_name;
    return 0;
}

/* Command line: Windows-style argv[0] = display name (e.g. C:\...\t01.exe). */
void wn_process_set_cmdline(int argc, char **argv)
{
    wn_buf b;
    wn_buf_init(&b);
    for (int i = 0; i < argc; i++) {
        if (i) wn_buf_append(&b, " ", 1);
        const char *a = argv[i];
        int space = strpbrk(a, " \t") != NULL;
        if (space) wn_buf_append(&b, "\"", 1);
        wn_buf_append_str(&b, a);
        if (space) wn_buf_append(&b, "\"", 1);
    }
    wn_buf_append(&b, "\0", 1);
    g_proc.cmdline_utf8 = (char *)b.data;

    uint16_t *w = wn_utf8_to_utf16(g_proc.cmdline_utf8, NULL);
    g_proc.cmdline_utf16 = w ? w : wn_xcalloc(1, 2);

    g_proc.params->command_line.length = (uint16_t)(strlen(g_proc.cmdline_utf8) * 2);
    g_proc.params->command_line.maximum_length =
        g_proc.params->command_line.length + 2;
    g_proc.params->command_line.buffer = g_proc.cmdline_utf16;

    char wpath[1024];
    wn_path_host_to_win(argv[0], wpath, sizeof wpath);
    uint16_t *img = wn_utf8_to_utf16(wpath, NULL);
    if (img) {
        size_t l = 0;
        while (img[l]) l++;
        g_proc.params->image_path_name.length = (uint16_t)(l * 2);
        g_proc.params->image_path_name.maximum_length = (uint16_t)(l * 2 + 2);
        g_proc.params->image_path_name.buffer = img;
    }

    /* Current directory (UTF-16). */
    char cwd[1024];
    wn_path_get_cwd_win(cwd, sizeof cwd);
    uint16_t *cwdw = wn_utf8_to_utf16(cwd, NULL);
    if (cwdw) {
        size_t l = 0;
        while (cwdw[l]) l++;
        g_proc.params->current_directory.length = (uint16_t)(l * 2);
        g_proc.params->current_directory.maximum_length = (uint16_t)(l * 2 + 2);
        g_proc.params->current_directory.buffer = cwdw;
    }
}

/* Note the exe module once loaded (fills PEB ImageBaseAddress). */
void wn_process_note_exe(struct wn_module *m)
{
    g_proc.exe = m;
    g_proc.peb->image_base_address = (uint64_t)(uintptr_t)m->base;
}

/* --- process exit ----------------------------------------------------------- */

int wn_process_atexit(void (*fn)(void))
{
    if (g_proc.atexit_count >= 64)
        return 0;
    g_proc.atexit_fns[g_proc.atexit_count++] = fn;
    return 1;
}

void wn_process_exit(int code)
{
    wn_log(WN_LOG_DEBUG, "process exit code %d", code);
    /* msvcrt atexit handlers. */
    for (int i = g_proc.atexit_count - 1; i >= 0; i--)
        g_proc.atexit_fns[i]();
    /* Registry persistence. */
    wn_registry_save();
    exit(code);
}
