/* wn_process.c — process context: PEB/TEB, command line, environment, LDR
 * lists, futex helpers, process exit.
 */
#include "wn_process.h"
#include "wn_module.h"
#include <execinfo.h>
#include <dlfcn.h>
#include "wn_log.h"
#include "wn_util.h"
#include "wn_path.h"
#include "wn_registry.h"
#include "wn_wow64.h"

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

#if defined(__x86_64__)

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
    wn_tls_thread_register(teb);
    return teb;
}

#else /* i386 */

/* i386 TEB hosting: %fs must point at the TEB (guest code reads
 * fs:0x18 self, fs:0x2C TLS array, fs:0x30 PEB, fs:0x34 last error).
 * glibc owns %gs for its own TLS, so we use the LDT via modify_ldt
 * (the Wine i386 model): one LDT entry per thread, selector = (n<<3)|7
 * (LDT, RPL3). struct user_desc is defined inline (16 bytes, bitfields
 * exactly as the kernel uapi) to avoid an asm/ldt.h include dependency.
 * LDT entries are PROCESS-GLOBAL: the counter is mutex-guarded. */
struct wn_user_desc {
    uint32_t entry_number;
    uint32_t base_addr;
    uint32_t limit;
    uint32_t seg_32bit:1, contents:2, read_exec_only:1, limit_in_pages:1,
             seg_not_present:1, useable:1;
};

static uint32_t g_ldt_next;
static pthread_mutex_t g_ldt_lock = PTHREAD_MUTEX_INITIALIZER;

static int teb_load_fs(void *teb)
{
    struct wn_user_desc d;
    memset(&d, 0, sizeof d);
    pthread_mutex_lock(&g_ldt_lock);
    d.entry_number = g_ldt_next++;
    pthread_mutex_unlock(&g_ldt_lock);
    d.base_addr = (uint32_t)(uintptr_t)teb;
    d.limit = 0x2000 - 1;        /* TEB (0x400) + TLS array page */
    d.seg_32bit = 1;
    d.contents = 0;              /* data, grow-up */
    d.read_exec_only = 0;
    d.limit_in_pages = 0;        /* byte-granular limit */
    d.seg_not_present = 0;
    d.useable = 1;
    /* Kernel contract: modify_ldt(func=1 write) returns 0 on success and
     * -1/errno on failure — the byte count is only meaningful for func=0
     * (read). Comparing against sizeof d misread success (return 0) as
     * failure with errno==0 ("failed: Success") and aborted a perfectly
     * working TEB setup. Verified against 6.x kernels and qemu-i386. */
    if (syscall(SYS_modify_ldt, 1 /* write */, &d, sizeof d) != 0) {
        wn_log(WN_LOG_ERR, "teb: modify_ldt failed: %s", strerror(errno));
        return -1;
    }
    uint32_t sel = (uint32_t)((d.entry_number << 3) | 0x07); /* LDT | RPL3 */
    __asm__ volatile ("mov %0, %%eax\n\tmov %%ax, %%fs"
                      : : "r" (sel) : "eax");
    return 0;
}

wn_teb *wn_teb_attach(void)
{
    uint8_t *mem = mmap(NULL, 0x2000, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        wn_log(WN_LOG_ERR, "teb: mmap failed");
        abort();
    }
    wn_teb *teb = (wn_teb *)mem;
    memset(teb, 0, 0x400);
    teb->self = (wn_abiptr)(uintptr_t)teb;
    teb->tls_array = (wn_abiptr *)(mem + 0x1000);
    teb->exception_list = 0;
    teb->peb = g_proc.peb;
    teb->client_id_process = getpid();
    teb->client_id_thread = wn_alloc_tid();
    if (teb_load_fs(teb) != 0) {
        wn_log(WN_LOG_ERR, "teb: cannot load %%fs (32-bit TEB unavailable)");
        abort();
    }
    wn_tls_thread_register(teb);
    return teb;
}

#endif

wn_teb *wn_teb_current(void)
{
#if defined(__x86_64__)
    wn_teb *t;
    __asm__ volatile ("movq %%gs:0x30, %0" : "=r"(t));
    return t;
#else
    /* i386: TEB self-pointer at fs:0x18; wn_teb_attach() loads %fs from
     * an LDT entry, so this is the canonical fast path. */
    wn_teb *t = NULL;
    __asm__ volatile ("movl %%fs:0x18, %0" : "=r"(t));
    return t;
#endif
}

wn_thread *wn_thread_current(void)
{
    return (wn_thread *)(uintptr_t)wn_teb_current()->wn_thread;
}

uint32_t wn_last_error_get(void)
{
    if (g_wow64_active) {
        wn_wow64_thread *wt = wn_wow64_thread_current();
        if (wt)
            return *(uint32_t *)(wt->teb32 + 0x34);
    }
    return wn_teb_current()->last_error;
}
void wn_last_error_set(uint32_t e)
{
    if (g_wow64_active) {
        wn_wow64_thread *wt = wn_wow64_thread_current();
        if (wt) {
            *(uint32_t *)(wt->teb32 + 0x34) = e;
            return;
        }
    }
    wn_teb_current()->last_error = e;
}

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

/* Default prefix: $WINNUX_HOME/default, else ~/.WinNux/default (documented
 * environment layout; self-contained prefixes under one root). */
void wn_prefix_default(char *out, size_t cap)
{
    const char *home = getenv("WINNUX_HOME");
    if (home && *home) {
        snprintf(out, cap, "%s/default", home);
        return;
    }
    home = getenv("HOME");
    snprintf(out, cap, "%s/.WinNux/default", home ? home : "/tmp");
}

uint32_t wn_process_create(const char *prefix, const char *exe_display_name)
{
    memset(&g_proc, 0, sizeof g_proc);
    g_proc.pid = getpid();
    g_proc.process_heap = WN_PROCESS_HEAP_HANDLE;

    /* Prefix: --prefix arg > WINNUX_PREFIX env > WINNUX_HOME/default >
     * ~/.WinNux/default. */
    const char *p = prefix;
    char def[1024];
    if (!p || !*p)
        p = getenv("WINNUX_PREFIX");
    if (!p || !*p) {
        wn_prefix_default(def, sizeof def);
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
        wn_abiptr *heads[] = { (wn_abiptr *)g_proc.ldr->in_load_order,
                               (wn_abiptr *)g_proc.ldr->in_memory_order,
                               (wn_abiptr *)g_proc.ldr->in_init_order };
        for (int j = 0; j < 2; j++)
            heads[i][j] = (wn_abiptr)(uintptr_t)&heads[i][0];
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
