/* thread.c — guest thread lifecycle: pthread wrapper, TEB/GS setup, static
 * TLS blocks, suspend/resume via SIGUSR1, thread exit.
 */
#include "wn_process.h"
#include "wn_wow64.h"
#include "wn_module.h"
#include "wn_pe.h"
#include "wn_log.h"
#include "wn_util.h"
#include "wn_handle.h"
#include "wn_seh.h"

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <ucontext.h>

/* Static TLS registry: modules with TLS directories, template ranges. */
typedef struct wn_tls_mod {
    struct wn_module *mod;
    uint64_t template_start, template_end;  /* guest VAs */
    uint32_t zero_fill;
    uint32_t index;
    struct wn_tls_mod *next;
} wn_tls_mod;

static wn_tls_mod *g_tls_mods;          /* documented global: grows with modules */
static pthread_mutex_t g_tls_lock = PTHREAD_MUTEX_INITIALIZER;

/* Registry of live TEBs. Windows loader contract: when a module with static
 * TLS loads, EVERY existing thread immediately gets a TLS block for it
 * (future threads get theirs at wn_teb_attach -> wn_tls_thread_register).
 * TEBs are never unmapped (thread exit keeps the mapping), so nodes stay
 * valid for the process lifetime. */
typedef struct wn_tls_teb_node {
    wn_teb *teb;
    struct wn_tls_teb_node *next;
} wn_tls_teb_node;

static wn_tls_teb_node *g_tls_tebs;

/* Allocate the per-thread block for one module into a TEB that lacks it. */
static void tls_alloc_block(wn_teb *teb, const wn_tls_mod *tm)
{
    if (tm->index == 0 || tm->index >= 512)
        return;
    if (teb->tls_array[tm->index] != 0)
        return;                          /* block already present */
    size_t raw = 0;
    if (tm->template_end > tm->template_start)
        raw = (size_t)(tm->template_end - tm->template_start);
    size_t sz = (raw + tm->zero_fill + 15) & ~15ULL;
    void *block;
    if (g_wow64_active) {
        /* 32-bit guest (in-process wow64): the TLS block MUST live below
         * 4GB, and the guest reads it through fs:[0x2C] -> TEB32 slots.
         * The 64-bit TEB keeps the mirror for our own Tls* impls. This is
         * the exe+0x4325 "NULL static-TLS block" crash (guest writes
         * [block+4] with block == NULL). */
        wn_wow64_thread *wt = (wn_wow64_thread *)(uintptr_t)
            *(volatile uint64_t *)((uint8_t *)teb + 0xE8);
        if (!wt || !wt->teb32)
            return;                      /* thread not wow64-hosted yet */
        uint32_t *slots32 = (uint32_t *)(wt->teb32 + 0xE10);
        if (tm->index >= 64)
            return;                      /* TEB32 has 64 slots (+expansion) */
        if (slots32[tm->index] != 0)
            return;
        block = wn_low_malloc(sz + 8);
        if (!block)
            return;
        memset(block, 0, sz + 8);
        if (raw && tm->template_start)
            memcpy(block, (const void *)(uintptr_t)tm->template_start, raw);
        slots32[tm->index] = (uint32_t)(uintptr_t)block;
        teb->tls_array[tm->index] = (wn_abiptr)(uintptr_t)block;
        return;
    }
    block = wn_xcalloc(1, sz + 8);
    if (raw && tm->template_start)
        memcpy(block, (const void *)(uintptr_t)tm->template_start, raw);
    teb->tls_array[tm->index] = (wn_abiptr)(uintptr_t)block;
}

struct thread_start_ctx {
    WN_API uint64_t (*start)(uint64_t);
    uint64_t param;
    wn_thread *th;
};

/* --- static TLS -------------------------------------------------------------- */

void wn_tls_register_module(struct wn_module *m)
{
    if (m->kind != WN_MOD_PE)
        return;
    /* Arch-correct data-directory access: PE32 and PE32+ keep the directory
     * table at different optional-header offsets (96 vs 112). The old code
     * unconditionally used the 64-bit overlay, so 32-bit images read a
     * garbage TLS directory and silently never registered. */
    const wn_image_data_directory *dirs = wn_pe_dirs(&m->pe);
    const wn_image_data_directory *dir = &dirs[WN_IMAGE_DIR_TLS];
    if (dir->virtual_address == 0)
        return;
    uint64_t ts = 0, te = 0;
    uint32_t zero = 0;
    if (m->pe.is_64) {
        if (dir->size < sizeof(wn_image_tls_directory64)) {
            wn_log(WN_LOG_WARN, "tls: '%s' TLS dir size 0x%x < PE32+ minimum - "
                   "static TLS NOT installed (expect guest crashes)",
                   m->name, dir->size);
            return;
        }
        const wn_image_tls_directory64 *tls =
            wn_pe_rva(&m->pe, dir->virtual_address, sizeof *tls);
        if (!tls) {
            wn_log(WN_LOG_WARN, "tls: '%s' TLS dir RVA 0x%x unmapped - static "
                   "TLS NOT installed", m->name, dir->virtual_address);
            return;
        }
        ts = tls->start_address_of_raw_data;
        te = tls->end_address_of_raw_data;
        zero = tls->size_of_zero_fill;
    } else {
        if (dir->size < sizeof(wn_image_tls_directory32)) {
            wn_log(WN_LOG_WARN, "tls: '%s' TLS dir size 0x%x < PE32 minimum - "
                   "static TLS NOT installed (expect guest crashes)",
                   m->name, dir->size);
            return;
        }
        const wn_image_tls_directory32 *tls =
            wn_pe_rva(&m->pe, dir->virtual_address, sizeof *tls);
        if (!tls) {
            wn_log(WN_LOG_WARN, "tls: '%s' TLS dir RVA 0x%x unmapped - static "
                   "TLS NOT installed", m->name, dir->virtual_address);
            return;
        }
        ts = tls->start_address_of_raw_data;
        te = tls->end_address_of_raw_data;
        zero = tls->size_of_zero_fill;
    }
    wn_tls_mod *tm = wn_xcalloc(1, sizeof *tm);
    tm->mod = m;
    tm->index = m->tls_index;
    /* Normalize VAs (images without relocs still work). */
    #define NORM(va) (((va) >= m->pe.preferred_base && \
                       (va) < m->pe.preferred_base + m->pe.size_of_image) \
                      ? (uint64_t)(uintptr_t)m->pe.base + ((va) - m->pe.preferred_base) \
                      : (va))
    tm->template_start = NORM(ts);
    tm->template_end = NORM(te);
    tm->zero_fill = zero;
    #undef NORM
    pthread_mutex_lock(&g_tls_lock);
    tm->next = g_tls_mods;
    g_tls_mods = tm;
    /* Backfill every live TEB, including the main thread's (its init ran
     * before any module existed). */
    for (wn_tls_teb_node *n = g_tls_tebs; n; n = n->next)
        tls_alloc_block(n->teb, tm);
    pthread_mutex_unlock(&g_tls_lock);
    wn_log(WN_LOG_DEBUG, "tls: module '%s' index %u, template 0x%llx..0x%llx (+%u zero)",
           m->name, tm->index, (unsigned long long)tm->template_start,
           (unsigned long long)tm->template_end, tm->zero_fill);
}

void wn_tls_thread_register(wn_teb *teb)
{
    pthread_mutex_lock(&g_tls_lock);
    wn_tls_teb_node *n = wn_xcalloc(1, sizeof *n);
    n->teb = teb;
    n->next = g_tls_tebs;
    g_tls_tebs = n;
    for (wn_tls_mod *tm = g_tls_mods; tm; tm = tm->next)
        tls_alloc_block(teb, tm);
    pthread_mutex_unlock(&g_tls_lock);
}

void wn_tls_thread_init(wn_teb *teb)
{
    pthread_mutex_lock(&g_tls_lock);
    for (wn_tls_mod *tm = g_tls_mods; tm; tm = tm->next)
        tls_alloc_block(teb, tm);
    pthread_mutex_unlock(&g_tls_lock);
}

int wn_tls_ensure_current(struct wn_module *m)
{
    if (!m || m->tls_index == 0 || m->tls_index >= 512)
        return 0;
    int repaired = 0;
    pthread_mutex_lock(&g_tls_lock);
    wn_tls_mod *tm = NULL;
    for (wn_tls_mod *t = g_tls_mods; t; t = t->next)
        if (t->mod == m) { tm = t; break; }
    if (tm) {
        wn_teb *teb = wn_teb_current();
        int known = 0;
        for (wn_tls_teb_node *n = g_tls_tebs; n; n = n->next)
            if (n->teb == teb) { known = 1; break; }
        if (!known) {
            /* %fs:0x18 resolving to something other than a registered TEB
             * would mean TEB hosting itself is broken on this machine -
             * DO NOT write through it (unknown memory); say it loudly. */
            wn_log(WN_LOG_ERR, "tls: %%fs:0x18 -> %p is not a registered "
                   "TEB - guest TLS state broken, refusing blind repair",
                   (void *)teb);
        } else if (teb->tls_array[m->tls_index] == 0) {
            tls_alloc_block(teb, tm);
            repaired = 1;
        }
    }
    pthread_mutex_unlock(&g_tls_lock);
    return repaired;
}

/* --- suspend/resume (SIGUSR1) ----------------------------------------------
 * The handler blocks in a futex loop; the thread is "suspended" from the
 * moment it enters the handler. Known race (documented): a thread already
 * inside a syscall suspends on return. Good enough for CRT/loader use.
 */
static void wn_suspend_handler(int sig)
{
    (void)sig;
    wn_thread *th = wn_thread_current();
    if (!th)
        return;
    while (__atomic_load_n(&th->suspended, __ATOMIC_ACQUIRE)) {
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 20000000 };
        nanosleep(&ts, NULL);
    }
}

/* --- thread trampoline ------------------------------------------------------ */

static void *wn_thread_trampoline(void *arg)
{
    struct thread_start_ctx ctx = *(struct thread_start_ctx *)arg;
    free(arg);

    wn_thread *th = ctx.th;
    wn_teb *teb = wn_teb_attach();
    teb->wn_thread = (uint64_t)(uintptr_t)th;
    th->teb = teb;
    th->tid = (uint32_t)syscall(SYS_gettid);
    teb->client_id_thread = th->tid;

    /* Real stack bounds for the TEB. */
    pthread_attr_t attr;
    if (pthread_getattr_np(pthread_self(), &attr) == 0) {
        void *stk;
        size_t sz;
        if (pthread_attr_getstack(&attr, &stk, &sz) == 0) {
            th->stack_low = (uint64_t)(uintptr_t)stk;
            th->stack_high = (uint64_t)(uintptr_t)stk + sz;
            teb->stack_base = th->stack_high - 64;
            teb->stack_limit = th->stack_low;
        }
        pthread_attr_destroy(&attr);
    }

    /* Alt signal stack for SEH crash reporting on small thread stacks. */
    th->altstack = wn_xmalloc(SIGSTKSZ);
    stack_t ss = { .ss_sp = th->altstack, .ss_size = SIGSTKSZ, .ss_flags = 0 };
    sigaltstack(&ss, NULL);

    wn_tls_thread_init(teb);

    if (th->suspended) {
        wn_log(WN_LOG_DEBUG, "thread %u: created suspended", th->tid);
        while (__atomic_load_n(&th->suspended, __ATOMIC_ACQUIRE))
            wn_futex_wait((uint32_t *)&th->suspended, 1, NULL);
    }

    wn_log(WN_LOG_TRACE, "thread %u entering start 0x%llx", th->tid,
           (unsigned long long)(uintptr_t)ctx.start);
    uint64_t rv = ctx.start(ctx.param);
    wn_fls_run_callbacks();
    wn_thread_exit((uint32_t)rv);
}

/* --- creation ---------------------------------------------------------------- */

uint32_t wn_thread_create(uint64_t stack_reserve, WN_API uint64_t (*start)(uint64_t),
                          uint64_t param, int create_suspended,
                          wn_thread **out, wn_handle *out_handle)
{
    static int suspend_installed = 0;
    if (!suspend_installed) {
        struct sigaction sa = { 0 };
        sa.sa_handler = wn_suspend_handler;
        sa.sa_flags = 0;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGUSR1, &sa, NULL);
        suspend_installed = 1;
    }

    wn_thread *th = wn_xcalloc(1, sizeof *th);
    th->suspended = create_suspended ? 1 : 0;

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    size_t stack = stack_reserve ? (size_t)stack_reserve : 0x100000; /* 1MB default */
    if (stack < 0x40000)
        stack = 0x40000;
    stack = (stack + 0xFFF) & ~0xFFFULL;
    stack += 0x10000; /* headroom for TEB/arg traffic + guard page */
    pthread_attr_setstacksize(&attr, stack);

    struct thread_start_ctx *ctx = wn_xmalloc(sizeof *ctx);
    ctx->start = start;
    ctx->param = param;
    ctx->th = th;

    int rc = pthread_create(&th->pthread, &attr, wn_thread_trampoline, ctx);
    pthread_attr_destroy(&attr);
    if (rc != 0) {
        wn_log(WN_LOG_ERR, "CreateThread: pthread_create failed: %s", strerror(rc));
        free(th);
        wn_last_error_set(WN_ERR_NOT_ENOUGH_MEMORY);
        return 0;
    }
    if (out)
        *out = th;
    if (out_handle)
        *out_handle = wn_handle_alloc(WN_HTYPE_THREAD, th);
    return 1;
}

/* Suspend: returns previous suspend count (0 if was running), 0xFFFFFFFF on
 * failure (no thread found). */
uint32_t wn_thread_suspend(wn_thread *th)
{
    if (!th)
        return 0xFFFFFFFF;
    int prev = __atomic_fetch_add(&th->suspended, 1, __ATOMIC_ACQ_REL);
    if (prev == 0)
        pthread_kill(th->pthread, SIGUSR1);
    return (uint32_t)prev;
}

uint32_t wn_thread_resume(wn_thread *th)
{
    if (!th)
        return 0xFFFFFFFF;
    int prev = __atomic_fetch_sub(&th->suspended, 1, __ATOMIC_ACQ_REL);
    if (prev <= 0) {
        /* Resume on a running thread: restore count, fail like Windows. */
        __atomic_fetch_add(&th->suspended, 1, __ATOMIC_ACQ_REL);
        wn_last_error_set(WN_ERR_GEN_FAILURE);
        return 0xFFFFFFFF;
    }
    return (uint32_t)(prev - 1);
}

void wn_thread_exit(uint32_t code)
{
    wn_thread *th = wn_thread_current();
    if (th) {
        th->exit_code = code;
        th->exited = 1;
    }
    pthread_exit(NULL);
    __builtin_unreachable();
}
