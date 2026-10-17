/* thread.c — guest thread lifecycle: pthread wrapper, TEB/GS setup, static
 * TLS blocks, suspend/resume via SIGUSR1, thread exit.
 */
#include "wn_process.h"
#include "wn_module.h"
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
    const wn_image_dos_header *dos = (const void *)m->pe.base;
    const wn_image_optional_header64 *oh =
        (const void *)(m->pe.base + dos->e_lfanew + 4 + sizeof(wn_image_file_header));
    const wn_image_data_directory *dir = &oh->dirs[WN_IMAGE_DIR_TLS];
    if (dir->virtual_address == 0 || dir->size < sizeof(wn_image_tls_directory64))
        return;
    const wn_image_tls_directory64 *tls = wn_pe_rva(&m->pe, dir->virtual_address, sizeof *tls);
    if (!tls)
        return;
    wn_tls_mod *tm = wn_xcalloc(1, sizeof *tm);
    tm->mod = m;
    tm->index = m->tls_index;
    /* Normalize VAs (images without relocs still work). */
    #define NORM(va) (((va) >= m->pe.preferred_base && \
                       (va) < m->pe.preferred_base + m->pe.size_of_image) \
                      ? (uint64_t)(uintptr_t)m->pe.base + ((va) - m->pe.preferred_base) \
                      : (va))
    tm->template_start = NORM(tls->start_address_of_raw_data);
    tm->template_end = NORM(tls->end_address_of_raw_data);
    tm->zero_fill = tls->size_of_zero_fill;
    #undef NORM
    pthread_mutex_lock(&g_tls_lock);
    tm->next = g_tls_mods;
    g_tls_mods = tm;
    pthread_mutex_unlock(&g_tls_lock);
    wn_log(WN_LOG_DEBUG, "tls: module '%s' index %u, template 0x%llx..0x%llx (+%u zero)",
           m->name, tm->index, (unsigned long long)tm->template_start,
           (unsigned long long)tm->template_end, tm->zero_fill);
}

void wn_tls_thread_init(wn_teb *teb)
{
    pthread_mutex_lock(&g_tls_lock);
    for (wn_tls_mod *tm = g_tls_mods; tm; tm = tm->next) {
        if (tm->index == 0 || tm->index >= 512)
            continue;
        size_t raw = 0;
        if (tm->template_end > tm->template_start)
            raw = (size_t)(tm->template_end - tm->template_start);
        size_t sz = (raw + tm->zero_fill + 15) & ~15ULL;
        void *block = wn_xcalloc(1, sz + 8);
        if (raw && tm->template_start)
            memcpy(block, (const void *)(uintptr_t)tm->template_start, raw);
        teb->tls_array[tm->index] = (uint64_t)(uintptr_t)block;
    }
    pthread_mutex_unlock(&g_tls_lock);
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
