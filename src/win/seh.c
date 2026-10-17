/* seh.c — signals -> EXCEPTION_RECORD64 -> VEH dispatch -> crash report.
 *
 * Crash handling rules (honesty first):
 *  - faults whose RIP is inside guest modules are WinNux's business: report
 *    a Windows-style unhandled exception with module+RVA and exit 0xCxxxxxxx;
 *  - faults in host code are re-raised with the default handler so real
 *    WinNux bugs show up as host crashes (never masked).
 */
#include "wn_seh.h"
#include "wn_process.h"
#include "wn_module.h"
#include "wn_log.h"
#include "wn_util.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucontext.h>
#include <execinfo.h>

/* --- guest-visible exception structures (Windows x64 layout) ---------------- */

typedef struct {
    uint32_t exception_code;
    uint32_t exception_flags;
    uint64_t exception_record;
    uint64_t exception_address;
    uint32_t number_parameters;
    uint32_t __unused;
    uint64_t exception_information[15];
} wn_exc_record;   /* 0x98 bytes */

typedef struct {
    uint64_t p1home, p2home, p3home, p4home, p5home, p6home;
    uint32_t context_flags;
    uint32_t mxcsr;
    uint16_t seg_cs, seg_ds, seg_es, seg_fs, seg_gs, seg_ss;
    uint32_t eflags;
    uint64_t dr0, dr1, dr2, dr3, dr6, dr7;
    uint64_t rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
    uint64_t rip;
    uint8_t  fltsave[512];
    uint64_t vector_control, debug_control;
    uint64_t last_branch_to, last_branch_from;
    uint64_t last_exception_to, last_exception_from;
} wn_context64;   /* fields at Windows offsets (verified by asserts below) */

_Static_assert(offsetof(wn_context64, rax) == 0x78, "ctx");
_Static_assert(offsetof(wn_context64, rcx) == 0x80, "ctx");
_Static_assert(offsetof(wn_context64, rsp) == 0x98, "ctx");
_Static_assert(offsetof(wn_context64, rip) == 0xF8, "ctx");
_Static_assert(offsetof(wn_context64, fltsave) == 0x100, "ctx");

typedef struct {
    wn_exc_record *record;
    wn_context64 *context;
} wn_exc_pointers;

#define WN_EXC_CONT_SEARCH   0
#define WN_EXC_CONT_EXEC     (uint32_t)-1
#define WN_EXC_EXECUTE_HANDLER 1

/* --- VEH registry ------------------------------------------------------------ */

typedef struct veh_node {
    WN_API int64_t (*handler)(wn_exc_pointers *);
    struct veh_node *next;
} veh_node;

static veh_node *g_veh;                     /* documented global: VEH list */
static WN_API int64_t (*g_unhandled)(wn_exc_pointers *) = NULL;

void *wn_seh_veh_add(void *handler, int first)
{
    veh_node *n = wn_xcalloc(1, sizeof *n);
    n->handler = handler;
    if (first) {
        n->next = g_veh;
        g_veh = n;
    } else {
        veh_node **pp = &g_veh;
        while (*pp)
            pp = &(*pp)->next;
        *pp = n;
    }
    return n;
}

void wn_seh_veh_remove(void *registration)
{
    for (veh_node **pp = &g_veh; *pp; pp = &(*pp)->next) {
        if (*pp == registration) {
            *pp = (*pp)->next;
            free(registration);
            return;
        }
    }
}

void *wn_seh_set_unhandled_filter(void *filter)
{
    void *old = (void *)g_unhandled;
    g_unhandled = filter;
    return old;
}

/* --- dispatch ------------------------------------------------------------------ */

/* Returns 1 if a VEH handler continued execution (context patched). */
static int dispatch_veh(wn_exc_record *rec, wn_context64 *ctx, ucontext_t *uc)
{
    for (veh_node *n = g_veh; n; n = n->next) {
        wn_exc_pointers ep = { rec, ctx };
        int64_t r = n->handler(&ep);
        if (r == (int64_t)WN_EXC_CONT_EXEC) {
            /* Copy GPRs back so execution resumes modified. */
            uc->uc_mcontext.gregs[REG_RAX] = ctx->rax;
            uc->uc_mcontext.gregs[REG_RCX] = ctx->rcx;
            uc->uc_mcontext.gregs[REG_RDX] = ctx->rdx;
            uc->uc_mcontext.gregs[REG_RBX] = ctx->rbx;
            uc->uc_mcontext.gregs[REG_RSP] = ctx->rsp;
            uc->uc_mcontext.gregs[REG_RBP] = ctx->rbp;
            uc->uc_mcontext.gregs[REG_RSI] = ctx->rsi;
            uc->uc_mcontext.gregs[REG_RDI] = ctx->rdi;
            uc->uc_mcontext.gregs[REG_R8] = ctx->r8;
            uc->uc_mcontext.gregs[REG_R9] = ctx->r9;
            uc->uc_mcontext.gregs[REG_R10] = ctx->r10;
            uc->uc_mcontext.gregs[REG_R11] = ctx->r11;
            uc->uc_mcontext.gregs[REG_R12] = ctx->r12;
            uc->uc_mcontext.gregs[REG_R13] = ctx->r13;
            uc->uc_mcontext.gregs[REG_R14] = ctx->r14;
            uc->uc_mcontext.gregs[REG_R15] = ctx->r15;
            uc->uc_mcontext.gregs[REG_RIP] = ctx->rip;
            return 1;
        }
    }
    return 0;
}

static void fill_context(wn_context64 *ctx, const ucontext_t *uc)
{
    memset(ctx, 0, sizeof *ctx);
    ctx->context_flags = 0x10003F;
    ctx->mxcsr = 0x1F80;
    ctx->seg_cs = 0x33;
    ctx->seg_ss = 0x2B;
    ctx->eflags = (uint32_t)uc->uc_mcontext.gregs[REG_EFL];
    ctx->rax = uc->uc_mcontext.gregs[REG_RAX];
    ctx->rcx = uc->uc_mcontext.gregs[REG_RCX];
    ctx->rdx = uc->uc_mcontext.gregs[REG_RDX];
    ctx->rbx = uc->uc_mcontext.gregs[REG_RBX];
    ctx->rsp = uc->uc_mcontext.gregs[REG_RSP];
    ctx->rbp = uc->uc_mcontext.gregs[REG_RBP];
    ctx->rsi = uc->uc_mcontext.gregs[REG_RSI];
    ctx->rdi = uc->uc_mcontext.gregs[REG_RDI];
    ctx->r8 = uc->uc_mcontext.gregs[REG_R8];
    ctx->r9 = uc->uc_mcontext.gregs[REG_R9];
    ctx->r10 = uc->uc_mcontext.gregs[REG_R10];
    ctx->r11 = uc->uc_mcontext.gregs[REG_R11];
    ctx->r12 = uc->uc_mcontext.gregs[REG_R12];
    ctx->r13 = uc->uc_mcontext.gregs[REG_R13];
    ctx->r14 = uc->uc_mcontext.gregs[REG_R14];
    ctx->r15 = uc->uc_mcontext.gregs[REG_R15];
    ctx->rip = uc->uc_mcontext.gregs[REG_RIP];
    if (uc->uc_mcontext.fpregs)
        memcpy(ctx->fltsave, uc->uc_mcontext.fpregs, 512);
}

static const char *exc_name(uint32_t c)
{
    switch (c) {
    case 0xC0000005: return "EXCEPTION_ACCESS_VIOLATION";
    case 0xC000001D: return "EXCEPTION_ILLEGAL_INSTRUCTION";
    case 0xC0000094: return "EXCEPTION_INT_DIVIDE_BY_ZERO";
    case 0xC0000095: return "EXCEPTION_INT_OVERFLOW";
    case 0xC00000FD: return "EXCEPTION_STACK_OVERFLOW";
    case 0xC0000409: return "EXCEPTION_STACK_BUFFER_OVERRUN";
    default: return "EXCEPTION_UNKNOWN";
    }
}

/* Print a Windows-style crash report, then exit with the exception code. */
static __attribute__((noreturn)) void
crash_report(wn_exc_record *rec, wn_context64 *ctx)
{
    if (g_unhandled) {
        wn_exc_pointers ep = { rec, ctx };
        if (g_unhandled(&ep) == WN_EXC_EXECUTE_HANDLER)
            exit((int)rec->exception_code);
    }
    char where[96];
    wn_module_describe_addr((const void *)(uintptr_t)ctx->rip, where, sizeof where);
    wn_log(WN_LOG_ERR, "===== unhandled exception %s (0x%08X) at %s =====",
           exc_name(rec->exception_code), rec->exception_code, where);
    if (rec->exception_code == 0xC0000005 && rec->number_parameters >= 2)
        wn_log(WN_LOG_ERR, "  access %s at address 0x%llx",
               rec->exception_information[0] ? "write" : "read",
               (unsigned long long)rec->exception_information[1]);
    wn_log(WN_LOG_ERR, "  RAX=%016llx RCX=%016llx RDX=%016llx RBX=%016llx",
           (unsigned long long)ctx->rax, (unsigned long long)ctx->rcx,
           (unsigned long long)ctx->rdx, (unsigned long long)ctx->rbx);
    wn_log(WN_LOG_ERR, "  RSP=%016llx RBP=%016llx RSI=%016llx RDI=%016llx",
           (unsigned long long)ctx->rsp, (unsigned long long)ctx->rbp,
           (unsigned long long)ctx->rsi, (unsigned long long)ctx->rdi);
    wn_log(WN_LOG_ERR, "  R8 =%016llx R9 =%016llx R10=%016llx R11=%016llx",
           (unsigned long long)ctx->r8, (unsigned long long)ctx->r9,
           (unsigned long long)ctx->r10, (unsigned long long)ctx->r11);
    wn_log(WN_LOG_ERR, "  RIP=%016llx", (unsigned long long)ctx->rip);
    /* Frame-pointer backtrace (MSVC /Oy- builds): stop on anything that does
     * not look like a sane chain. Best-effort - we are already crashing. */
    {
        uint64_t rbp = ctx->rbp;
        for (int i = 0; i < 24 && rbp; i++) {
            if (rbp & 7 || rbp < 0x1000 || rbp - ctx->rbp > 0x400000ULL ||
                (i && rbp <= ctx->rbp + (uint64_t)i * 16))
                break;
            uint64_t ret = *(const uint64_t *)(const void *)(rbp + 8);
            if (!ret)
                break;
            char w[96];
            wn_module_describe_addr((const void *)(uintptr_t)ret, w, sizeof w);
            wn_log(WN_LOG_ERR, "  #%d from %s", i, w);
            uint64_t next = *(const uint64_t *)(const void *)rbp;
            if (next <= rbp)
                break;
            rbp = next;
        }
    }
    exit((int)rec->exception_code);
}

static void signal_handler(int sig, siginfo_t *si, void *uc_)
{
    ucontext_t *uc = uc_;
    wn_module *m = wn_module_from_addr((const void *)uc->uc_mcontext.gregs[REG_RIP], NULL);
    if (!m) {
        /* Fault inside host code: not ours to hide. Re-raise default. */
        wn_log(WN_LOG_ERR, "seh: host-side fault (SIG%d addr=%p ip=%p) — "
               "re-raising, this is a WinNux bug", sig, si->si_addr,
               (void *)uc->uc_mcontext.gregs[REG_RIP]);
        void *bt[16];
        int n = backtrace(bt, 16);
        char **sym = backtrace_symbols(bt, n);
        for (int i = 0; i < n && sym; i++)
            wn_log(WN_LOG_ERR, "  #%d %s", i, sym[i]);
        free(sym);
        signal(sig, SIG_DFL);
        raise(sig);
        return;
    }

    wn_exc_record rec;
    memset(&rec, 0, sizeof rec);
    switch (sig) {
    case SIGSEGV:
    case SIGBUS:
        rec.exception_code = 0xC0000005;
        rec.exception_information[0] = (si->si_code == SEGV_ACCERR ||
                                        si->si_code == BUS_ADRERR) ? 1 : 0;
        rec.exception_information[1] = (uint64_t)(uintptr_t)si->si_addr;
        rec.number_parameters = 2;
        break;
    case SIGFPE:
        rec.exception_code = si->si_code == FPE_INTDIV ? 0xC0000094 : 0xC0000095;
        rec.number_parameters = 0;
        break;
    case SIGILL:
        rec.exception_code = 0xC000001D;
        rec.number_parameters = 0;
        break;
    default:
        rec.exception_code = 0xC0000026; /* STATUS_NONCONTINUABLE_EXCEPTION */
        break;
    }
    rec.exception_address = uc->uc_mcontext.gregs[REG_RIP];

    wn_context64 ctx;
    fill_context(&ctx, uc);
    rec.exception_record = 0;

    if (dispatch_veh(&rec, &ctx, uc))
        return;   /* VEH continued execution */

    crash_report(&rec, &ctx);
}

void wn_seh_init(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = signal_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGFPE, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
}

void wn_seh_raise(uint32_t code, uint32_t flags, uint32_t nparams,
                  const uint64_t *params)
{
    wn_exc_record rec;
    memset(&rec, 0, sizeof rec);
    rec.exception_code = code;
    rec.exception_flags = flags;
    rec.number_parameters = nparams > 15 ? 15 : nparams;
    for (uint32_t i = 0; i < rec.number_parameters; i++)
        rec.exception_information[i] = params[i];

    ucontext_t uc;
    memset(&uc, 0, sizeof uc);   /* approximate context: raise site */
    wn_context64 ctx;
    fill_context(&ctx, &uc);
    ctx.rip = (uint64_t)(uintptr_t)__builtin_return_address(0);
    rec.exception_address = ctx.rip;

    if (dispatch_veh(&rec, &ctx, &uc))
        return;   /* VEH continued: exception swallowed (logged) */

    crash_report(&rec, &ctx);
}
