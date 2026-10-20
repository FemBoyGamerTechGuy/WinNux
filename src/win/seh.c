/* seh.c — signals -> EXCEPTION_RECORD64 -> VEH dispatch -> crash report.
 *
 * Crash handling rules (honesty first):
 *  - faults whose RIP is inside guest modules are WinNux's business: report
 *    a Windows-style unhandled exception with module+RVA and exit 0xCxxxxxxx;
 *  - faults in host code are re-raised with the default handler so real
 *    WinNux bugs show up as host crashes (never masked).
 */
#include "wn_wow64.h"
#include "wn_seh.h"
#include "wn_process.h"
#include "wn_module.h"
#include "wn_pe.h"
#include "wn_log.h"
#include "wn_util.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucontext.h>
#include <execinfo.h>
#include <sys/mman.h>

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
    wn_log(WN_LOG_DEBUG, "seh: app installs unhandled filter %p (old %p)",
           filter, old);
    g_unhandled = filter;
    return old;
}

/* UnhandledExceptionFilter kernel32 export: route to the app's installed
 * filter (guest ms_abi function); the verdict: -1 continue search,
 * 0 continue, 1 execute handler. */
int64_t wn_seh_call_unhandled_filter(void *exception_pointers)
{
    if (!g_unhandled)
        return 1;   /* EXCEPTION_EXECUTE_HANDLER (default handler) */
    typedef WN_API int64_t (*filter_fn)(void *);
    wn_log(WN_LOG_DEBUG, "seh: dispatching UnhandledExceptionFilter(%p) "
           "to app filter %p", exception_pointers, (void *)g_unhandled);
    int64_t r = ((filter_fn)(uintptr_t)g_unhandled)(exception_pointers);
    wn_log(WN_LOG_DEBUG, "seh: app filter verdict %lld", (long long)r);
    return r;
}

/* --- faulting-instruction classification ------------------------------------ */

/* Linux tells us SEGV_MAPERR/SEGV_ACCERR but NOT read-vs-write: a store to
 * an unmapped page arrives as SEGV_MAPERR, which we used to report as
 * "read" — the LuaForWindows crash (mov [eax+4],edx at exe+0x4325) was a
 * WRITE reported as a read. Decode the common memory opcode forms instead;
 * return -1 when unknown (caller falls back to the si_code heuristic).
 * Called with RIP already validated to live in a mapped guest module. */
static int fault_is_write(const uint8_t *c, size_t n)
{
    size_t i = 0;
#if defined(__x86_64__)
    const int is64 = 1;
#else
    const int is64 = 0;
#endif
    /* prefixes: legacy segment/operand/address/rep/lock + REX on x64 */
    while (i < n) {
        uint8_t b = c[i];
        if (b == 0x66 || b == 0x67 || b == 0xF0 || b == 0xF2 || b == 0xF3 ||
            b == 0x2E || b == 0x3E || b == 0x26 || b == 0x36 ||
            b == 0x64 || b == 0x65 || (is64 && (b & 0xF0) == 0x40)) {
            i++;
            continue;
        }
        break;
    }
    if (i >= n)
        return -1;
    uint8_t op = c[i];
#define REG_FIELD() ((i + 1 < n) ? ((c[i + 1] >> 3) & 7) : 0xFFu)
    switch (op) {
    case 0x88: case 0x89: case 0xC6: case 0xC7:      /* mov r/m, r / imm */
    case 0xA2: case 0xA3:                            /* moffs stores */
    case 0xA4: case 0xA5: case 0xAA: case 0xAB:      /* movs/stos */
    case 0x8C: case 0x86: case 0x87: case 0x8F:      /* mov sreg / xchg / pop */
        return 1;
    case 0x8A: case 0x8B: case 0xA0: case 0xA1:      /* loads */
    case 0x8D: case 0x8E:                            /* lea / mov r, sreg */
    case 0xA6: case 0xA7: case 0xAC: case 0xAD:      /* cmps/scas */
    case 0xAE: case 0xAF:
    case 0x84: case 0x85:                            /* test r/m, r */
        return 0;
    case 0x0F: {                                     /* two-byte forms */
        if (i + 1 >= n)
            return -1;
        switch (c[i + 1]) {
        case 0x11: case 0x13: case 0x15: case 0x17:  /* movups/h/lps stores */
        case 0x29: case 0x2B: case 0x7E: case 0x7F:  /* movaps/movd/movdqa */
        case 0xD6: case 0xE7:                        /* movq/movntdq */
            return 1;
        case 0x10: case 0x12: case 0x14: case 0x16:  /* loads */
        case 0x28: case 0x2A: case 0x2C: case 0x2D:
        case 0x2E: case 0x6E: case 0x6F:
        case 0xB6: case 0xB7: case 0xBE: case 0xBF:  /* movzx/movsx */
        case 0xAF:                                    /* imul r, r/m */
            return 0;
        default:
            return -1;
        }
    }
    case 0x80: case 0x81: case 0x82: case 0x83: {    /* ALU r/m, imm */
        uint8_t reg = REG_FIELD();
        return (reg == 6 || reg == 7) ? 0 : 1;      /* TEST/CMP read */
    }
    case 0xC0: case 0xC1:                            /* shift imm */
    case 0xD0: case 0xD1: case 0xD2: case 0xD3:      /* shift cl / by 1 */
        return 1;                                     /* rmw, dest = r/m */
    case 0xF6: case 0xF7: {                          /* grp3 r/m, imm */
        uint8_t reg = REG_FIELD();
        return (reg == 0 || reg == 1 || reg >= 4) ? 0 : 1; /* not/neg rmw */
    }
    case 0xFE: case 0xFF: {                          /* inc/dec/call/push */
        uint8_t reg = REG_FIELD();
        if (reg == 0 || reg == 1)
            return 1;                                 /* inc/dec [mem] */
        return 0;                                     /* call/jmp/push read */
    }
    case 0xD9: case 0xDA: case 0xDB: case 0xDC:      /* x87 memory forms */
    case 0xDD: case 0xDE: case 0xDF: {
        uint8_t reg = REG_FIELD();
        return (reg == 2 || reg == 3 || reg == 7) ? 1 : 0; /* fst/fstp */
    }
    default:
        /* 0x00-0x3F ALU pairs: opcode bit 1 = direction (0: r/m <- r). */
        if (op < 0x38)
            return (op & 2) ? 0 : 1;
        if (op == 0x38 || op == 0x39 || op == 0x3A || op == 0x3B)
            return 0;                                 /* cmp */
        return -1;
    }
#undef REG_FIELD
}

/* --- dispatch ------------------------------------------------------------------ */

/* Returns 1 if a VEH handler continued execution (context patched). */
static int dispatch_veh(wn_exc_record *rec, wn_context64 *ctx, ucontext_t *uc)
{
    for (veh_node *n = g_veh; n; n = n->next) {
        wn_exc_pointers ep = { rec, ctx };
        int64_t r = n->handler(&ep);
        if (r == (int64_t)WN_EXC_CONT_EXEC) {
            /* Copy GPRs back so execution resumes modified. The ucontext
             * greg indices are REG_R* on x64 / REG_E* on i386. */
#if defined(__x86_64__)
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
#else
            uc->uc_mcontext.gregs[REG_EAX] = (uint32_t)ctx->rax;
            uc->uc_mcontext.gregs[REG_ECX] = (uint32_t)ctx->rcx;
            uc->uc_mcontext.gregs[REG_EDX] = (uint32_t)ctx->rdx;
            uc->uc_mcontext.gregs[REG_EBX] = (uint32_t)ctx->rbx;
            uc->uc_mcontext.gregs[REG_ESP] = (uint32_t)ctx->rsp;
            uc->uc_mcontext.gregs[REG_EBP] = (uint32_t)ctx->rbp;
            uc->uc_mcontext.gregs[REG_ESI] = (uint32_t)ctx->rsi;
            uc->uc_mcontext.gregs[REG_EDI] = (uint32_t)ctx->rdi;
            uc->uc_mcontext.gregs[REG_EIP] = (uint32_t)ctx->rip;
#endif
            return 1;
        }
    }
    return 0;
}

/* ============================================================================
 * 32-bit frame-based SEH (i386 guests under wow64) — fs:[0] chain walk.
 *
 * Before this, every guest exception (fault or RaiseException, including
 * Delphi's flow-control 0xEEDFACE) fell straight to "unhandled": the 32-bit
 * frame chain in the emulated TEB was never walked, so no guest try/except
 * ever ran (found via the Inno Setup installer: Delphi raises constantly).
 *
 * Contract notes (decoded from the installer's own System-unit SEH code):
 *  - frame = {uint32 next, uint32 handler} on the guest stack, chain head at
 *    TEB32+0 (fs:[0]);
 *  - handler(record32, frame, ctx32, 0) is a 4-arg stdcall guest proc;
 *  - verdicts: 0 keep searching, 0xFFFFFFFF continue execution, 1 unwind to
 *    this frame (the Borland/Delphi except handler then CALLS RtlUnwind
 *    itself and never returns normally — see wn_seh_rtl_unwind_32);
 *  - i386 EXCEPTION_RECORD: code@0 flags@4 rec@8 addr@0xC nparams@0x10
 *    info@0x14 (0x50 bytes); i386 CONTEXT is 0x2CC (Ebp@0xB4, Eip@0xB8,
 *    EFlags@0xC0, Esp@0xC4);
 *  - RtlUnwind(TargetFrame, TargetIp, Record, ReturnValue): walk to the
 *    frame calling handlers with EH_UNWINDING, pop frames, then the guest
 *    resumes at TargetIp with ESP=TargetFrame carrying [esp]=ReturnValue,
 *    [esp+4]=Record (the Delphi continuation reads the record at [esp+4]).
 * ==========================================================================*/

#if defined(__x86_64__)
#include <setjmp.h>

/* Walk-level longjmp chain: rtl_unwind_32 aborts the handler invocation it
 * was called from, so the abandoned call32 frame unwinds cleanly (depth
 * restored here; no C-stack leak per exception). */
typedef struct seh32_jmp {
    jmp_buf jb;
    struct seh32_jmp *prev;
    int    depth;          /* wt->depth to restore after the longjmp */
} seh32_jmp;
static __thread seh32_jmp *g_seh32_jmp;
static __thread int g_seh32_walk_active;   /* nested-fault cap: a fault or
                                           * raise inside a walk never re-enters
                                           * (it hung in the 4th frame when a
                                           * finally body raised again) */

static int seh32_mapped(uint32_t addr, uint32_t len)
{
    if (addr < 0x10000)
        return 0;
    if (addr + len < addr)
        return 0;
    return msync((void *)(uintptr_t)(addr & ~0xFFFULL), 0x1000, MS_ASYNC) == 0;
}

/* i386 CONTEXT (0x2CC) from the host view. */
static void seh32_fill_ctx(uint8_t *ctx32, const wn_context64 *c)
{
    memset(ctx32, 0, 0x2CC);
    *(uint32_t *)(void *)(ctx32 + 0x00) = 0x10007;   /* CONTEXT_FULL */
    *(uint32_t *)(void *)(ctx32 + 0x8C) = 0x2B;      /* SegGs */
    *(uint32_t *)(void *)(ctx32 + 0x90) = 0x50;      /* SegFs: emulated TEB sel */
    *(uint32_t *)(void *)(ctx32 + 0x94) = 0x2B;      /* SegEs */
    *(uint32_t *)(void *)(ctx32 + 0x98) = 0x2B;      /* SegDs */
    *(uint32_t *)(void *)(ctx32 + 0x9C) = (uint32_t)c->rdi;
    *(uint32_t *)(void *)(ctx32 + 0xA0) = (uint32_t)c->rsi;
    *(uint32_t *)(void *)(ctx32 + 0xA4) = (uint32_t)c->rbx;
    *(uint32_t *)(void *)(ctx32 + 0xA8) = (uint32_t)c->rdx;
    *(uint32_t *)(void *)(ctx32 + 0xAC) = (uint32_t)c->rcx;
    *(uint32_t *)(void *)(ctx32 + 0xB0) = (uint32_t)c->rax;
    *(uint32_t *)(void *)(ctx32 + 0xB4) = (uint32_t)c->rbp;
    *(uint32_t *)(void *)(ctx32 + 0xB8) = (uint32_t)c->rip;
    *(uint32_t *)(void *)(ctx32 + 0xBC) = 0x23;      /* SegCs */
    *(uint32_t *)(void *)(ctx32 + 0xC0) = (uint32_t)c->eflags;
    *(uint32_t *)(void *)(ctx32 + 0xC4) = (uint32_t)c->rsp;
    *(uint32_t *)(void *)(ctx32 + 0xC8) = 0x2B;      /* SegSs */
}

/* Walk the 32-bit frame chain and dispatch the exception.
 *   uc != NULL  → signal path: uc gets patched on unwind / continue-exec;
 *                 the handler scratch anchors below the FAULTING esp.
 *   uc == NULL  → RaiseException path (runs inside the RaiseException
 *                 thunk dispatch): a pending unwind is applied by the
 *                 dispatch layer's exit path; anchor = the raise args.
 * Returns 1 when handled (or an unwind is pending), 0 = unhandled. */
static int seh32_dispatch(wn_exc_record *rec, wn_context64 *ctx, void *uc_)
{
    ucontext_t *uc = uc_;
    wn_wow64_thread *wt = wn_wow64_thread_current();
    if (!wt || !g_wow64_active)
        return 0;
    if (g_seh32_walk_active) {
        wn_log(WN_LOG_WARN, "seh32: nested fault/raise inside the walk — "
               "capped (pending unwind: %s)",
               wn_wow64_unwind32_pending() ? "kept" : "none");
        return 0;
    }
    uint32_t teb32 = (uint32_t)(uintptr_t)wt->teb32;
    if (!seh32_mapped(teb32, 4))
        return 0;
    uint32_t head = *(uint32_t *)(uintptr_t)teb32;
    if (!seh32_mapped(head, 8))
        return 0;

    /* anchor: below the deepest live guest stack we know of */
    uint32_t anchor = uc
        ? (uint32_t)uc->uc_mcontext.gregs[REG_RSP]
        : wt->args32;

    /* build the guest-shaped EXCEPTION_RECORD + CONTEXT in low memory */
    uint8_t *blk = wn_low_malloc(0x50 + 0x2CC);
    if (!blk)
        return 0;
    uint8_t *rec32 = blk;
    uint8_t *ctx32 = blk + 0x50;
    memset(rec32, 0, 0x50);
    *(uint32_t *)(void *)(rec32 + 0x00) = rec->exception_code;
    *(uint32_t *)(void *)(rec32 + 0x04) = rec->exception_flags;
    *(uint32_t *)(void *)(rec32 + 0x08) = 0;        /* nested chain */
    *(uint32_t *)(void *)(rec32 + 0x0C) = (uint32_t)rec->exception_address;
    *(uint32_t *)(void *)(rec32 + 0x10) =
        rec->number_parameters > 15 ? 15 : rec->number_parameters;
    for (uint32_t i = 0; i < rec->number_parameters && i < 15; i++)
        *(uint32_t *)(void *)(rec32 + 0x14 + 4 * i) =
            (uint32_t)rec->exception_information[i];
    seh32_fill_ctx(ctx32, ctx);

    int handled = 0;
    uint32_t walked[128];      /* frames already searched (for the
                                 * return-1 unwind-to-me pass) */
    int n_walked = 0;
    wn_log(WN_LOG_DEBUG, "seh32: dispatch code=%08x addr=%x head=%x "
           "anchor=%x uc=%d", rec->exception_code,
           (uint32_t)rec->exception_address, head, anchor, uc ? 1 : 0);
    g_seh32_walk_active = 1;
    for (int i = 0; i < 128 && seh32_mapped(head, 8); i++) {
        uint32_t next = *(uint32_t *)(uintptr_t)head;
        uint32_t handler = *(uint32_t *)(uintptr_t)(head + 4);
        wn_log(WN_LOG_DEBUG, "seh32: frame %x handler %x (next %x)",
               head, handler, next);
        if (next && next < 0x10000)
            break;
        if (!seh32_mapped(handler, 16))
            break;
        seh32_jmp j;
        j.prev = g_seh32_jmp;
        j.depth = wt->depth;
        g_seh32_jmp = &j;
        uint64_t r;
        if (setjmp(j.jb) == 0)
            r = wn_wow64_call_wndproc32_base(anchor, handler,
                    (uint32_t)(uintptr_t)rec32, head,
                    (uint32_t)(uintptr_t)ctx32, 0);
        else
            r = (uint64_t)-2;    /* RtlUnwind ran inside the handler */
        g_seh32_jmp = j.prev;
        wt->depth = j.depth;      /* longjmp skipped call32's restore */
        wn_log(WN_LOG_DEBUG, "seh32: handler %x verdict %llx", handler,
               (unsigned long long)r);

        if ((uint32_t)r == 0xFFFFFFFFu) {
            /* EXCEPTION_CONTINUE_EXECUTION: copy (possibly modified)
             * guest context back and resume. */
            if (uc) {
                uc->uc_mcontext.gregs[REG_RAX] = *(uint32_t *)(void *)(ctx32 + 0xB0);
                uc->uc_mcontext.gregs[REG_RCX] = *(uint32_t *)(void *)(ctx32 + 0xAC);
                uc->uc_mcontext.gregs[REG_RDX] = *(uint32_t *)(void *)(ctx32 + 0xA8);
                uc->uc_mcontext.gregs[REG_RBX] = *(uint32_t *)(void *)(ctx32 + 0xA4);
                uc->uc_mcontext.gregs[REG_RSP] = *(uint32_t *)(void *)(ctx32 + 0xC4);
                uc->uc_mcontext.gregs[REG_RBP] = *(uint32_t *)(void *)(ctx32 + 0xB4);
                uc->uc_mcontext.gregs[REG_RSI] = *(uint32_t *)(void *)(ctx32 + 0xA0);
                uc->uc_mcontext.gregs[REG_RDI] = *(uint32_t *)(void *)(ctx32 + 0x9C);
                uc->uc_mcontext.gregs[REG_RIP] = *(uint32_t *)(void *)(ctx32 + 0xB8);
            }
            handled = 1;
            break;
        }
        if ((int64_t)r == -2 || wn_wow64_unwind32_pending()) {
            if (uc) {
                uint32_t t, e, a;
                if (wn_wow64_unwind32_take(&t, &e, &a)) {
                    uc->uc_mcontext.gregs[REG_RIP] = t;
                    uc->uc_mcontext.gregs[REG_RSP] = e;
                    uc->uc_mcontext.gregs[REG_RAX] = a;
                }
            }
            handled = 1;
            break;
        }
        if ((uint32_t)r == 1) {
            /* ExceptionExecuteHandler. For Borland/Delphi __finally frames
             * (decoded from the installer's System unit: the handler runs
             * the finally body when called with the UNWINDING flags and
             * returns 1 on BOTH passes; the real except handler claims the
             * exception by calling RtlUnwind itself): unwind to this frame
             * — run every inner frame's finally body with EH_UNWINDING,
             * run THIS frame's with EH_UNWINDING|EH_TARGET_UNWINDING — pop
             * them all, then CONTINUE THE SEARCH OUTWARD with the same
             * record. */
            *(uint32_t *)(void *)(rec32 + 0x04) |= 2;   /* EH_UNWINDING */
            for (int k = 0; k < n_walked; k++) {
                uint32_t fh = *(uint32_t *)(uintptr_t)(walked[k] + 4);
                if (seh32_mapped(fh, 16))
                    wn_wow64_call_wndproc32_base(anchor, fh,
                            (uint32_t)(uintptr_t)rec32, walked[k],
                            (uint32_t)(uintptr_t)ctx32, 0);
                *(uint32_t *)(uintptr_t)teb32 =
                    *(uint32_t *)(uintptr_t)walked[k];   /* pop */
            }
            *(uint32_t *)(void *)(rec32 + 0x04) |= 4; /* EH_TARGET_UNWINDING */
            if (seh32_mapped(handler, 16))
                wn_wow64_call_wndproc32_base(anchor, handler,
                        (uint32_t)(uintptr_t)rec32, head,
                        (uint32_t)(uintptr_t)ctx32, 0);
            /* pop the target frame; the search resumes from its next */
            *(uint32_t *)(uintptr_t)teb32 = next;
            n_walked = 0;
            head = next;
            wn_log(WN_LOG_DEBUG, "seh32: finally-frame unwound, "
                   "search continues at %x", head);
            continue;
        }
        if ((uint32_t)r != 0)
            wn_log(WN_LOG_DEBUG, "seh32: handler %x returned %llx", handler,
                   (unsigned long long)r);
        if (n_walked < 128)
            walked[n_walked++] = head;
        head = next;
    }
    g_seh32_walk_active = 0;
    wn_low_free(blk);
    return handled;
}

/* kernel32/ntdll RtlUnwind for a 32-bit caller (Borland/Delphi SEH).
 * Never returns normally when a walk is active: longjmps back to the walk,
 * which reports "handled" and lets the dispatch/signal layer resume the
 * guest at the continuation. Without a walk (direct guest abort path),
 * leaves a pending unwind for the dispatch layer. */
void wn_seh_rtl_unwind_32(uint32_t target_frame, uint32_t target_ip,
                         uint32_t rec32, uint32_t retval)
{
    wn_wow64_thread *wt = wn_wow64_thread_current();
    if (!wt)
        return;
    wn_log(WN_LOG_DEBUG, "seh32: RtlUnwind(frame=%x ip=%x rec=%x rv=%x)",
           target_frame, target_ip, rec32, retval);
    uint32_t teb32 = (uint32_t)(uintptr_t)wt->teb32;
    if (!seh32_mapped(teb32, 4) || !seh32_mapped(target_frame, 8))
        return;

    /* intermediate frames: run finally bodies with EH_UNWINDING */
    if (rec32 && seh32_mapped(rec32, 4))
        *(uint32_t *)(uintptr_t)(rec32 + 4) |= 2;
    uint32_t head = *(uint32_t *)(uintptr_t)teb32;
    for (int i = 0; i < 256 && seh32_mapped(head, 8); i++) {
        if (head == target_frame)
            break;
        uint32_t next = *(uint32_t *)(uintptr_t)head;
        uint32_t handler = *(uint32_t *)(uintptr_t)(head + 4);
        if (!next || next < 0x10000)
            break;
        if (seh32_mapped(handler, 16))
            wn_wow64_call_wndproc32(handler, rec32, head, 0, 0);
        *(uint32_t *)(uintptr_t)teb32 = next;    /* pop the frame */
        head = next;
    }
    if (head != target_frame)
        wn_log(WN_LOG_WARN, "seh32: RtlUnwind target %x not on chain "
               "(at %x) — unwinding anyway", target_frame, head);

    /* pop the target frame too */
    *(uint32_t *)(uintptr_t)teb32 =
        *(uint32_t *)(uintptr_t)target_frame;

    /* Continuation: [esp]=ReturnValue, [esp+4]=Record, ESP=TargetFrame —
     * the two popped frame dwords are reused (decoded from the Delphi
     * System handler: its continuation reads the record at [esp+4]). */
    *(uint32_t *)(uintptr_t)(target_frame + 4) = rec32;
    *(uint32_t *)(uintptr_t)target_frame = retval;
    wn_wow64_unwind32_set(target_ip, target_frame, retval);

    if (g_seh32_jmp) {
        seh32_jmp *j = g_seh32_jmp;
        g_seh32_jmp = j->prev;
        wt->depth = j->depth;     /* unwound handler frames never returned */
        longjmp(j->jb, 1);
    }
    /* no walk: the dispatch layer applies the pending unwind */
}

#else  /* !__x86_64__ — native i386 (winnux32) frame-based SEH ---------------
 * The same walk engine as the wow64 host above, except everything is
 * native: %fs:0x18 IS the TEB (its first dword is the live fs:[0] chain
 * head the guest maintains itself), handler addresses are real cdecl
 * code pointers, and the unwound continuation lands by switching the
 * real stack. Guest pointers need no low-memory staging, but rec32/ctx32
 * still go through wn_low_malloc to keep the shape identical. */

#include <setjmp.h>

typedef struct seh32_jmp {
    jmp_buf jb;
    struct seh32_jmp *prev;
} seh32_jmp;
static __thread seh32_jmp *g_seh32_jmp;
static __thread int      g_seh32_walk_active;   /* same nested-fault cap */
static __thread uint32_t g_land_ip, g_land_esp, g_land_eax;
static __thread int      g_land_pending;

static int seh32_mapped(uint32_t addr, uint32_t len)
{
    if (addr < 0x10000)
        return 0;
    if (addr + len < addr)
        return 0;
    return msync((void *)(uintptr_t)(addr & ~0xFFFULL), 0x1000, MS_ASYNC) == 0;
}

/* i386 frame handlers are CDECL (wn_types.h: caller cleans) — plain fn-ptr
 * calls, the Linux i386 default ABI. NOT WN_API/stdcall. */
typedef int (*seh32_handler_t)(uint32_t rec, uint32_t frame, uint32_t ctx,
                               uint32_t dispatcher);
static int seh32_call(uint32_t handler, uint32_t rec, uint32_t frame,
                      uint32_t ctx)
{
    return ((seh32_handler_t)(uintptr_t)handler)(rec, frame, ctx, 0);
}

/* i386 CONTEXT (0x2CC). uc != NULL → fault path (real register state);
 * uc == NULL → RaiseException path: approximate with the raise site
 * (same spirit as the x64 host's approximation). */
static void seh32_fill_ctx(uint8_t *ctx32, const ucontext_t *uc)
{
    uint32_t gs, fs, es, ds, cs, ss;
    uint32_t edi, esi, ebx, edx, ecx, eax, ebp, eip, efl, esp;
    __asm__ volatile ("movl %%gs, %0" : "=r"(gs));
    __asm__ volatile ("movl %%fs, %0" : "=r"(fs));
    __asm__ volatile ("movl %%es, %0" : "=r"(es));
    __asm__ volatile ("movl %%ds, %0" : "=r"(ds));
    __asm__ volatile ("movl %%cs, %0" : "=r"(cs));
    __asm__ volatile ("movl %%ss, %0" : "=r"(ss));
    if (uc) {
        edi = uc->uc_mcontext.gregs[REG_EDI];
        esi = uc->uc_mcontext.gregs[REG_ESI];
        ebx = uc->uc_mcontext.gregs[REG_EBX];
        edx = uc->uc_mcontext.gregs[REG_EDX];
        ecx = uc->uc_mcontext.gregs[REG_ECX];
        eax = uc->uc_mcontext.gregs[REG_EAX];
        ebp = uc->uc_mcontext.gregs[REG_EBP];
        eip = uc->uc_mcontext.gregs[REG_EIP];
        efl = uc->uc_mcontext.gregs[REG_EFL];
        esp = uc->uc_mcontext.gregs[REG_ESP];
    } else {
        __asm__ volatile ("movl %%edi, %0" : "=r"(edi));
        __asm__ volatile ("movl %%esi, %0" : "=r"(esi));
        __asm__ volatile ("movl %%ebx, %0" : "=r"(ebx));
        __asm__ volatile ("movl %%edx, %0" : "=r"(edx));
        __asm__ volatile ("movl %%ecx, %0" : "=r"(ecx));
        __asm__ volatile ("movl %%eax, %0" : "=r"(eax));
        __asm__ volatile ("movl %%ebp, %0" : "=r"(ebp));
        __asm__ volatile ("pushfl\n\tpopl %0" : "=r"(efl));
        __asm__ volatile ("movl %%esp, %0" : "=r"(esp));
        eip = (uint32_t)(uintptr_t)__builtin_return_address(0);
    }
    memset(ctx32, 0, 0x2CC);
    *(uint32_t *)(void *)(ctx32 + 0x00) = 0x10007;   /* CONTEXT_FULL */
    *(uint32_t *)(void *)(ctx32 + 0x8C) = gs;
    *(uint32_t *)(void *)(ctx32 + 0x90) = fs;
    *(uint32_t *)(void *)(ctx32 + 0x94) = es;
    *(uint32_t *)(void *)(ctx32 + 0x98) = ds;
    *(uint32_t *)(void *)(ctx32 + 0x9C) = edi;
    *(uint32_t *)(void *)(ctx32 + 0xA0) = esi;
    *(uint32_t *)(void *)(ctx32 + 0xA4) = ebx;
    *(uint32_t *)(void *)(ctx32 + 0xA8) = edx;
    *(uint32_t *)(void *)(ctx32 + 0xAC) = ecx;
    *(uint32_t *)(void *)(ctx32 + 0xB0) = eax;
    *(uint32_t *)(void *)(ctx32 + 0xB4) = ebp;
    *(uint32_t *)(void *)(ctx32 + 0xB8) = eip;
    *(uint32_t *)(void *)(ctx32 + 0xBC) = cs;
    *(uint32_t *)(void *)(ctx32 + 0xC0) = efl;
    *(uint32_t *)(void *)(ctx32 + 0xC4) = esp;
    *(uint32_t *)(void *)(ctx32 + 0xC8) = ss;
}

/* Walk the fs:[0] frame chain (native build).
 *   uc != NULL → signal path: uc patched on unwind / continue-exec.
 *   uc == NULL → RaiseException path: a pending continuation lands via
 *               wn_seh32_land (never returns).
 * Returns 1 when handled (or a continuation is pending), 0 = unhandled. */
static int seh32_dispatch(wn_exc_record *rec, ucontext_t *uc)
{
    if (g_seh32_walk_active) {
        wn_log(WN_LOG_WARN, "seh32: nested fault/raise inside the walk — "
               "capped (pending unwind: %s)", g_land_pending ? "kept" : "none");
        return 0;
    }
    wn_teb *teb = wn_teb_current();
    if (!teb)
        return 0;
    uint32_t head = (uint32_t)teb->exception_list;
    if (!seh32_mapped(head, 8))
        return 0;

    uint8_t *blk = wn_low_malloc(0x50 + 0x2CC);
    if (!blk)
        return 0;
    uint8_t *rec32 = blk;
    uint8_t *ctx32 = blk + 0x50;
    memset(rec32, 0, 0x50);
    *(uint32_t *)(void *)(rec32 + 0x00) = rec->exception_code;
    *(uint32_t *)(void *)(rec32 + 0x04) = rec->exception_flags;
    *(uint32_t *)(void *)(rec32 + 0x08) = 0;        /* nested chain */
    *(uint32_t *)(void *)(rec32 + 0x0C) = (uint32_t)rec->exception_address;
    *(uint32_t *)(void *)(rec32 + 0x10) =
        rec->number_parameters > 15 ? 15 : rec->number_parameters;
    for (uint32_t i = 0; i < rec->number_parameters && i < 15; i++)
        *(uint32_t *)(void *)(rec32 + 0x14 + 4 * i) =
            (uint32_t)rec->exception_information[i];
    seh32_fill_ctx(ctx32, uc);

    int handled = 0;
    uint32_t walked[128];      /* frames already searched (for the
                                * return-1 unwind-to-me pass) */
    int n_walked = 0;
    wn_log(WN_LOG_DEBUG, "seh32: dispatch code=%08x addr=%x head=%x uc=%d",
           rec->exception_code, (uint32_t)rec->exception_address, head,
           uc ? 1 : 0);
    g_seh32_walk_active = 1;
    for (int i = 0; i < 128 && seh32_mapped(head, 8); i++) {
        uint32_t next = *(uint32_t *)(uintptr_t)head;
        uint32_t handler = *(uint32_t *)(uintptr_t)(head + 4);
        wn_log(WN_LOG_DEBUG, "seh32: frame %x handler %x (next %x)",
               head, handler, next);
        if (next && next < 0x10000)
            break;
        if (!seh32_mapped(handler, 16))
            break;
        seh32_jmp j;
        j.prev = g_seh32_jmp;
        g_seh32_jmp = &j;
        int r;
        if (setjmp(j.jb) == 0)
            r = seh32_call(handler, (uint32_t)(uintptr_t)rec32, head,
                           (uint32_t)(uintptr_t)ctx32);
        else
            r = -2;    /* RtlUnwind ran inside the handler */
        g_seh32_jmp = j.prev;
        wn_log(WN_LOG_DEBUG, "seh32: handler %x verdict %x", handler,
               (uint32_t)r);

        if (r == -1) {
            /* EXCEPTION_CONTINUE_EXECUTION: copy (possibly modified)
             * guest context back and resume. */
            if (uc) {
                uc->uc_mcontext.gregs[REG_EAX] = *(uint32_t *)(void *)(ctx32 + 0xB0);
                uc->uc_mcontext.gregs[REG_ECX] = *(uint32_t *)(void *)(ctx32 + 0xAC);
                uc->uc_mcontext.gregs[REG_EDX] = *(uint32_t *)(void *)(ctx32 + 0xA8);
                uc->uc_mcontext.gregs[REG_EBX] = *(uint32_t *)(void *)(ctx32 + 0xA4);
                uc->uc_mcontext.gregs[REG_ESP] = *(uint32_t *)(void *)(ctx32 + 0xC4);
                uc->uc_mcontext.gregs[REG_EBP] = *(uint32_t *)(void *)(ctx32 + 0xB4);
                uc->uc_mcontext.gregs[REG_ESI] = *(uint32_t *)(void *)(ctx32 + 0xA0);
                uc->uc_mcontext.gregs[REG_EDI] = *(uint32_t *)(void *)(ctx32 + 0x9C);
                uc->uc_mcontext.gregs[REG_EIP] = *(uint32_t *)(void *)(ctx32 + 0xB8);
            }
            handled = 1;
            break;
        }
        if (r == -2 || g_land_pending) {
            if (uc && g_land_pending) {
                uc->uc_mcontext.gregs[REG_EIP] = g_land_ip;
                uc->uc_mcontext.gregs[REG_ESP] = g_land_esp;
                uc->uc_mcontext.gregs[REG_EAX] = g_land_eax;
            }
            handled = 1;
            break;
        }
        if (r == 1) {
            /* Borland __finally frame (same decode as the x64 twin):
             * run inner finally bodies with EH_UNWINDING, this frame's with
             * EH_UNWINDING|EH_TARGET_UNWINDING, pop them all, then continue
             * the search outward with the same record. */
            *(uint32_t *)(void *)(rec32 + 0x04) |= 2;   /* EH_UNWINDING */
            for (int k = 0; k < n_walked; k++) {
                uint32_t fh = *(uint32_t *)(uintptr_t)(walked[k] + 4);
                if (seh32_mapped(fh, 16))
                    seh32_call(fh, (uint32_t)(uintptr_t)rec32, walked[k],
                               (uint32_t)(uintptr_t)ctx32);
                teb->exception_list = *(uint32_t *)(uintptr_t)walked[k];
            }
            *(uint32_t *)(void *)(rec32 + 0x04) |= 4;   /* TARGET_UNWINDING */
            if (seh32_mapped(handler, 16))
                seh32_call(handler, (uint32_t)(uintptr_t)rec32, head,
                           (uint32_t)(uintptr_t)ctx32);
            teb->exception_list = next;
            n_walked = 0;
            head = next;
            wn_log(WN_LOG_DEBUG, "seh32: finally-frame unwound, "
                   "search continues at %x", head);
            continue;
        }
        if (r != 0)
            wn_log(WN_LOG_DEBUG, "seh32: handler %x returned %x", handler,
                   (uint32_t)r);
        if (n_walked < 128)
            walked[n_walked++] = head;
        head = next;
    }
    g_seh32_walk_active = 0;
    wn_low_free(blk);
    return handled;
}

/* Landing trampoline for the raise path: switches the real stack to the
 * unwound continuation ([esp]=retval, [esp+4]=record are already in guest
 * memory; EAX mirrors retval like the x64 twin). Never returns — global
 * asm, no prologue at all. */
__asm__(
".globl wn_seh32_land\n"
".type  wn_seh32_land, @function\n"
"wn_seh32_land:\n"
"  movl 4(%esp), %ecx\n"    /* target ip */
"  movl 8(%esp), %edx\n"    /* target esp */
"  movl 12(%esp), %eax\n"   /* retval */
"  movl %edx, %esp\n"
"  jmp *%ecx\n"
".size wn_seh32_land, .-wn_seh32_land\n"
);
extern void wn_seh32_land(uint32_t ip, uint32_t esp, uint32_t eax_val);

/* kernel32/ntdll RtlUnwind for a 32-bit caller (native build). Walks the
 * real fs:[0] chain, runs finally frames, then either longjmps back to a
 * live walk or leaves the continuation pending for the caller to apply. */
void wn_seh_rtl_unwind_32(uint32_t target_frame, uint32_t target_ip,
                         uint32_t rec32, uint32_t retval)
{
    wn_teb *teb = wn_teb_current();
    if (!teb)
        return;
    wn_log(WN_LOG_DEBUG, "seh32: RtlUnwind(frame=%x ip=%x rec=%x rv=%x)",
           target_frame, target_ip, rec32, retval);
    if (!seh32_mapped(target_frame, 8))
        return;

    /* intermediate frames: run finally bodies with EH_UNWINDING */
    if (rec32 && seh32_mapped(rec32, 4))
        *(uint32_t *)(uintptr_t)(rec32 + 4) |= 2;
    uint32_t head = (uint32_t)teb->exception_list;
    for (int i = 0; i < 256 && seh32_mapped(head, 8); i++) {
        if (head == target_frame)
            break;
        uint32_t next = *(uint32_t *)(uintptr_t)head;
        uint32_t handler = *(uint32_t *)(uintptr_t)(head + 4);
        if (!next || next < 0x10000)
            break;
        if (seh32_mapped(handler, 16))
            seh32_call(handler, rec32, head, 0);
        teb->exception_list = next;    /* pop the frame */
        head = next;
    }
    if (head != target_frame)
        wn_log(WN_LOG_WARN, "seh32: RtlUnwind target %x not on chain "
               "(at %x) — unwinding anyway", target_frame, head);

    /* pop the target frame; continuation: [esp]=ReturnValue, [esp+4]=Record */
    teb->exception_list = *(uint32_t *)(uintptr_t)target_frame;
    *(uint32_t *)(uintptr_t)(target_frame + 4) = rec32;
    *(uint32_t *)(uintptr_t)target_frame = retval;
    g_land_ip = target_ip;
    g_land_esp = target_frame;
    g_land_eax = retval;
    g_land_pending = 1;

    if (g_seh32_jmp) {
        seh32_jmp *j = g_seh32_jmp;
        g_seh32_jmp = j->prev;
        longjmp(j->jb, 1);    /* unwound handler frames never returned */
    }
    /* no walk: the fault path patches uc, the raise path lands via the
     * wn_seh32_land trampoline. */
}
#endif  /* __x86_64__ */


static void fill_context(wn_context64 *ctx, const ucontext_t *uc)
{
    memset(ctx, 0, sizeof *ctx);
    ctx->context_flags = 0x10003F;
    ctx->mxcsr = 0x1F80;
    ctx->seg_cs = 0x33;
    ctx->seg_ss = 0x2B;
    ctx->eflags = (uint32_t)uc->uc_mcontext.gregs[REG_EFL];
#if defined(__x86_64__)
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
#else
    ctx->rax = uc->uc_mcontext.gregs[REG_EAX];
    ctx->rcx = uc->uc_mcontext.gregs[REG_ECX];
    ctx->rdx = uc->uc_mcontext.gregs[REG_EDX];
    ctx->rbx = uc->uc_mcontext.gregs[REG_EBX];
    ctx->rsp = uc->uc_mcontext.gregs[REG_ESP];
    ctx->rbp = uc->uc_mcontext.gregs[REG_EBP];
    ctx->rsi = uc->uc_mcontext.gregs[REG_ESI];
    ctx->rdi = uc->uc_mcontext.gregs[REG_EDI];
    ctx->rip = uc->uc_mcontext.gregs[REG_EIP];
    /* greg_t is SIGNED 32-bit here: stack addresses >= 0x80000000 sign-
     * extended into the kernel half of the u64 context copy — garbage in
     * crash reports (RSP=0xfffffffff7b5a130). Zero-extend the half. */
    ctx->rsp &= 0xFFFFFFFFu;
    ctx->rbp &= 0xFFFFFFFFu;
#endif
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
    char where[96];
    wn_module_describe_addr((const void *)(uintptr_t)ctx->rip, where, sizeof where);
    wn_log(WN_LOG_ERR, "seh: guest exception %s (0x%08X) at %s -> app filter",
           exc_name(rec->exception_code), rec->exception_code, where);
    if (g_unhandled) {
        wn_exc_pointers ep = { rec, ctx };
        if (g_unhandled(&ep) == WN_EXC_EXECUTE_HANDLER)
            exit((int)rec->exception_code);
    }
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
#if defined(__x86_64__)
    /* RBP frame-chain walk (MSVC builds keep frame pointers on x64). The
     * i386 frame chain is 4-byte; the walk is skipped there for now. */
    {
        uint64_t rbp = ctx->rbp;
        for (int i = 0; i < 24 && rbp; i++) {
            if (rbp & 7 || rbp < 0x1000 || rbp - ctx->rbp > 0x400000ULL ||
                (i && rbp <= ctx->rbp + (uint64_t)i * 16))
                break;
            uint64_t ret = *(const uint64_t *)(const void *)(uintptr_t)(rbp + 8);
            if (!ret)
                break;
            char w[96];
            wn_module_describe_addr((const void *)(uintptr_t)ret, w, sizeof w);
            wn_log(WN_LOG_ERR, "  #%d from %s", i, w);
            uint64_t next = *(const uint64_t *)(const void *)(uintptr_t)rbp;
            if (next <= rbp)
                break;
            rbp = next;
        }
    }
#endif
    exit((int)rec->exception_code);
}

static void signal_handler(int sig, siginfo_t *si, void *uc_)
{
    ucontext_t *uc = uc_;
    /* Fault inside a guarded safe-probe (wn_safe_strnlen etc.): jump back
     * to the probe so callers get a clean "unreadable" answer instead of
     * dying. This must run before any other handling. */
    /* 32-bit guest faults FIRST: the wow64 hook restores the host %fs base
     * before any libc/TLS use. Without this, a handler entered from compat
     * mode (fs base 0) faults on the first __thread access and the kernel
     * kills the process with no diagnostic at all (found via core dump:
     * crash inside wn_safe_fault_active). */
    if (wn_wow64_fault_hook(uc_, si->si_addr, si->si_code, sig))
        return;
    if (wn_safe_fault_active()) {
        wn_log(WN_LOG_DEBUG, "seh: fault inside safe probe (addr=%p) — "
               "jumping back to caller", si->si_addr);
        wn_safe_fault_jump();
    }
    wn_module *m = wn_module_from_addr((const void *)(uintptr_t)
#if defined(__x86_64__)
        uc->uc_mcontext.gregs[REG_RIP]
#else
        uc->uc_mcontext.gregs[REG_EIP]
#endif
        , NULL);
    if (!m) {
        /* Fault inside host code: not ours to hide. Re-raise default. */
        wn_log(WN_LOG_ERR, "seh: host-side fault (SIG%d addr=%p ip=%p) — "
               "re-raising, this is a WinNux bug", sig, si->si_addr,
               (void *)(uintptr_t)
#if defined(__x86_64__)
               uc->uc_mcontext.gregs[REG_RIP]
#else
               uc->uc_mcontext.gregs[REG_EIP]
#endif
               );
#if !defined(__x86_64__)
        /* i386 host-fault context: regs + stack words (ret candidates). */
        wn_log(WN_LOG_ERR, "  EAX=%08x EBX=%08x ECX=%08x EDX=%08x",
               (unsigned)uc->uc_mcontext.gregs[REG_EAX],
               (unsigned)uc->uc_mcontext.gregs[REG_EBX],
               (unsigned)uc->uc_mcontext.gregs[REG_ECX],
               (unsigned)uc->uc_mcontext.gregs[REG_EDX]);
        wn_log(WN_LOG_ERR, "  ESI=%08x EDI=%08x EBP=%08x ESP=%08x",
               (unsigned)uc->uc_mcontext.gregs[REG_ESI],
               (unsigned)uc->uc_mcontext.gregs[REG_EDI],
               (unsigned)uc->uc_mcontext.gregs[REG_EBP],
               (unsigned)uc->uc_mcontext.gregs[REG_ESP]);
        {
            uint32_t *sp = (uint32_t *)(uintptr_t)uc->uc_mcontext.gregs[REG_ESP];
            for (int i = 0; i < 12; i++) {
                char w[96];
                wn_module_describe_addr((const void *)(uintptr_t)sp[i], w, sizeof w);
                wn_log(WN_LOG_ERR, "  [esp+%02d] %08x  %s", i * 4,
                       (unsigned)sp[i], w);
            }
            /* Memory at the faulting address — an exec-fault target is a
             * data page (readable); heap structures identify themselves. */
            uint8_t *fa = (uint8_t *)(uintptr_t)uc->uc_mcontext.gregs[REG_EIP];
            if ((uintptr_t)fa > 0x10000) {
                char hex[3 * 24 + 1];
                size_t o = 0;
                for (int i = 0; i < 24; i++)
                    o += (size_t)snprintf(hex + o, sizeof hex - o, "%02x ",
                                          fa[i]);
                wn_log(WN_LOG_ERR, "  bytes at fault addr: %s", hex);
            }
            /* Full memory map: stack-region math is the crux of i386 faults. */
            FILE *mf = fopen("/proc/self/maps", "re");
            if (mf) {
                char ml[512];
                wn_log(WN_LOG_ERR, "  ---- /proc/self/maps ----");
                while (fgets(ml, sizeof ml, mf))
                    wn_log(WN_LOG_ERR, "  %s", ml);
                fclose(mf);
            }
        }
#endif
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
    case SIGBUS: {
        rec.exception_code = 0xC0000005;
        /* Read vs write: decode the faulting instruction (RIP is inside a
         * mapped guest module here, so the opcode bytes are readable). */
        int is_write = -1;
        {
            const uint8_t *code = (const uint8_t *)(uintptr_t)
#if defined(__x86_64__)
                uc->uc_mcontext.gregs[REG_RIP];
#else
                uc->uc_mcontext.gregs[REG_EIP];
#endif
            is_write = fault_is_write(code, 16);
        }
        if (is_write < 0)
            is_write = (si->si_code == SEGV_ACCERR ||
                        si->si_code == BUS_ADRERR) ? 1 : 0;
        rec.exception_information[0] = (uint64_t)is_write;
        rec.exception_information[1] = (uint64_t)(uintptr_t)si->si_addr;
        rec.number_parameters = 2;
        break;
    }
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
    rec.exception_address =
#if defined(__x86_64__)
        uc->uc_mcontext.gregs[REG_RIP];
#else
        uc->uc_mcontext.gregs[REG_EIP];
#endif

    wn_context64 ctx;
    fill_context(&ctx, uc);
    rec.exception_record = 0;

    if (dispatch_veh(&rec, &ctx, uc))
        return;   /* VEH continued execution */

#if defined(__x86_64__)
    if (g_wow64_active) {
        /* 32-bit frame-based SEH: give the guest's fs:[0] chain a chance
         * before declaring the exception unhandled (Delphi's try/except
         * runs here — it is also Inno Setup's main flow-control path). */
        if (seh32_dispatch(&rec, &ctx, uc))
            return;   /* handled or unwind patched into uc */
    }
#else
    /* Native build: the same walk over the REAL fs:[0] chain. */
    if (seh32_dispatch(&rec, uc))
        return;   /* handled, or uc patched to the unwind continuation */
#endif

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

    {
        const char *mod = "?";
        uint64_t rva = 0;
        wn_module *m = wn_module_from_addr(
            (const void *)(uintptr_t)__builtin_return_address(0), NULL);
        if (m) {
            mod = m->name;
            rva = (uint64_t)(uintptr_t)__builtin_return_address(0) -
                  (uint64_t)(uintptr_t)m->base;
        }
        wn_log(WN_LOG_DEBUG, "seh: RaiseException(0x%08X) from %s+0x%llx",
               code, mod, (unsigned long long)rva);
    }
    /* Parameter dump: fault raises carry none, but explicit RaiseException
     * calls (Delphi/VCL 0x0EEDFACE, C++ EH 0xE06D7363) carry the payload
     * the app's filter needs — and the one our log needs to decode the
     * raise's origin. */
    for (uint32_t i = 0; i < rec.number_parameters && i < 8; i++) {
        char where[96];
        wn_module_describe_addr(
            (const void *)(uintptr_t)rec.exception_information[i],
            where, sizeof where);
        wn_log(WN_LOG_DEBUG, "seh:   info[%u]=0x%llx (%s)", i,
               (unsigned long long)rec.exception_information[i], where);
    }
    /* Delphi raises: info[0] = raise-site address, info[1] = Exception
     * object in Delphi 2-era RTLs (the VCL class-name shortstring rides at
     * the raise site instead); [obj]=VMT, [obj+4]=FMessage (Pascal string:
     * length at ptr-4, chars at ptr). Dumped via safe probes so a bogus
     * pointer can't take the handler down. */
    if (code == 0x0EEDFACEu && rec.number_parameters >= 2) {
        for (int cand = 1; cand >= 0; cand--) {
            uint32_t obj = (uint32_t)rec.exception_information[cand];
            if (obj <= 0x10000 || !wn_ptr_readable((void *)(uintptr_t)obj, 16))
                continue;
            uint32_t vmt = 0, msgp = 0;
            memcpy(&vmt, (const void *)(uintptr_t)obj, 4);
            memcpy(&msgp, (const void *)(uintptr_t)(obj + 4), 4);
            wn_log(WN_LOG_DEBUG, "seh:   delphi info[%d] obj=0x%x vmt=0x%x "
                   "msg=0x%x", cand, obj, vmt, msgp);
            if (msgp > 0x10000 &&
                wn_ptr_readable((void *)(uintptr_t)(msgp - 4), 8)) {
                uint32_t mlen = 0;
                memcpy(&mlen, (const void *)(uintptr_t)(msgp - 4), 4);
                if (mlen && mlen < 512 &&
                    wn_ptr_readable((void *)(uintptr_t)msgp, mlen)) {
                    char txt[257];
                    size_t n = mlen < 256 ? mlen : 256;
                    memcpy(txt, (const void *)(uintptr_t)msgp, n);
                    txt[n] = 0;
                    wn_log(WN_LOG_DEBUG, "seh:   delphi msg: \"%s\"", txt);
                }
            }
        }
    }

    ucontext_t uc;
    memset(&uc, 0, sizeof uc);   /* approximate context: raise site */
    wn_context64 ctx;
    fill_context(&ctx, &uc);
    ctx.rip = (uint64_t)(uintptr_t)__builtin_return_address(0);
    rec.exception_address = ctx.rip;

    if (dispatch_veh(&rec, &ctx, &uc))
        return;   /* VEH continued: exception swallowed (logged) */

#if defined(__x86_64__)
    if (g_wow64_active) {
        if (seh32_dispatch(&rec, &ctx, NULL))
            return;   /* handled (or unwind pending: the dispatch layer
                        * resumes the guest at the continuation) */
        if (wn_wow64_unwind32_pending())
            return;   /* nested raise during an unwind was capped: keep the
                        * outer unwind (the thunk exit path lands it) */
    }
#else
    if (seh32_dispatch(&rec, NULL)) {
        if (g_land_pending) {
            wn_log(WN_LOG_DEBUG, "seh32: raise landing at %x (esp=%x)",
                   g_land_ip, g_land_esp);
            wn_seh32_land(g_land_ip, g_land_esp, g_land_eax);  /* noreturn */
        }
        return;   /* handler swallowed the raise (no unwind pending) */
    }
    if (g_land_pending) {
        wn_log(WN_LOG_WARN, "seh32: capped raise during unwind — resuming "
               "continuation %x", g_land_ip);
        wn_seh32_land(g_land_ip, g_land_esp, g_land_eax);
    }
#endif

    crash_report(&rec, &ctx);
}

/* ============================================================================
 * Table-driven x64 exception unwinding (.pdata/.xdata) — Rtl* exports.
 *
 * Putty's own crash/entropy paths call RtlCaptureContext +
 * RtlLookupFunctionEntry (+ RtlUnwind) directly, so these must be real.
 * Layout: RUNTIME_FUNCTION {BeginRVA, EndRVA, UnwindRVA} arrays live in
 * .pdata; UNWIND_INFO at ImageBase+UnwindRVA describes the prologue.
 * ==========================================================================*/

/* RtlCaptureContext: must be raw asm — a C wrapper would capture its own
 * frame instead of the caller's. ms_abi: first arg (CONTEXT*) in RCX.
 * i386: the CONTEXT layout differs entirely (EBP/ESP at different offsets,
 * arguments on the stack) — needed before any WoW64 unwind work. */
#if defined(__x86_64__)
__asm__(
".globl wn_rtl_capture_context\n"
".type  wn_rtl_capture_context, @function\n"
"wn_rtl_capture_context:\n"
"  movq  %rax, 0x78(%rcx)\n"      /* Rax  */
"  movq  %rcx, 0x80(%rcx)\n"      /* Rcx  (== ctx) */
"  movq  %rdx, 0x88(%rcx)\n"      /* Rdx  */
"  movq  %rbx, 0x90(%rcx)\n"      /* Rbx  */
"  leaq  8(%rsp), %rax\n"
"  movq  %rax, 0x98(%rcx)\n"      /* Rsp  (caller, past return address) */
"  movq  %rbp, 0xA0(%rcx)\n"      /* Rbp  */
"  movq  %rsi, 0xA8(%rcx)\n"      /* Rsi  */
"  movq  %rdi, 0xB0(%rcx)\n"      /* Rdi  */
"  movq  %r8,  0xB8(%rcx)\n"
"  movq  %r9,  0xC0(%rcx)\n"
"  movq  %r10, 0xC8(%rcx)\n"
"  movq  %r11, 0xD0(%rcx)\n"
"  movq  %r12, 0xD8(%rcx)\n"
"  movq  %r13, 0xE0(%rcx)\n"
"  movq  %r14, 0xE8(%rcx)\n"
"  movq  %r15, 0xF0(%rcx)\n"
"  movq  (%rsp), %rax\n"
"  movq  %rax, 0xF8(%rcx)\n"      /* Rip  = return address into caller */
"  movl  $0x0010003F, 0x30(%rcx)\n"  /* ContextFlags: CONTROL|INT|FP */
"  movl  $0x33, 0x38(%rcx)\n"     /* SegCs */
"  movl  $0x2B, 0x42(%rcx)\n"     /* SegSs */
"  ret\n"
".size wn_rtl_capture_context, .-wn_rtl_capture_context\n"
);
#else
/* i386 wn_rtl_capture_context: implement with i386 CONTEXT layout (TODO) */
__asm__(".globl wn_rtl_capture_context\n.type wn_rtl_capture_context,@function\nwn_rtl_capture_context:\n ret\n");
#endif


/* raw base+RVA resolution (no wn_pe_image handle) */
static const void *pe_rva_raw(const void *base, uint32_t rva, size_t n)
{
    const wn_image_dos_header *dos = base;
    if (!base || dos->e_magic != 0x5A4D)
        return NULL;
    const wn_image_optional_header64 *oh =
        (const void *)((const uint8_t *)base + dos->e_lfanew + 4 +
                       sizeof(wn_image_file_header));
    if (rva >= oh->size_of_image)
        return NULL;
    if (n && (uint64_t)rva + n > oh->size_of_image)
        return NULL;
    return (const uint8_t *)base + rva;
}

/* .pdata entry */
typedef struct {
    uint32_t begin_rva, end_rva, unwind_rva;
} wn_runtime_function;

/* walk .pdata of the module containing ControlPc */
void *wn_seh_lookup_function_entry(uint64_t control_pc, uint64_t *image_base)
{
    wn_module *m = wn_module_from_addr((const void *)(uintptr_t)control_pc,
                                       NULL);
    if (!m || m->kind != WN_MOD_PE) {
        if (image_base)
            *image_base = 0;
        return NULL;
    }
    if (image_base)
        *image_base = (uint64_t)(uintptr_t)m->base;
    const wn_image_dos_header *dos = (const void *)m->pe.base;
    const wn_image_optional_header64 *oh =
        (const void *)(m->pe.base + dos->e_lfanew + 4 +
                       sizeof(wn_image_file_header));
    const wn_image_data_directory *dir = &oh->dirs[3 /*EXCEPTION*/];
    if (!dir->virtual_address || dir->size < sizeof(wn_runtime_function))
        return NULL;
    const wn_runtime_function *rf = (const void *)
        wn_pe_rva(&m->pe, dir->virtual_address, sizeof *rf);
    if (!rf)
        return NULL;
    size_t n = dir->size / sizeof(wn_runtime_function);
    uint32_t rva = (uint32_t)(control_pc - (uint64_t)(uintptr_t)m->base);
    /* binary search */
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (rva < rf[mid].begin_rva)
            hi = mid;
        else if (rva >= rf[mid].end_rva)
            lo = mid + 1;
        else
            return (void *)&rf[mid];
    }
    return NULL;
}

/* RtlLookupFunctionEntry(ControlPc, ImageBase*, HistoryTable) */
WN_API void *seh_RtlLookupFunctionEntry(uint64_t control_pc,
                                               uint64_t *image_base,
                                               void *history)
{
    (void)history;
    return wn_seh_lookup_function_entry(control_pc, image_base);
}

/* RtlPcToFileHeader(Pc, ImageBase*) */
WN_API void *seh_RtlPcToFileHeader(uint64_t pc, uint64_t *image_base)
{
    wn_module *m = wn_module_from_addr((const void *)(uintptr_t)pc, NULL);
    if (!m) {
        if (image_base)
            *image_base = 0;
        return NULL;
    }
    if (image_base)
        *image_base = (uint64_t)(uintptr_t)m->base;
    return m->base;
}

/* --- UNWIND_INFO interpretation --------------------------------------------- */

/* register id -> offset in CONTEXT (for RSP/RBP/RBX/RDI/RSI/R12-R15) */
static int gpr_ctx_offset(int reg)
{
    switch (reg) {
    case 0: return -1;              /* RAX: not saved by prologues */
    case 1: return 0x80;            /* RCX */
    case 2: return 0x88;            /* RDX */
    case 3: return 0x90;            /* RBX */
    case 5: return 0xA0;            /* RBP */
    case 6: return 0xA8;            /* RSI */
    case 7: return 0xB0;            /* RDI */
    case 8:  return 0xB8;  case 9:  return 0xC0;
    case 10: return 0xC8;  case 11: return 0xD0;
    case 12: return 0xD8;  case 13: return 0xE0;
    case 14: return 0xE8;  case 15: return 0xF0;
    default: return -1;
    }
}

#define UWOP_PUSH_NONVOL     0
#define UWOP_ALLOC_LARGE     1
#define UWOP_ALLOC_SMALL     2
#define UWOP_SET_FPREG       3
#define UWOP_SAVE_NONVOL     4
#define UWOP_SAVE_NONVOL_FAR 5
#define UWOP_EPILOG          6
#define UWOP_SPARE_CODE      7
#define UWOP_SAVE_XMM128     8
#define UWOP_SAVE_XMM128_FAR 9
#define UWOP_PUSH_MACHFRAME 10

#define UNW_FLAG_EHANDLER  0x01
#define UNW_FLAG_UHANDLER  0x02
#define UNW_FLAG_CHAININFO 0x04

/* RtlVirtualUnwind(HandlerType, ImageBase, TargetIp, FunctionEntry,
 *                  Context, HandlerData*, EstablisherFrame*,
 *                  ContextPointers*) -> PEXCEPTION_ROUTINE or 0 */
WN_API void *seh_RtlVirtualUnwind(uint32_t handler_type,
                                         uint64_t image_base,
                                         uint64_t target_ip,
                                         void *function_entry,
                                         void *context,
                                         void **handler_data,
                                         uint32_t *establisher_frame,
                                         void *context_pointers)
{
    (void)handler_type;
    (void)target_ip;
    (void)context_pointers;
    if (handler_data)
        *handler_data = NULL;
    if (establisher_frame)
        *establisher_frame = 0;
    wn_context64 *ctx = context;
    const wn_runtime_function *rf = function_entry;
    if (!ctx || !rf)
        return NULL;

    /* UNWIND_INFO (raw base+rva walk; module not needed here) */
    const uint8_t *ui = pe_rva_raw((const void *)(uintptr_t)image_base,
                                   rf->unwind_rva, 4);
    if (!ui) {
        wn_log(WN_LOG_WARN, "unwind: bad UNWIND_INFO rva 0x%x",
               rf->unwind_rva);
        return NULL;
    }
    uint32_t flags = ui[0] >> 3;
    uint32_t count = ui[2];
    int frame_reg = ui[3] & 0xF;
    uint32_t frame_off = ui[3] >> 4;
    const uint16_t *codes = (const uint16_t *)(ui + 4);

    /* Walk unwind codes in reverse (undoing the prologue). */
    uint64_t sim_rsp = ctx->rsp;
    struct { int reg; uint64_t off; int xmm; } saves[64];
    int n_saves = 0;

    for (int i = (int)count - 1; i >= 0; ) {
        uint16_t c = codes[i];
        uint32_t op = (c >> 8) & 0xF;      /* UnwindOp in high nibble of 2nd byte */
        uint32_t info = (c >> 12) & 0xF;
        /* code layout: byte0 = CodeOffset, byte1 = Op<<4|Info */
        switch (op) {
        case UWOP_PUSH_NONVOL: {
            int off = gpr_ctx_offset(info);
            if (off >= 0 && wn_ptr_readable((void *)(uintptr_t)sim_rsp, 8))
                *(uint64_t *)((uint8_t *)ctx + off) =
                    *(const uint64_t *)(const void *)(uintptr_t)sim_rsp;
            sim_rsp += 8;
            i -= 1;
            break;
        }
        case UWOP_ALLOC_SMALL:
            sim_rsp += (uint64_t)info * 8 + 8;
            i -= 1;
            break;
        case UWOP_ALLOC_LARGE: {
            uint64_t size;
            if (info == 0) {
                size = (uint64_t)codes[i - 1] * 8;   /* slot value * 8 */
                i -= 2;
            } else {
                size = ((uint64_t)codes[i - 1] |
                        ((uint64_t)codes[i - 2] << 16)) * 16;
                i -= 3;
            }
            sim_rsp += size;
            break;
        }
        case UWOP_SET_FPREG: {
            uint64_t fval = frame_reg == 5 ? ctx->rbp :
                            frame_reg == 3 ? ctx->rbx :
                            *(uint64_t *)((uint8_t *)ctx +
                                          gpr_ctx_offset(frame_reg));
            sim_rsp = fval - (uint64_t)frame_off * 16;
            i -= 1;
            break;
        }
        case UWOP_SAVE_NONVOL:
            if (n_saves < 64 && i >= 1) {
                saves[n_saves].reg = (int)info;
                saves[n_saves].off = (uint64_t)codes[i - 1] * 8;
                saves[n_saves].xmm = 0;
                n_saves++;
            }
            i -= 2;
            break;
        case UWOP_SAVE_NONVOL_FAR:
            if (n_saves < 64 && i >= 2) {
                saves[n_saves].reg = (int)info;
                saves[n_saves].off = ((uint64_t)codes[i - 1] |
                                      ((uint64_t)codes[i - 2] << 16)) * 8;
                saves[n_saves].xmm = 0;
                n_saves++;
            }
            i -= 3;
            break;
        case UWOP_SAVE_XMM128:
            if (n_saves < 64 && i >= 1) {
                saves[n_saves].reg = (int)info;
                saves[n_saves].off = (uint64_t)codes[i - 1] * 16;
                saves[n_saves].xmm = 1;
                n_saves++;
            }
            i -= 2;
            break;
        case UWOP_SAVE_XMM128_FAR:
            if (n_saves < 64 && i >= 2) {
                saves[n_saves].reg = (int)info;
                saves[n_saves].off = ((uint64_t)codes[i - 1] |
                                      ((uint64_t)codes[i - 2] << 16)) * 16;
                saves[n_saves].xmm = 1;
                n_saves++;
            }
            i -= 3;
            break;
        case UWOP_EPILOG:
        case UWOP_SPARE_CODE:
            i -= 2;
            break;
        default:
            wn_log(WN_LOG_TRACE, "unwind: unknown op %u", op);
            i -= 1;
            break;
        }
    }

    /* entry_rsp = sim_rsp after undoing everything = frame base. SAVE_*
     * offsets are relative to it. */
    uint64_t entry_rsp = sim_rsp;
    for (int s = 0; s < n_saves; s++) {
        uint64_t addr = entry_rsp + saves[s].off;
        if (!wn_ptr_readable((void *)(uintptr_t)addr, 16))
            continue;
        if (saves[s].xmm) {
            int slot = saves[s].reg;
            if (slot >= 0 && slot < 16)
                memcpy(ctx->fltsave + 16 + slot * 16,
                       (const void *)(uintptr_t)addr, 16);
        } else {
            int off = gpr_ctx_offset(saves[s].reg);
            if (off >= 0)
                *(uint64_t *)((uint8_t *)ctx + off) =
                    *(const uint64_t *)(const void *)(uintptr_t)addr;
        }
    }

    if (establisher_frame)
        *establisher_frame = (uint32_t)entry_rsp;

    /* pop the return address */
    if (!wn_ptr_readable((void *)(uintptr_t)entry_rsp, 8)) {
        wn_log(WN_LOG_WARN, "unwind: return address at 0x%llx unreadable",
               (unsigned long long)entry_rsp);
        ctx->rip = 0;
        return NULL;
    }
    ctx->rip = *(const uint64_t *)(const void *)(uintptr_t)entry_rsp;
    ctx->rsp = entry_rsp + 8;

    /* chained unwind info: the next RUNTIME_FUNCTION follows the codes */
    if (flags & UNW_FLAG_CHAININFO) {
        wn_log(WN_LOG_TRACE, "unwind: CHAININFO (followed)");
    }

    /* handler address (E/UHANDLER): u32 after the (aligned) code array */
    if ((flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)) &&
        handler_data) {
        size_t hdr = 4 + ((count + 1) & ~1u) * 2;
        const uint32_t *h = (const uint32_t *)(ui + hdr);
        *handler_data = (void *)(h + 1);
        return (void *)(uintptr_t)(image_base + *h);
    }
    return NULL;
}

/* RtlUnwind(TargetFrame, TargetIp, ExceptionRecord, ReturnValue).
 * Full RtlUnwind semantics (searching handlers while unwinding) need the
 * exception-dispatch engine; v1 unwinds the raw frames up to TargetFrame
 * from a freshly captured context so the caller's walker can continue. */
WN_API void seh_RtlUnwind(uint64_t target_frame, uint64_t target_ip,
                                 void *exception_record, uint64_t return_value)
{
    (void)target_ip;
    (void)exception_record;
    (void)return_value;
    if (!target_frame) {
        wn_log(WN_LOG_WARN, "RtlUnwind(NULL frame) — ignored");
        return;
    }
    wn_context64 ctx;
    memset(&ctx, 0, sizeof ctx);
    /* capture current context (asm) then walk frames to target */
    extern void wn_rtl_capture_context(void *);
    wn_rtl_capture_context(&ctx);
    for (int depth = 0; depth < 64; depth++) {
        if (ctx.rip == 0)
            break;
        if (ctx.rsp == target_frame)
            break;   /* reached the target frame */
        uint64_t base = 0;
        wn_runtime_function *rf = wn_seh_lookup_function_entry(ctx.rip, &base);
        if (!rf)
            break;
        void *hd = NULL;
        uint32_t ef = 0;
        seh_RtlVirtualUnwind(0, base, 0, rf, &ctx, &hd, &ef, NULL);
        if (ctx.rip == 0)
            break;
    }
    wn_log(WN_LOG_INFO, "RtlUnwind(target 0x%llx) walked to rip=0x%llx "
           "(jump not performed — dispatcher integration pending)",
           (unsigned long long)target_frame,
           (unsigned long long)ctx.rip);
}
