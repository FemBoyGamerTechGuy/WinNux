/* wow64.c — the i386-on-x86-64 layer. See include/wn_wow64.h for the design
 * and scripts/wow64_probe.c for the sandbox proofs.
 *
 * Low map layout (one RWX mapping, "gates", 1MB at ~0x7F000000):
 *   +0x0000  thunk_gate  (copied from wow64_gates.S, slot patched)
 *   +0x0100  exit_gate   (copied from wow64_gates.S)
 *   +0x0200  ret_thunk32 (32-bit: push 0x33; push exit_gate; retf)
 *   +0x0210  start_ret32 (32-bit: push eax; push 0x33; push exit; retf)
 *   +0x0280  self-test code
 *   +0x1000  thunk stubs (16 bytes each: push funcid; push 0x33; push
 *            thunk_gate; retf)
 */
#include "wn_wow64.h"
#include "wn_process.h"
#include "wn_module.h"
#include "wn_dll.h"
#include "wn_log.h"
#include "wn_util.h"
#include "wn_path.h"
#include "wn_pe.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

int g_wow64_active = 0;
uint32_t g_wow64_peb32, g_wow64_params32, g_wow64_ldr32;
uint32_t g_wow64_env_w32, g_wow64_cmdline_w32, g_wow64_cmdline_a32;

/* from wow64_gates.S */
extern const uint8_t wow64_thunk_gate[], wow64_thunk_gate_end[];
extern const uint8_t wow64_exit_gate[], wow64_exit_gate_end[];
extern void wow64_dispatch_c(wn_wow64_thread *wt, uint64_t *frame);
extern void wow64_enter32_asm(wn_wow64_thread *wt, void *enter_frame);
extern void *wow64_call12(void *fn, uint64_t *a, double *d, int nd);

/* offset asserts (layout is ABI for the .S) */
_Static_assert(offsetof(wn_wow64_thread, teb32) == 0, "wt ABI");
_Static_assert(offsetof(wn_wow64_thread, scratch) == 8, "wt ABI");
_Static_assert(offsetof(wn_wow64_thread, host_fsbase) == 32, "wt ABI");
_Static_assert(offsetof(wn_wow64_thread, exit_blk) == 40, "wt ABI");
_Static_assert(offsetof(wn_wow64_thread, host_rsp) == 48, "wt ABI");
_Static_assert(offsetof(wn_wow64_thread, depth) == 176, "wt ABI");
_Static_assert(offsetof(wn_wow64_thread, start32) == 180, "wt ABI");
_Static_assert(offsetof(wn_wow64_thread, param32) == 184, "wt ABI");

#define TEB64_WOW64_OFF 0xE8     /* inside wn_teb reserved_80 area */

/* 32-bit TEB field offsets (x86 ABI). */
#define TEB32_EXCLIST    0x00
#define TEB32_STACKBASE  0x04
#define TEB32_STACKLIMIT 0x08
#define TEB32_SELF       0x18
#define TEB32_PID        0x20
#define TEB32_TID        0x24
#define TEB32_TLSARRAY   0x2C
#define TEB32_PEB        0x30
#define TEB32_LASTERR    0x34
#define TEB32_TLS_SLOTS  0xE10

/* scratch offsets (inside wt->scratch) */
#define SCR_EXITBLK   0x00
#define SCR_EXITFRAME 0x20
#define SCR_ENTER     0x40
#define SCR_START     0x64
#define SCR_PARAM     0x68

static uint8_t *g_gates;
static uint8_t *g_stubs;          /* g_gates + 0x1000 */
static uint32_t gate_thunk, gate_exit, stub_ret_thunk, stub_start_ret;

/* ------------------------------------------------------------------ gates -- */

static uint32_t build_gates(void)
{
    g_gates = mmap((void *)0x7F000000, 0x100000,
                   PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
    if (g_gates == MAP_FAILED) {
        wn_log(WN_LOG_ERR, "wow64: gate mmap failed: %s", strerror(errno));
        return WN_ERR_GEN_FAILURE;
    }
    g_stubs = g_gates + 0x1000;

    size_t thunksz = (size_t)(wow64_thunk_gate_end - wow64_thunk_gate);
    memcpy(g_gates + 0x00, wow64_thunk_gate, thunksz);
    /* patch the dispatch slot inside the copy */
    {
        extern const uint8_t wow64_thunk_gate_disp[];
        size_t disp_off = (size_t)(wow64_thunk_gate_disp - wow64_thunk_gate);
        *(uint64_t *)(g_gates + 0x00 + disp_off) =
            (uint64_t)(uintptr_t)wow64_dispatch_c;
    }
    memcpy(g_gates + 0x100, wow64_exit_gate,
           (size_t)(wow64_exit_gate_end - wow64_exit_gate));

    /* ret_thunk32: push 0x33; push exit_gate; retf */
    uint8_t *p = g_gates + 0x200;
    p[0] = 0x68; *(uint32_t *)(p + 1) = 0x33;
    p[5] = 0x68; *(uint32_t *)(p + 6) = 0;   /* patched below */
    p[10] = 0xCB;
    /* start_ret32: push eax; push 0x33; push exit_gate; retf */
    uint8_t *q = g_gates + 0x210;
    q[0] = 0x50;
    q[1] = 0x68; *(uint32_t *)(q + 2) = 0x33;
    q[6] = 0x68; *(uint32_t *)(q + 7) = 0;
    q[11] = 0xCB;

    gate_thunk = (uint32_t)(uintptr_t)(g_gates + 0x00);
    gate_exit = (uint32_t)(uintptr_t)(g_gates + 0x100);
    stub_ret_thunk = (uint32_t)(uintptr_t)p;
    stub_start_ret = (uint32_t)(uintptr_t)q;
    *(uint32_t *)(p + 6) = gate_exit;
    *(uint32_t *)(q + 7) = gate_exit;
    return 0;
}

/* ---------------------------------------------------------------- low mem -- */

void *wn_low_mmap(size_t size, int prot, uint64_t hint)
{
    void *p = mmap((void *)(uintptr_t)hint, size, prot,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
    if (p == MAP_FAILED)
        p = mmap(NULL, size, prot, MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT,
                 -1, 0);
    return p;
}

/* low heap: first-fit free lists over a NORESERVE mapping */
#define LH_MAGIC 0x574C3332u   /* "WL32" */
typedef struct lh_hdr {
    uint32_t magic;
    uint32_t size;            /* payload bytes */
    struct lh_hdr *next_free;
} lh_hdr;

static uint8_t *g_lh_base;
static size_t   g_lh_size, g_lh_used;
static lh_hdr  *g_lh_free;

static void lh_init(void)
{
    g_lh_size = 512u << 20;
    g_lh_base = mmap(NULL, g_lh_size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT | MAP_NORESERVE,
                     -1, 0);
    if (g_lh_base == MAP_FAILED) {
        g_lh_size = 64u << 20;
        g_lh_base = mmap(NULL, g_lh_size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
        if (g_lh_base == MAP_FAILED) {
            wn_log(WN_LOG_ERR, "wow64: low heap mmap failed");
            abort();
        }
    }
}

static size_t lh_round(size_t n) { return (n + 15) & ~(size_t)15; }

void *wn_low_malloc(size_t n)
{
    if (!n) n = 1;
    size_t need = lh_round(n) + sizeof(lh_hdr);
    lh_hdr **pp = &g_lh_free;
    for (lh_hdr *h = g_lh_free; h; pp = &h->next_free, h = h->next_free) {
        if (h->magic != LH_MAGIC) continue;
        size_t hsz = lh_round(h->size) + sizeof(lh_hdr);
        if (hsz >= need + 32) {
            lh_hdr *rest = (lh_hdr *)((uint8_t *)h + need);
            rest->magic = LH_MAGIC;
            rest->size = hsz - need - sizeof(lh_hdr);
            rest->next_free = h->next_free;
            *pp = rest;
            h->size = need - sizeof(lh_hdr);
            h->next_free = NULL;
            return (uint8_t *)h + sizeof(lh_hdr);
        }
        if (hsz >= need) {
            *pp = h->next_free;
            h->next_free = NULL;
            return (uint8_t *)h + sizeof(lh_hdr);
        }
    }
    if (g_lh_used + need > g_lh_size) {
        wn_log(WN_LOG_ERR, "wow64: low heap exhausted (%zu used)", g_lh_used);
        return NULL;
    }
    lh_hdr *h = (lh_hdr *)(g_lh_base + g_lh_used);
    g_lh_used += need;
    h->magic = LH_MAGIC;
    h->size = need - sizeof(lh_hdr);
    h->next_free = NULL;
    return (uint8_t *)h + sizeof(lh_hdr);
}

void wn_low_free(void *p)
{
    if (!p) return;
    lh_hdr *h = (lh_hdr *)((uint8_t *)p - sizeof(lh_hdr));
    if (h->magic != LH_MAGIC) {
        wn_log(WN_LOG_WARN, "wow64: low heap free of bad block %p", p);
        return;
    }
    h->next_free = g_lh_free;
    g_lh_free = h;
}

void *wn_low_realloc(void *p, size_t n)
{
    if (!p) return wn_low_malloc(n);
    if (!n) { wn_low_free(p); return NULL; }
    lh_hdr *h = (lh_hdr *)((uint8_t *)p - sizeof(lh_hdr));
    if (h->magic != LH_MAGIC) return NULL;
    if (lh_round(h->size) >= lh_round(n)) {
        h->size = n;
        return p;
    }
    void *np = wn_low_malloc(n);
    if (!np) return NULL;
    memcpy(np, p, h->size < n ? h->size : n);
    wn_low_free(p);
    return np;
}

size_t wn_low_usable(void *p)
{
    if (!p) return 0;
    lh_hdr *h = (lh_hdr *)((uint8_t *)p - sizeof(lh_hdr));
    return h->magic == LH_MAGIC ? h->size : 0;
}

/* --------------------------------------------------------- thread attach -- */

wn_wow64_thread *wn_wow64_thread_current(void)
{
    wn_teb *t = wn_teb_current();
    if (!t) return NULL;
    return (wn_wow64_thread *)(uintptr_t)
        *(volatile uint64_t *)((uint8_t *)t + TEB64_WOW64_OFF);
}

wn_wow64_thread *wn_wow64_thread_attach(void)
{
    wn_teb *teb = wn_teb_current();
    if (!teb) {
        wn_log(WN_LOG_ERR, "wow64: attach without 64-bit TEB");
        return NULL;
    }
    wn_wow64_thread *wt = wn_xcalloc(1, sizeof *wt);
    wt->teb32 = wn_low_mmap(0x1000, PROT_READ | PROT_WRITE, 0);
    wt->scratch = wn_low_malloc(0x100);
    if (wt->teb32 == MAP_FAILED || !wt->scratch) {
        wn_log(WN_LOG_ERR, "wow64: teb32/scratch alloc failed");
        free(wt);
        return NULL;
    }
    memset(wt->teb32, 0, 0x1000);
    memset(wt->scratch, 0, 0x100);
    
    *(uint32_t *)(wt->teb32 + TEB32_SELF) = (uint32_t)(uintptr_t)wt->teb32;
    *(uint32_t *)(wt->teb32 + TEB32_PID) = g_proc.pid;
    *(uint32_t *)(wt->teb32 + TEB32_TID) = wn_alloc_tid();
    *(uint32_t *)(wt->teb32 + TEB32_TLSARRAY) =
        (uint32_t)(uintptr_t)(wt->teb32 + TEB32_TLS_SLOTS);
    *(uint32_t *)(wt->teb32 + TEB32_EXCLIST) = 0xFFFFFFFF;
    if (g_wow64_peb32)
        *(uint32_t *)(wt->teb32 + TEB32_PEB) = g_wow64_peb32;
    wt->exit_blk = (volatile uint64_t *)(wt->scratch + SCR_EXITBLK);
    if (syscall(SYS_arch_prctl, 0x1003 /*ARCH_GET_FS*/, &wt->host_fsbase) != 0)
        wt->host_fsbase = 0;
    *(volatile uint64_t *)((uint8_t *)teb + TEB64_WOW64_OFF) =
        (uint64_t)(uintptr_t)wt;
    return wt;
}

/* ------------------------------------------------------------- PEB32 ---- */

static uint32_t ustr32_new(const char *utf8, uint16_t *out_len)
{
    size_t l = 0;
    uint16_t *w = wn_utf8_to_utf16(utf8, &l);
    if (!w) { if (out_len) *out_len = 0; return 0; }
    uint16_t *low = wn_low_malloc((l + 1) * 2);
    memcpy(low, w, (l + 1) * 2);
    free(w);
    if (out_len) *out_len = (uint16_t)(l * 2);
    return (uint32_t)(uintptr_t)low;
}

static void set_ustr32(uint8_t *base, uint32_t off, uint32_t buf,
                       uint16_t bytelen)
{
    *(uint16_t *)(base + off) = bytelen;
    *(uint16_t *)(base + off + 2) = bytelen;
    *(uint32_t *)(base + off + 4) = buf;
}

void wn_wow64_build_peb32(void)
{
    uint8_t *peb = wn_low_malloc(0x400);
    uint8_t *params = wn_low_malloc(0x200);
    if (!peb || !params) abort();
    memset(peb, 0, 0x400);
    memset(params, 0, 0x200);
    g_wow64_peb32 = (uint32_t)(uintptr_t)peb;
    g_wow64_params32 = (uint32_t)(uintptr_t)params;

    *(uint32_t *)(params + 0x00) = 0x200;   /* MaximumLength */
    *(uint32_t *)(params + 0x04) = 0x200;   /* Length        */

    uint16_t cl = 0;
    g_wow64_cmdline_w32 = ustr32_new(g_proc.cmdline_utf8, &cl);
    g_wow64_cmdline_a32 = (uint32_t)(uintptr_t)
        wn_low_malloc(strlen(g_proc.cmdline_utf8) + 1);
    strcpy((char *)(uintptr_t)g_wow64_cmdline_a32, g_proc.cmdline_utf8);

    /* env block (UTF-16, double-NUL) */
    size_t envn = 0;
    while (g_proc.env_utf16[envn] || g_proc.env_utf16[envn + 1]) envn++;
    envn += 2;
    uint16_t *env = wn_low_malloc(envn * 2);
    memcpy(env, g_proc.env_utf16, envn * 2);
    g_wow64_env_w32 = (uint32_t)(uintptr_t)env;

    char wcwd[2048], wimg[2100];
    wn_path_get_cwd_win(wcwd, sizeof wcwd);
    uint16_t cdlen = 0;
    uint32_t cd = ustr32_new(wcwd, &cdlen);
    uint16_t ilen = 0;
    if (g_proc.exe && g_proc.exe->path[0])
        wn_path_host_to_win(g_proc.exe->path, wimg, sizeof wimg);
    else
        snprintf(wimg, sizeof wimg, "C:\\");
    uint32_t img = ustr32_new(wimg, &ilen);

    set_ustr32(params, 0x24, cd, cdlen);        /* CurrentDirectory.DosPath */
    *(uint32_t *)(params + 0x2C) = 0;           /* .Handle */
    set_ustr32(params, 0x30, 0, 0);             /* DllPath */
    set_ustr32(params, 0x38, img, ilen);        /* ImagePathName */
    set_ustr32(params, 0x40, g_wow64_cmdline_w32, cl);  /* CommandLine */
    *(uint32_t *)(params + 0x48) = g_wow64_env_w32;     /* Environment */

    /* PEB_LDR_DATA32 */
    uint8_t *ldr = wn_low_malloc(0x40);
    memset(ldr, 0, 0x40);
    g_wow64_ldr32 = (uint32_t)(uintptr_t)ldr;
    *(uint32_t *)(ldr + 0x00) = 0x30;
    *(uint32_t *)(ldr + 0x04) = 1;
    for (int li = 0; li < 3; li++) {
        uint32_t head = g_wow64_ldr32 + 0x0C + li * 8;
        *(uint32_t *)(uintptr_t)(head) = head;
        *(uint32_t *)(uintptr_t)(head + 4) = head;
    }

    /* PEB (x86 offsets) */
    peb[2] = 0;
    if (g_proc.exe)
        *(uint32_t *)(peb + 0x08) = (uint32_t)(uintptr_t)g_proc.exe->base;
    *(uint32_t *)(peb + 0x0C) = g_wow64_ldr32;
    *(uint32_t *)(peb + 0x10) = g_wow64_params32;
    *(uint32_t *)(peb + 0x18) = (uint32_t)(uintptr_t)g_proc.process_heap;
    *(uint32_t *)(peb + 0x64) = (uint32_t)sysconf(_SC_NPROCESSORS_ONLN);
    *(uint32_t *)(peb + 0x74) = 5;      /* OSMajorVersion */
    *(uint32_t *)(peb + 0x78) = 1;      /* OSMinorVersion */
    *(uint16_t *)(peb + 0x7C) = 2600;   /* OSBuildNumber  */
    *(uint32_t *)(peb + 0x80) = 2;      /* OSPlatformId   */
}

void wn_wow64_ldr_add_module(struct wn_module *m)
{
    if (!g_wow64_ldr32) return;
    uint8_t *ent = wn_low_malloc(0x60);
    if (!ent) return;
    memset(ent, 0, 0x60);
    uint32_t ent32 = (uint32_t)(uintptr_t)ent;
    *(uint32_t *)(ent + 0x18) = (uint32_t)(uintptr_t)m->base;
    *(uint32_t *)(ent + 0x20) = (uint32_t)m->pe.size_of_image;

    char wfull[2100], wbase[128];
    if (m->path[0])
        wn_path_host_to_win(m->path, wfull, sizeof wfull);
    else
        snprintf(wfull, sizeof wfull, "C:\\windows\\system32\\%s", m->name);
    snprintf(wbase, sizeof wbase, "%s", m->name);
    uint16_t lf = 0, lb = 0;
    uint32_t full32 = ustr32_new(wfull, &lf);
    uint32_t base32 = ustr32_new(wbase, &lb);
    set_ustr32(ent, 0x24, full32, lf);
    set_ustr32(ent, 0x2C, base32, lb);

    for (int li = 0; li < 3; li++) {
        uint32_t head = g_wow64_ldr32 + 0x0C + li * 8;
        uint32_t first = *(uint32_t *)(uintptr_t)(head);
        uint32_t ent_link = ent32 + li * 8;
        *(uint32_t *)(uintptr_t)(ent_link) = first;
        *(uint32_t *)(uintptr_t)(ent_link + 4) = head;
        *(uint32_t *)(uintptr_t)(first) = ent_link;
        *(uint32_t *)(uintptr_t)(head + 4) = ent_link;
    }
    m->ldr_entry = (void *)(uintptr_t)ent32;
}

/* ------------------------------------------------------------------ dispatch */

typedef struct {
    void    *fn;
    uint16_t cleanup;
    uint8_t  flags;
    uint8_t  n_double;
    uint64_t hash;            /* dedup key (fn address) */
    uint32_t stub;
    char     name[96];
} thunk_ent;

static thunk_ent *g_thunks;
static uint32_t g_thunk_n;

static uint32_t thunk_emit(uint32_t funcid)
{
    uint8_t *p = g_stubs + (size_t)funcid * 16;
    p[0] = 0x68; *(uint32_t *)(p + 1) = funcid;
    p[5] = 0x68; *(uint32_t *)(p + 6) = 0x33;
    p[10] = 0x68; *(uint32_t *)(p + 11) = gate_thunk;
    p[15] = 0xCB;
    return (uint32_t)(uintptr_t)p;
}

static uint32_t thunk_register(void *fn, const char *dll, const char *name,
                               uint16_t cleanup, uint8_t flags,
                               uint8_t n_double)
{
    if (!g_thunks) {
        g_thunks = wn_xmalloc(8192 * sizeof *g_thunks);
        memset(g_thunks, 0, 8192 * sizeof *g_thunks);
    } else if (g_thunk_n >= 8192) {
        wn_log(WN_LOG_ERR, "wow64: thunk table full");
        return 0;
    }
    thunk_ent *e = &g_thunks[g_thunk_n];
    e->fn = fn;
    e->cleanup = cleanup;
    e->flags = flags;
    e->n_double = n_double;
    e->hash = (uint64_t)(uintptr_t)fn;
    e->stub = thunk_emit(g_thunk_n);
    snprintf(e->name, sizeof e->name, "%s!%s", dll ? dll : "?",
             name ? name : "?");
    return g_thunks[g_thunk_n++].stub;
}

/* crt-family DLLs are cdecl on x86 (caller cleans) */
static int dll_is_crt(const char *dll)
{
    static const char *crt[] = {
        "msvcrt.dll", "ucrtbase.dll", "crtdll.dll", "msvcr90.dll",
        "msvcr100.dll", "msvcr110.dll", "msvcr120.dll", "msvcrtd.dll",
        "vcruntime140.dll", "vcruntime140_1.dll", NULL,
    };
    char low[64];
    wn_strlower(low, sizeof low, dll ? dll : "");
    for (int i = 0; crt[i]; i++)
        if (!strcmp(low, crt[i]))
            return 1;
    return 0;
}

uint32_t wn_wow64_thunk_for(void *fn, const char *dll_name, const char *name)
{
    for (uint32_t i = 0; i < g_thunk_n; i++)
        if (g_thunks[i].hash == (uint64_t)(uintptr_t)fn)
            return g_thunks[i].stub;

    wn_sig32 sig;
    memset(&sig, 0, sizeof sig);
    if (!wn_sig32_lookup(name, &sig)) {
        /* unknown signature (rare): 4-word stdcall guess */
        sig.cleanup = 4;
        sig.arity = 4;
    }
    if (sig.flags & WN32_VARARG || dll_is_crt(dll_name))
        sig.cleanup = 0;
    return thunk_register(fn, dll_name, name, sig.cleanup, sig.flags,
                          sig.n_double);
}

uint32_t wn_wow64_stub32_for(const char *dll_name, const char *name)
{
    return thunk_register(NULL, dll_name, name, 0, WN32_CDECL | WN32_STUB32, 0);
}

uint32_t wn_wow64_data32_for(const void *obj)
{
    void *p = wn_low_malloc(64);
    if (!p) return 0;
    memcpy(p, obj, 64);
    return (uint32_t)(uintptr_t)p;
}

/* C dispatcher: called by thunk_gate (frame = the 32-bit stack view). */
void wow64_dispatch_c(wn_wow64_thread *wt, uint64_t *frame)
{
    uint32_t funcid = *(uint32_t *)frame;

    uint32_t ret32 = *(uint32_t *)((uint8_t *)frame + 4);
    uint32_t *args = (uint32_t *)((uint8_t *)frame + 8);
    if (funcid >= g_thunk_n) {
        wn_log(WN_LOG_ERR, "wow64: bad funcid %u", funcid);
        wt->exit_blk[0] = 0;
        wt->exit_blk[1] = (uint32_t)(uintptr_t)frame + 8;
        wt->exit_blk[2] = ret32;
        wt->exit_blk[3] = 0;
        return;
    }
    thunk_ent *ent = &g_thunks[funcid];

    uint64_t a[12];
    double d[3];
    uint64_t ret = 0, ret_hi = 0;
    memset(a, 0, sizeof a);
    memset(d, 0, sizeof d);

    if (ent->flags & WN32_STUB32) {
        wn_log(WN_LOG_WARN, "wow64: stub32 %s called (returning 0)",
               ent->name);
    } else if (ent->flags & WN32_VARARG) {
        a[0] = args[0];
        a[1] = (uint64_t)(uintptr_t)(args + 1);
        ret = (uint64_t)(uintptr_t)wow64_call12(ent->fn, a, d, 0);
    } else {
        int nd = 0;
        uint32_t word = 0;
        for (int i = 0; i < ent->n_double && i < 3; i++) {
            memcpy(&d[i], args + word, 8);
            word += 2;
            nd++;
        }
        for (int gp = 0; gp < 12 && word < 12; gp++, word++)
            a[gp] = args[word];
        ret = (uint64_t)(uintptr_t)wow64_call12(ent->fn, a, d, nd);
        if (ent->flags & WN32_RET64)
            ret_hi = ret >> 32;
    }


    uint32_t esp = (uint32_t)(uintptr_t)frame + 8 + ent->cleanup * 4;
    wt->exit_blk[0] = ret;
    wt->exit_blk[1] = esp;
    wt->exit_blk[2] = ret32;
    wt->exit_blk[3] = ret_hi;
    /* pass rax/rdx through to the gate (see the asm contract) */
    __asm__ volatile("" : : "a"(ret), "d"(ret_hi));
}

/* ------------------------------------------------------------------ call32 */

int wn_wow64_call32(uint32_t target, uint32_t *esp_io, uint32_t regs_io[7])
{
    wn_wow64_thread *wt = wn_wow64_thread_current();
    if (!wt) {
        wn_log(WN_LOG_ERR, "wow64: call32 without attached thread");
        return -1;
    }
    if (wt->depth >= 15) {
        wn_log(WN_LOG_ERR, "wow64: call32 depth overflow");
        return -1;
    }
    uint8_t *ef = wt->scratch + SCR_ENTER;
    memset(ef, 0, 0x24);
    uint32_t esp32 = *esp_io - 4;
    *(uint32_t *)(uintptr_t)esp32 = stub_ret_thunk;
    *(uint32_t *)(ef + 0) = target;
    *(uint32_t *)(ef + 4) = esp32;
    for (int i = 0; i < 7; i++)
        *(uint32_t *)(ef + 8 + i * 4) = regs_io[i];

    wt->depth++;
    wow64_enter32_asm(wt, ef);
    wt->depth--;

    uint8_t *ex = wt->scratch + SCR_EXITFRAME;
    static const int map[7] = {0, 1, 2, 3, 4, 5, 6};
    for (int i = 0; i < 7; i++)
        regs_io[i] = *(uint32_t *)(ex + map[i] * 4);
    *esp_io = *(uint32_t *)(ex + 28);
    return 0;
}

/* startup: kernel32-style stack for the exe entry point */
void wn_wow64_run_exe(uint32_t entry)
{
    wn_wow64_thread *wt = wn_wow64_thread_current();
    if (!wt) {
        wn_log(WN_LOG_ERR, "wow64: run_exe without thread");
        wn_process_exit(1);
    }

    /* argv from the command line (both MSVC and mingw CRTs accept this) */
    char **argv = wn_xcalloc(64, sizeof(char *));
    uint32_t argc = 0;
    {
        char *p = g_proc.cmdline_utf8;
        int inq = 0;
        char *start = p;
        for (char *c = p; ; c++) {
            if (*c == '"') { inq = !inq; continue; }
            if (!*c || (!inq && *c == ' ')) {
                if (c > start) {
                    size_t len = (size_t)(c - start);
                    char *s = wn_xmalloc(len + 1);
                    memcpy(s, start, len);
                    s[len] = 0;
                    if (argc < 63) argv[argc++] = s;
                }
                while (*c == ' ') c++;
                start = c;
                if (!*c) break;
                c--;
            }
        }
        if (argc == 0) { argv[0] = wn_xstrdup("app"); argc = 1; }
    }
    uint32_t argv32 = (uint32_t)(uintptr_t)wn_low_malloc((argc + 1) * 4);
    uint32_t *ap = (uint32_t *)(uintptr_t)argv32;
    for (uint32_t i = 0; i < argc; i++) {
        size_t l = strlen(argv[i]) + 1;
        uint32_t s = (uint32_t)(uintptr_t)wn_low_malloc(l);
        strcpy((char *)(uintptr_t)s, argv[i]);
        ap[i] = s;
    }
    ap[argc] = 0;

    uint32_t esp32 = (uint32_t)(uintptr_t)(wt->stack_low + wt->stack_size);
    esp32 &= ~15u;
    esp32 -= 16;
    *(uint32_t *)(uintptr_t)(esp32 + 0) = stub_start_ret;
    *(uint32_t *)(uintptr_t)(esp32 + 4) = argc;
    *(uint32_t *)(uintptr_t)(esp32 + 8) = argv32;
    *(uint32_t *)(uintptr_t)(esp32 + 12) = 0;

    uint32_t regs[7] = {0};
    wn_wow64_call32(entry, &esp32, regs);
    wn_log(WN_LOG_INFO, "wow64: exe entry returned eax=%u", regs[0]);
    wn_process_exit((int)(int32_t)regs[0]);
}

/* ------------------------------------------------------------------- faults */

/* x86 reg indices for our decode */
enum { XEAX, XECX, XEDX, XEBX, XESP, XEBP, XESI, XEDI };

static uint32_t *greg32(ucontext_t *uc, int r)
{
    static const int g[] = { REG_RAX, REG_RCX, REG_RDX, REG_RBX,
                             REG_RSP, REG_RBP, REG_RSI, REG_RDI };
    if (r < 0 || r > 7) return NULL;
    return (uint32_t *)&uc->uc_mcontext.gregs[g[r]];
}

/* Emulate one fs-prefixed instruction against teb32.
 * 1 = emulated, 0 = not ours, -1 = error. */
static int fs_emulate(ucontext_t *uc, unsigned long fault_addr)
{
    uint8_t *rip = (uint8_t *)uc->uc_mcontext.gregs[REG_RIP];
    wn_wow64_thread *wt = wn_wow64_thread_current();
    if (!wt) return -1;
    uint8_t *teb = wt->teb32;
    (void)fault_addr;

    int o = 0, op16 = 0, has_fs = 0;
    for (;;) {
        uint8_t b = rip[o];
        if (b == 0x64) { has_fs = 1; o++; }
        else if (b == 0x66) { op16 = 1; o++; }
        else if (b == 0x67) return 0;          /* 16-bit addressing: bail */
        else if (b == 0x2E || b == 0x3E || b == 0x26 || b == 0x36 ||
                 b == 0xF0 || b == 0xF2 || b == 0xF3) o++;
        else break;
        if (o > 6) return 0;
    }
    if (!has_fs) return 0;

    uint8_t op = rip[o++];
    int size = op16 ? 2 : 4;

    /* moffs forms */
    if (op >= 0xA0 && op <= 0xA3) {
        uint32_t disp = *(uint32_t *)(rip + o);
        uint64_t lin = (uint64_t)(uintptr_t)teb + disp;
        o += 4;
        if (op == 0xA1 && !op16) {
            if (lin + 4 > (uint64_t)(uintptr_t)teb + 0x1000) return 0;
            uc->uc_mcontext.gregs[REG_RAX] = *(uint32_t *)lin;
        } else if (op == 0xA1) {
            if (lin + 2 > (uint64_t)(uintptr_t)teb + 0x1000) return 0;
            uc->uc_mcontext.gregs[REG_RAX] = *(uint16_t *)lin;
        } else if (op == 0xA3 && !op16) {
            if (lin + 4 > (uint64_t)(uintptr_t)teb + 0x1000) return 0;
            *(uint32_t *)lin = (uint32_t)uc->uc_mcontext.gregs[REG_RAX];
        } else if (op == 0xA3) {
            if (lin + 2 > (uint64_t)(uintptr_t)teb + 0x1000) return 0;
            *(uint16_t *)lin = (uint16_t)uc->uc_mcontext.gregs[REG_RAX];
        } else return 0;
        uc->uc_mcontext.gregs[REG_RIP] += o;
        return 1;
    }

    /* classify opcode */
    int is_mov_to_reg = 0, is_mov_to_mem = 0, is_push = 0, is_pop = 0,
        is_alu = 0, is_imm = 0, is_movzx = 0, is_xchg = 0, is_group = 0;
    uint8_t group_sub = 0;
    switch (op) {
    case 0x8B: is_mov_to_reg = 1; break;
    case 0x89: is_mov_to_mem = 1; break;
    case 0x8A: is_mov_to_reg = 1; size = 1; break;
    case 0x88: is_mov_to_mem = 1; size = 1; break;
    case 0x03: case 0x0B: case 0x1B: case 0x23: case 0x2B: case 0x33:
    case 0x3A: case 0x3B:
        is_alu = 1; size = (op == 0x3A) ? 1 : (op16 ? 2 : 4); break;
    case 0xC6: is_mov_to_mem = 1; is_imm = 1; size = 1; break;
    case 0xC7: is_mov_to_mem = 1; is_imm = 1; break;
    case 0xFF: is_group = 1; break;
    case 0x8F: is_pop = 1; break;
    case 0x87: is_xchg = 1; break;
    case 0x86: is_xchg = 1; size = 1; break;
    case 0xF7: is_group = 1; break;
    case 0x0F: {
        uint8_t hi = rip[o++];
        if (hi == 0xB6 || hi == 0xBE) { is_movzx = 1; size = 1; }
        else if (hi == 0xB7 || hi == 0xBF) { is_movzx = 1; size = 2; }
        else return 0;
        break;
    }
    default: return 0;
    }

    if (is_group) {
        uint8_t modrm = rip[o];
        group_sub = (modrm >> 3) & 7;
        if (op == 0xFF && group_sub == 6) is_push = 1;
        else if (op == 0xFF && (group_sub == 0 || group_sub == 1))
            is_alu = 1;                       /* inc/dec rm */
        else if (op == 0xF7 && group_sub == 0) { is_alu = 1; is_imm = 1; }
        else return 0;
    }

    uint8_t modrm = rip[o++];
    uint8_t mod = modrm >> 6, reg = (modrm >> 3) & 7, rm = modrm & 7;
    if (mod == 3) return 0;

    int64_t disp = 0;
    if (mod == 1) { disp = (int8_t)rip[o]; o += 1; }
    else if (mod == 2) { disp = (int32_t)*(uint32_t *)(rip + o); o += 4; }

    uint64_t base = 0;
    if (rm == 4) {
        uint8_t sib = rip[o++];
        int scale = 1 << (sib >> 6);
        int index = (sib >> 3) & 7;
        int baser = sib & 7;
        if (index != 4)
            base += (uint64_t)*greg32(uc, index) * scale;
        if (mod == 0 && baser == 5) {
            disp = (int32_t)*(uint32_t *)(rip + o); o += 4;
        } else {
            base += *greg32(uc, baser);
        }
    } else if (mod == 0 && rm == 5) {
        disp = (int32_t)*(uint32_t *)(rip + o); o += 4;
    } else {
        base = *greg32(uc, rm);
    }

    uint64_t lin = (uint64_t)(uintptr_t)teb + (uint64_t)(int64_t)disp + base;
    if (lin < (uint64_t)(uintptr_t)teb ||
        lin + 8 > (uint64_t)(uintptr_t)teb + 0x1000)
        return 0;

    int imm_off = 0;
    if (is_imm) {
        if (op == 0xC6 || (op == 0xF7 && size == 1)) imm_off = 1;
        else imm_off = op16 ? 2 : 4;
        o += imm_off;
    }

    /* execute */
    uint64_t val = 0;
    int need_read = is_mov_to_reg || is_alu || is_push || is_movzx || is_xchg;
    if (need_read) {
        if (size == 1) val = *(uint8_t *)lin;
        else if (size == 2) val = *(uint16_t *)lin;
        else val = *(uint32_t *)lin;
    }

    if (is_push) {
        uint32_t *esp = greg32(uc, XESP);
        *esp -= 4;
        uint32_t dst = *esp;
        if (dst < 0x10000) return 0;
        *(uint32_t *)(uintptr_t)dst = (uint32_t)val;
    } else if (is_pop) {
        uint32_t *esp = greg32(uc, XESP);
        uint32_t src = *esp;
        if (src < 0x10000) return 0;
        uint32_t v = *(uint32_t *)(uintptr_t)src;
        *esp += 4;
        *(uint32_t *)lin = v;
    } else if (is_mov_to_mem) {
        uint64_t v;
        if (is_imm) {
            if (imm_off == 1) v = rip[o - 1];
            else if (op16) v = (uint64_t)*(uint16_t *)(rip + o - 2);
            else v = (uint64_t)*(uint32_t *)(rip + o - 4);
        } else {
            v = *greg32(uc, reg);
        }
        if (size == 1) *(uint8_t *)lin = (uint8_t)v;
        else if (size == 2) *(uint16_t *)lin = (uint16_t)v;
        else *(uint32_t *)lin = (uint32_t)v;
    } else if (is_xchg) {
        uint32_t *r32 = greg32(uc, reg);
        uint32_t old = (size == 1) ? (*r32 & 0xFFu) : *r32;
        if (size == 1) *(uint8_t *)lin = (uint8_t)old;
        else *(uint32_t *)lin = old;
        if (size == 1) *r32 = (*r32 & ~0xFFu) | (uint32_t)(val & 0xFFu);
        else *r32 = (uint32_t)val;
    } else if (is_movzx) {
        *greg32(uc, reg) = (uint32_t)val;   /* zext (size already limits) */
    } else if (is_mov_to_reg) {
        uint32_t *r32 = greg32(uc, reg);
        if (size == 1) {
            if (reg < 4) *r32 = (*r32 & ~0xFFu) | (uint32_t)(val & 0xFFu);
            else *r32 = (*r32 & ~0xFF00u) |
                        (uint32_t)((val & 0xFFu) << 8);
        } else if (size == 2) {
            *r32 = (*r32 & ~0xFFFFu) | (uint32_t)(val & 0xFFFFu);
        } else {
            *r32 = (uint32_t)val;
        }
    } else if (is_alu) {
        /* load rm into reg (flags are not modeled; TEB field compares work
         * by value. inc/dec loads the new value minus/plus one) */
        uint32_t *r32 = greg32(uc, reg);
        if (is_group && op == 0xFF && group_sub == 0) *r32 = (uint32_t)val + 1;
        else if (is_group && op == 0xFF && group_sub == 1)
            *r32 = (uint32_t)val - 1;
        else if (size == 1) *r32 = (val & 0xFFu);
        else if (size == 2) *r32 = (val & 0xFFFFu);
        else *r32 = (uint32_t)val;
    }

    uc->uc_mcontext.gregs[REG_RIP] += o;
    return 1;
}

int wn_wow64_fault_hook(void *uc_, void *fault_addr_v, int si_code, int sig)
{
    if (!g_wow64_active) return 0;
    ucontext_t *uc = (ucontext_t *)uc_;
    unsigned short cs = (unsigned)(uc->uc_mcontext.gregs[REG_CSGSFS] & 0xFFFF);
    if (cs != 0x23) return 0;

    /* CRITICAL ORDER: restore glibc's FS base BEFORE any libc call (a
     * handler that calls snprintf with the guest FS state crashes and the
     * kernel kills the process with no diagnostic at all). */
    wn_wow64_thread *wt = wn_wow64_thread_current();
    if (!wt) return 0;
    if (wt->host_fsbase)
        syscall(SYS_arch_prctl, 0x1002, wt->host_fsbase);


    if (sig == SIGSEGV || sig == SIGBUS) {
        int r = fs_emulate(uc, (unsigned long)(uintptr_t)fault_addr_v);
        if (r == 1) {
            static uint32_t emu_count;
            emu_count++;
            if ((emu_count & 0xFFFF) == 1)
                wn_log(WN_LOG_DEBUG, "wow64: fs emulation #%u at rip=%p",
                       emu_count, (void *)(uintptr_t)uc->uc_mcontext.gregs[REG_RIP]);
            return 1;
        }
    }

    /* real guest fault: report and die (32-bit frame-based SEH comes later) */
    wn_log(WN_LOG_ERR, "wow64: guest fault addr=%p code=%d sig=%d rip=0x%llx",
           fault_addr_v, si_code, sig,
           (unsigned long long)uc->uc_mcontext.gregs[REG_RIP]);
    char w[96];
    wn_module_describe_addr((const void *)(uintptr_t)
                            uc->uc_mcontext.gregs[REG_RIP], w, sizeof w);
    wn_log(WN_LOG_ERR, "wow64: faulting ip: %s", w);
    {
        uint32_t r[8];
        static const int gr[] = { REG_RAX, REG_RBX, REG_RCX, REG_RDX,
                                  REG_RSI, REG_RDI, REG_RBP, REG_RSP };
        for (int i = 0; i < 8; i++)
            memcpy(&r[i], &uc->uc_mcontext.gregs[gr[i]], 4);
        wn_log(WN_LOG_ERR, "wow64: regs eax=%x ebx=%x ecx=%x edx=%x esi=%x "
               "edi=%x ebp=%x esp=%x", r[0], r[1], r[2], r[3], r[4], r[5],
               r[6], r[7]);
    }
    return 0;   /* let the normal crash path run */
}

/* --------------------------------------------------------------------- init */

int wn_wow64_ready(void) { return g_gates != NULL; }


uint32_t wn_wow64_init(void)
{
    uint32_t rc;
    if (g_wow64_active) return 0;
    if ((rc = build_gates()) != 0) return rc;
    lh_init();
    g_wow64_active = 1;

    wn_wow64_thread *wt = wn_wow64_thread_attach();
    if (!wt) { g_wow64_active = 0; return WN_ERR_GEN_FAILURE; }
    wt->stack_low = wn_low_mmap(0x101000, PROT_READ | PROT_WRITE, 0);
    if (wt->stack_low == MAP_FAILED) {
        g_wow64_active = 0;
        return WN_ERR_GEN_FAILURE;
    }
    mprotect(wt->stack_low, 0x1000, PROT_NONE);   /* overflow guard */
    wt->stack_size = 0x100000;

    /* self test: mov eax, 0x5A5A; ret (32-bit) */
    uint8_t *t = g_gates + 0x280;
    t[0] = 0xB8; *(uint32_t *)(t + 1) = 0x5A5A; t[5] = 0xC3;
    uint32_t esp = (uint32_t)(uintptr_t)(wt->stack_low + wt->stack_size);
    esp &= ~15u;
    uint32_t regs[7] = {0};
    if (wn_wow64_call32((uint32_t)(uintptr_t)t, &esp, regs) != 0 ||
        regs[0] != 0x5A5A) {
        wn_log(WN_LOG_ERR, "wow64: 32-bit self test FAILED (eax=0x%x)",
               regs[0]);
        g_wow64_active = 0;
        return WN_ERR_GEN_FAILURE;
    }

    /* thunk self test: a builtin with a known signature — strlen via a
     * wrapper is not available; test with GetLastError (0 args, stdcall). */
    wn_log(WN_LOG_INFO, "wow64: initialized (self test ok)");
    return 0;
}

int wn_wow64_is_gate_addr(const void *addr)
{
    return g_gates && (uint8_t *)addr >= g_gates &&
           (uint8_t *)addr < g_gates + 0x100000;
}
