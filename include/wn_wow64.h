/* wn_wow64.h — WoW64 layer: run 32-bit (i386) Windows code natively on this
 * x86-64 host in compatibility mode, with thunks to the 64-bit builtins.
 *
 * Design (proven by scripts/wow64_probe.c on this exact sandbox kernel):
 *  - 32-bit code segment: the kernel's own __USER32_CS (0x23); flat data via
 *    __USER_DS (0x2b). No modify_ldt / set_thread_area / FSGSBASE needed
 *    (all unavailable here; see HANDOFF).
 *  - %fs has no usable descriptor (arch_prctl(SET_FS) zeroes the selector and
 *    loading a selector zeroes the base), so guest fs:[x] accesses fault at
 *    linear address x; the SIGSEGV handler decodes the fs-prefixed
 *    instruction and emulates it against the 32-bit TEB.
 *  - Guest->builtin calls go through 16-byte 32-bit stubs that far-return
 *    (retf) into a low-memory 64-bit gate; the gate restores the host %fs
 *    base (one arch_prctl per call), dispatches to the 64-bit ms_abi
 *    implementation via a generic 12-argument bridge, then far-returns
 *    (retfq) back into the guest with stdcall stack cleanup.
 *  - Every pointer handed to a 32-bit guest must live below 4GB: a low
 *    arena provides the heap, stacks, TEBs and thunk code.
 */
#ifndef WN_WOW64_H
#define WN_WOW64_H

#include <stdint.h>
#include <stddef.h>

/* Signature bits for 32-bit dispatch. */
#define WN32_CDECL   0x01   /* caller cleans stack (msvcrt family)        */
#define WN32_VARARG  0x02   /* impl receives (arg0, va32) - see dispatch  */
#define WN32_RET64   0x04   /* returns 64-bit value in EDX:EAX            */
#define WN32_DOUBLE  0x10   /* has by-value double params -> XMM0-2       */
#define WN32_STUB32  0x20   /* registered missing-import stub (logs, 0)    */

struct wn_module;

typedef struct {
    uint16_t cleanup;    /* 32-bit words the callee pops (stdcall) */
    uint16_t arity;      /* declared parameter count                */
    uint8_t  flags;      /* WN32_*                                  */
    uint8_t  n_double;   /* leading by-value double/float params    */
} wn_sig32;

/* Generated from the builtin sources by scripts/dev/gen_sigs32.py.
 * Returns 1 and fills *out when fn is a known WN_API builtin; else 0. */
int wn_sig32_lookup(const char *name, wn_sig32 *out);

/* Per-thread 32-bit execution state. Layout is ABI for wow64_gates.S —
 * offsets asserted at init (see wow64.c). */
typedef struct wn_wow64_thread {
    uint8_t *teb32;                /* 0   low: x86 TEB (0x1000)          */
    uint8_t *scratch;              /* 8   low block (see below)          */
    uint8_t *stack_low;            /* 16  low stack mapping base         */
    uint32_t stack_size;           /* 24  usable bytes                   */
    uint64_t host_fsbase;          /* 32  glibc TCB, saved at attach     */
    volatile uint64_t *exit_blk;   /* 40  -> scratch+0 (host pointer)    */
    uint64_t host_rsp[16];         /* 48  call32 depth stack             */
    int      depth;                /* 176                                */
    uint32_t start32;              /* 180 CreateThread start             */
    uint32_t param32;              /* 184                                */
    struct wn_wow64_thread *self;  /* 192                                */
    uint8_t *seh_low;              /* 200 low SEH scratch (0x400)        */
    uint32_t dispatch32;           /* 208 builtin serves a 32-bit caller */
    uint32_t args32;               /* 212 guest esp at the args (debug)  */
} wn_wow64_thread;

/* scratch layout (low, 0x100): 0x00 exit_blk (4 u64: retval, new_esp32,
 * ret32, ret_hi), 0x20 exit_frame (8 u32: eax,ebx,ecx,edx,esi,edi,ebp,esp),
 * 0x40 enter frame (target32, esp32, 7 regs), 0x64 start32/param32 slots. */

/* ---- process-level ------------------------------------------------------- */

/* Global: this process runs a 32-bit image. */
extern int g_wow64_active;

/* Low-address PEB32 & friends (see wow64.c). */
extern uint32_t g_wow64_peb32, g_wow64_params32, g_wow64_ldr32;
extern uint32_t g_wow64_env_w32, g_wow64_cmdline_w32, g_wow64_cmdline_a32;

/* Initialize the wow64 layer (arena, gates, stub cache, self test). Called
 * by the loader once the main exe turns out to be PE32. 0 on success. */
uint32_t wn_wow64_init(void);

/* Is the wow64 layer initialized? */
int wn_wow64_ready(void);

/* Attach the current host thread to 32-bit execution (TEB32 + scratch).
 * Idempotent per thread. Returns the state or NULL. */
wn_wow64_thread *wn_wow64_thread_attach(void);

/* Current thread's state (via the 64-bit TEB back-pointer). NULL when the
 * thread never attached. */
wn_wow64_thread *wn_wow64_thread_current(void);

/* Build the x86 PEB/params/LDR skeleton. Called once after the exe module
 * is registered (exe base known, process heap exists). */
void wn_wow64_build_peb32(void);

/* Add a module to the 32-bit PEB LDR lists (called by the loader for every
 * module while wow64 is active). */
void wn_wow64_ldr_add_module(struct wn_module *m);

/* ---- imports / thunks ------------------------------------------------------ */

/* Get (or create) the 32-bit thunk stub for a builtin export.
 * dll_name/name are used for logging and cdecl classification.
 * Returns a low stub address (guest-callable) or 0 on failure. */
uint32_t wn_wow64_thunk_for(void *fn, const char *dll_name, const char *name);

/* Missing-import stub for 32-bit guests: logs dll!name and returns 0
 * (cdecl - arity unknown, imbalance is logged). */
uint32_t wn_wow64_stub32_for(const char *dll_name, const char *name);

/* A data export for a 32-bit importer: copies the object into low memory
 * and returns its low address. */
uint32_t wn_wow64_data32_for(const void *obj);

/* ---- execution ------------------------------------------------------------- */

/* Call 32-bit code from the 64-bit side (used for SEH handlers, entry
 * points, thread starts). regs_io layout: [eax,ebx,ecx,edx,esi,edi,ebp].
 * esp_io: in = guest esp with args already pushed; out = esp at return. */
int wn_wow64_call32(uint32_t target, uint32_t *esp_io, uint32_t regs_io[7]);

/* Run the main 32-bit exe: startup stack (kernel32-style return address,
 * argc/argv/envp) then the entry point. Never returns. */
void wn_wow64_run_exe(uint32_t entry) __attribute__((noreturn));

/* ---- memory ---------------------------------------------------------------- */

/* Low-memory heap (guest-visible < 4GB). */
void *wn_low_malloc(size_t n);
void  wn_low_free(void *p);
void *wn_low_realloc(void *p, size_t n);
size_t wn_low_usable(void *p);

/* Map below 4GB (MAP_32BIT). hint may be the PE preferred base. */
void *wn_low_mmap(size_t size, int prot, uint64_t hint);

/* ---- fault hook (called from seh.c first) ---------------------------------- */

/* Returns 1 when the fault was handled (guest state patched, resume). */
int wn_wow64_fault_hook(void *uc_, void *fault_addr_v, int si_code, int sig);

/* Query: is addr inside the gate/thunk region (for crash reporting)? */
int wn_wow64_is_gate_addr(const void *addr);

/* Is the CURRENT builtin invocation serving a 32-bit guest call? Layout-
 * sensitive struct writers (SYSTEM_INFO, MEMORY_BASIC_INFORMATION, ...) must
 * use the i386 layout when this returns 1 - the host build is x86-64 even
 * while running an i386 guest in-process, so compile-time #if is WRONG for
 * the in-process wow64 path (found via the LuaForWindows installer). */
int wn_wow64_guest32(void);

/* Write a HANDLE-sized out-param with the CALLER's pointer width. A 32-bit
 * caller's HKEY/HMODULE/... slot is 4 bytes; an 8-byte host store smashes
 * the adjacent guest data (registry handles corrupted the Inno heap). */
void wn_wow64_out_handle(void *slot, uint64_t val);

#endif /* WN_WOW64_H */
