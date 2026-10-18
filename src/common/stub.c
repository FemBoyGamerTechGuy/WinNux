/* stub.c — executable trampolines for unimplemented imports.
 *
 * Stub code (guest calls it like any ms_abi function):
 *   41 BA <imm32>     mov r10d, info       ; r10/r11 volatile in MS ABI
 *   48 B8 <imm64>     mov rax, trampoline
 *   FF E0             jmp rax
 *
 * The trampoline preserves the guest argument registers (rcx,rdx,r8,r9),
 * captures the guest return address for logging, calls the C implementation,
 * and returns 0 (failure by contract; last error 120 is set by the logger).
 */
#include "wn_stub.h"
#include "wn_log.h"
#include "wn_util.h"
#include "wn_module.h"
#include "wn_process.h"

#include <sys/mman.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#define WN_STUB_AREA  (256u * 1024u)   /* 256 KiB => ~10k stubs */
#define WN_STUB_SLOT  32u

typedef struct wn_stub_info {
    const char *dll;
    const char *name;
    uint32_t    hits;
} wn_stub_info;

static uint8_t *g_stub_region;
extern void wn_stub_entry_trampoline(void);

/* Stable per-entry storage: trampolines embed &info in their code, so the
 * info objects must never move (no realloc of the objects themselves). */
static wn_stub_info **g_infos;     /* index i <-> stub i */
static uint32_t g_info_count;

/* The impl is called by the raw-asm trampoline: ms_abi on x64 (the asm
 * builds the MS register+shadow layout), plain cdecl on i386. */
#if defined(__x86_64__)
#define WN_STUBIMPL WN_API
#else
#define WN_STUBIMPL
#endif

WN_STUBIMPL void wn_stub_entry_impl(uint64_t info_p, uint64_t a1, uint64_t a2,
                                    uint64_t a3, uint64_t a4, uint64_t guest_ret);

/* MS-ABI assembly bridge (see file comment). */
#if defined(__x86_64__)
__asm__(
    ".text\n"
    ".globl wn_stub_entry_trampoline\n"
    ".type wn_stub_entry_trampoline, @function\n"
    "wn_stub_entry_trampoline:\n"
    "    subq  $0x38, %rsp\n"          /* align to 16 + shadow + 2 stack args */
    "    movq  %r9, 0x20(%rsp)\n"      /* C arg5  <- original guest r9   */
    "    movq  0x38(%rsp), %rax\n"     /* guest return address           */
    "    movq  %rax, 0x28(%rsp)\n"     /* C arg6  <- guest retaddr       */
    "    movq  %r8, %r9\n"             /* C arg4  <- original guest r8   */
    "    movq  %rdx, %r8\n"            /* C arg3  <- original guest rdx  */
    "    movq  %rcx, %rdx\n"           /* C arg2  <- original guest rcx  */
    "    movq  %r10, %rcx\n"           /* C arg1  <- info                */
    "    call  wn_stub_entry_impl\n"
    "    xorq  %rax, %rax\n"           /* return 0                      */
    "    addq  $0x38, %rsp\n"
    "    ret\n"
    ".size wn_stub_entry_trampoline, .-wn_stub_entry_trampoline\n"
);
#else
/* i386 bridge. At entry: [esp]=ret-to-guest, [esp+4..+16]=a1..a4,
 * [esp+20]=info (pushed by the stub code). cdecl impl; returns 0 with a
 * PLAIN ret — cdecl guests clean their own args; stdcall guests leak the
 * arg frame per call (documented: only unimplemented imports hit this). */
__asm__(
    ".text\n"
    ".globl wn_stub_entry_trampoline\n"
    ".type wn_stub_entry_trampoline, @function\n"
    "wn_stub_entry_trampoline:\n"
    "    popl  %eax\n"                 /* eax = info                     */
    "    pushl 0(%esp)\n"              /* arg6: guest ret addr           */
    "    pushl 20(%esp)\n"             /* arg5: a4 (orig +16, one push)  */
    "    pushl 16(%esp)\n"             /* arg4: a3                       */
    "    pushl 12(%esp)\n"             /* arg3: a2                       */
    "    pushl 8(%esp)\n"              /* arg2: a1                       */
    "    pushl %eax\n"                 /* arg1: info                     */
    "    call  wn_stub_entry_impl\n"
    "    addl  $24, %esp\n"
    "    xorl  %eax, %eax\n"           /* return 0                      */
    "    ret\n"
    ".size wn_stub_entry_trampoline, .-wn_stub_entry_trampoline\n"
);
#endif


WN_STUBIMPL void wn_stub_entry_impl(uint64_t info_p, uint64_t a1, uint64_t a2,
                                    uint64_t a3, uint64_t a4, uint64_t guest_ret)
{
    wn_stub_info *info = (wn_stub_info *)(uintptr_t)info_p;
    if (!info)
        return;
    info->hits++;
    /* Crash-proof first line: raw write, no stdio, no formatting. */
    if (info->hits == 1) {
        const char msg[] = "[stub-call] ";
        (void)!write(2, msg, sizeof msg - 1);
        (void)!write(2, info->dll, strlen(info->dll));
        (void)!write(2, "!", 1);
        (void)!write(2, info->name, strlen(info->name));
        (void)!write(2, "\n", 1);
    }
    if (wn_log_level() >= WN_LOG_TRACE || info->hits == 1 || info->hits % 1000 == 0) {
        wn_log(WN_LOG_ERR, "STUB %s!%s(args: 0x%llx 0x%llx 0x%llx 0x%llx)",
               info->dll, info->name,
               (unsigned long long)a1, (unsigned long long)a2,
               (unsigned long long)a3, (unsigned long long)a4);
        char where[96] = "?";
        wn_module_describe_addr((const void *)(uintptr_t)guest_ret, where, sizeof where);
        wn_log(WN_LOG_ERR, "STUB %s!%s called from %s -> returning 0, "
               "GetLastError=120", info->dll, info->name, where);
        wn_last_error_set(120 /* ERROR_CALL_NOT_IMPLEMENTED */);
    }
}

static void ensure_region(void)
{
    if (g_stub_region)
        return;
    g_stub_region = mmap(NULL, WN_STUB_AREA, PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
    if (g_stub_region == MAP_FAILED)
        g_stub_region = mmap(NULL, WN_STUB_AREA, PROT_READ | PROT_WRITE | PROT_EXEC,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (g_stub_region == MAP_FAILED) {
        wn_log(WN_LOG_ERR, "stub: cannot allocate trampoline area");
        abort();
    }
}

void *wn_stub_for(const char *dll, const char *name)
{
    ensure_region();
    for (uint32_t i = 0; i < g_info_count; i++)
        if (!strcmp(g_infos[i]->dll, dll) && !strcmp(g_infos[i]->name, name))
            return g_stub_region + (size_t)i * WN_STUB_SLOT;

    if ((uint64_t)(g_info_count + 1) * WN_STUB_SLOT > WN_STUB_AREA) {
        wn_log(WN_LOG_ERR, "stub: trampoline area exhausted");
        abort();
    }
    uint32_t idx = g_info_count;
    g_infos = wn_xrealloc(g_infos, (idx + 1) * sizeof *g_infos);
    wn_stub_info *info = wn_xmalloc(sizeof *info);
    info->dll = wn_xstrdup(dll);
    info->name = wn_xstrdup(name);
    info->hits = 0;
    g_infos[idx] = info;
    g_info_count++;

    uint8_t *p = g_stub_region + (size_t)idx * WN_STUB_SLOT;
#if defined(__x86_64__)
    uint64_t info_addr = (uint64_t)(uintptr_t)g_infos[idx];
    uint64_t entry_addr = (uint64_t)(uintptr_t)&wn_stub_entry_trampoline;
    if (info_addr < 0x100000000ULL) {
        *p++ = 0x41; *p++ = 0xBA; memcpy(p, &info_addr, 4); p += 4;   /* mov r10d,imm32 */
    } else {
        *p++ = 0x49; *p++ = 0xBA; memcpy(p, &info_addr, 8); p += 8;   /* mov r10,imm64  */
    }
    *p++ = 0x48; *p++ = 0xB8; memcpy(p, &entry_addr, 8); p += 8;      /* mov rax,imm64  */
    *p++ = 0xFF; *p++ = 0xE0;                                         /* jmp rax        */
#else
    uint32_t info_addr = (uint32_t)(uintptr_t)g_infos[idx];
    *p++ = 0x68; memcpy(p, &info_addr, 4); p += 4;                    /* push imm32     */
    int32_t rel = (int32_t)((uintptr_t)&wn_stub_entry_trampoline
                            - (uintptr_t)(p + 5));
    *p++ = 0xE9; memcpy(p, &rel, 4); p += 4;                          /* jmp rel32      */
#endif
    return g_stub_region + (size_t)idx * WN_STUB_SLOT;
}

unsigned wn_stub_count(void) { return g_info_count; }
