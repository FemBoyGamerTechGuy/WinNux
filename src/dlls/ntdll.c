/* ntdll.c — builtin ntdll.dll: Rtl helpers guest CRTs import. */
#include "wn_dll.h"
#include "wn_process.h"
#include "wn_sync.h"
#include "wn_seh.h"
#include "wn_wow64.h"
#include "wn_log.h"

#include <stdlib.h>
#include <string.h>

static WN_API void nt_RtlEnterCriticalSection(wn_critsect *cs)
{
    wn_critsect_enter(cs);
}

static WN_API void nt_RtlLeaveCriticalSection(wn_critsect *cs)
{
    wn_critsect_leave(cs);
}

static WN_API int32_t nt_RtlTryEnterCriticalSection(wn_critsect *cs)
{
    return wn_critsect_try(cs);
}

static WN_API void nt_RtlInitializeCriticalSection(wn_critsect *cs)
{
    wn_critsect_init(cs, 0);
}

static WN_API int32_t nt_RtlInitializeCriticalSectionAndSpinCount(wn_critsect *cs,
                                                                  uint32_t spin)
{
    wn_critsect_init(cs, spin);
    return 1;
}

static WN_API void nt_RtlDeleteCriticalSection(wn_critsect *cs)
{
    wn_critsect_delete(cs);
}

static WN_API uint64_t nt_RtlAllocateHeap(wn_abiword heap, uint32_t flags, wn_abiword size)
{
    (void)heap;
    void *p = (flags & 8) ? calloc(1, (size_t)size) : malloc((size_t)size);
    return (uint64_t)(uintptr_t)p;
}

static WN_API int32_t nt_RtlFreeHeap(wn_abiword heap, uint32_t flags, void *ptr)
{
    (void)heap;
    (void)flags;
    (void)ptr;
    return 1;   /* heap allocations are tracked by the host allocator */
}

static WN_API uint64_t nt_RtlSizeHeap(wn_abiword heap, uint32_t flags, void *ptr)
{
    (void)heap;
    (void)flags;
    (void)ptr;
    return 0;
}

static WN_API void *nt_RtlAddVectoredExceptionHandler(uint32_t first,
                                                      void *handler)
{
    return wn_seh_veh_add(handler, (int)first);
}

static WN_API uint32_t nt_RtlRemoveVectoredExceptionHandler(void *reg)
{
    wn_seh_veh_remove(reg);
    return 1;
}

static WN_API void *nt_RtlAddVectoredContinueHandler(uint32_t first, void *handler)
{
    return wn_seh_veh_add(handler, (int)first);
}

static WN_API uint64_t nt_RtlFillMemory(void *dst, wn_abiword n, uint8_t c)
{
    memset(dst, c, (size_t)n);
    return (uint64_t)(uintptr_t)dst;
}

static WN_API uint64_t nt_RtlZeroMemory(void *dst, wn_abiword n)
{
    memset(dst, 0, (size_t)n);
    return (uint64_t)(uintptr_t)dst;
}

static WN_API int32_t nt_RtlUnwind(void *frame, void *target, void *rec, void *ret)
{
    if (wn_wow64_guest32()) {
        /* i386 caller: frame-based unwind (see seh.c). */
        wn_seh_rtl_unwind_32((uint32_t)(uintptr_t)frame,
                            (uint32_t)(uintptr_t)target,
                            (uint32_t)(uintptr_t)rec,
                            (uint32_t)(uintptr_t)ret);
        return 0;
    }
    wn_log(WN_LOG_ERR, "ntdll: RtlUnwind not implemented (x64 table-based "
           "unwinding pending; see STATUS.md)");
    (void)frame; (void)target; (void)rec; (void)ret;
    return 0;
}

static WN_API void *nt_NtCurrentTeb(void)
{
    return wn_teb_current();
}

/* LdrLoadDll etc. are used by some CRTs — loud stubs via missing export. */

const wn_export_entry wn_ntdll_exports[] = {
    { "NtCurrentTeb", nt_NtCurrentTeb },
    { "RtlAddVectoredContinueHandler", nt_RtlAddVectoredContinueHandler },
    { "RtlAddVectoredExceptionHandler", nt_RtlAddVectoredExceptionHandler },
    { "RtlAllocateHeap", nt_RtlAllocateHeap },
    { "RtlDeleteCriticalSection", nt_RtlDeleteCriticalSection },
    { "RtlEnterCriticalSection", nt_RtlEnterCriticalSection },
    { "RtlFillMemory", nt_RtlFillMemory },
    { "RtlFreeHeap", nt_RtlFreeHeap },
    { "RtlInitializeCriticalSection", nt_RtlInitializeCriticalSection },
    { "RtlInitializeCriticalSectionAndSpinCount", nt_RtlInitializeCriticalSectionAndSpinCount },
    { "RtlLeaveCriticalSection", nt_RtlLeaveCriticalSection },
    { "RtlRemoveVectoredExceptionHandler", nt_RtlRemoveVectoredExceptionHandler },
    { "RtlSizeHeap", nt_RtlSizeHeap },
    { "RtlTryEnterCriticalSection", nt_RtlTryEnterCriticalSection },
    { "RtlUnwind", nt_RtlUnwind },
    { "RtlZeroMemory", nt_RtlZeroMemory },
    { NULL, NULL },
};
