/* imm32.c — Input Method Manager.
 *
 * WinNux has no IME engine yet, so the honest model is "no IME available":
 * contexts cannot be created (NULL), composition state is absent, and every
 * query returns the documented no-data error. Applications must handle a
 * NULL HIMC — that is a legal result on real Windows too (e.g. console
 * windows / disabled IME). Anything we do not model returns a safe failure
 * with a loud log, never a fake success.
 */
#include "wn_dll.h"
#include "wn_log.h"
#include "wn_process.h"
#include "wn_util.h"

#include <stdint.h>

#define IMM_ERROR_NODATA   ((int32_t)-1)

static WN_API void *im32_GetContext(uint64_t hwnd)
{
    (void)hwnd;
    wn_log(WN_LOG_DEBUG, "imm32: ImmGetContext -> NULL (no IME engine)");
    return NULL;
}

static WN_API int32_t im32_ReleaseContext(uint64_t hwnd, uint64_t himc)
{
    (void)hwnd;
    (void)himc;
    return 0;   /* FALSE: we never hand out a context */
}

static WN_API void *im32_AssociateContext(uint64_t hwnd, uint64_t himc)
{
    (void)hwnd;
    (void)himc;
    return NULL; /* previous context: none */
}

static WN_API int32_t im32_GetOpenStatus(uint64_t himc)
{
    (void)himc;
    return 0;
}

static WN_API int32_t im32_SetOpenStatus(uint64_t himc, int32_t open)
{
    (void)himc;
    (void)open;
    wn_log(WN_LOG_WARN, "imm32: ImmSetOpenStatus ignored (no IME engine)");
    return 0;
}

static WN_API int32_t im32_GetCompositionStringW(uint64_t himc, uint32_t index,
                                                 void *buf, uint32_t len)
{
    (void)himc;
    (void)index;
    (void)buf;
    (void)len;
    return IMM_ERROR_NODATA;
}

static WN_API int32_t im32_GetCompositionStringA(uint64_t himc, uint32_t index,
                                                 void *buf, uint32_t len)
{
    (void)himc;
    (void)index;
    (void)buf;
    (void)len;
    return IMM_ERROR_NODATA;
}

static WN_API int32_t im32_SetCompositionWindow(uint64_t himc, const void *cf)
{
    (void)himc;
    (void)cf;
    wn_log(WN_LOG_WARN, "imm32: ImmSetCompositionWindow ignored (no IME)");
    return 0;
}

static WN_API int32_t im32_SetCompositionFontA(uint64_t himc, const void *lf)
{
    (void)himc;
    (void)lf;
    wn_log(WN_LOG_WARN, "imm32: ImmSetCompositionFontA ignored (no IME)");
    return 0;
}

static WN_API int32_t im32_SetCompositionFontW(uint64_t himc, const void *lf)
{
    (void)himc;
    (void)lf;
    wn_log(WN_LOG_WARN, "imm32: ImmSetCompositionFontW ignored (no IME)");
    return 0;
}

static WN_API int32_t im32_SetCandidateWindow(uint64_t himc, const void *cf)
{
    (void)himc;
    (void)cf;
    return 0;
}

static WN_API int32_t im32_NotifyIME(uint64_t himc, uint32_t action,
                                     uint32_t index, uint32_t value)
{
    (void)himc;
    (void)action;
    (void)index;
    (void)value;
    return 0;
}

const wn_export_entry wn_imm32_exports[] = {
    { "ImmGetContext",              im32_GetContext },
    { "ImmReleaseContext",          im32_ReleaseContext },
    { "ImmAssociateContext",        im32_AssociateContext },
    { "ImmGetOpenStatus",           im32_GetOpenStatus },
    { "ImmSetOpenStatus",           im32_SetOpenStatus },
    { "ImmGetCompositionStringW",   im32_GetCompositionStringW },
    { "ImmGetCompositionStringA",   im32_GetCompositionStringA },
    { "ImmSetCompositionWindow",    im32_SetCompositionWindow },
    { "ImmSetCompositionFontA",     im32_SetCompositionFontA },
    { "ImmSetCompositionFontW",     im32_SetCompositionFontW },
    { "ImmSetCandidateWindow",      im32_SetCandidateWindow },
    { "ImmNotifyIME",               im32_NotifyIME },
    { NULL, NULL },
};
