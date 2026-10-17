/* comctl32.c — Common controls.
 *
 * Init/version calls are real (bookkeeping + honest version report). The
 * control window classes themselves (SysTabControl32, tooltips, etc.) are NOT
 * registered yet — CreateWindow on them fails loudly through user32. Rest of
 * the surface is auto-stubbed (loud, returns 0) unless implemented here.
 */
#include "wn_dll.h"
#include "wn_log.h"
#include "wn_process.h"
#include "wn_util.h"

#include <stdint.h>
#include <string.h>

/* InitCommonControlsEx expects: {DWORD dwSize; DWORD dwICC;} */
static WN_API int32_t cc_InitCommonControlsEx(const void *picce)
{
    if (!picce) {
        wn_last_error_set(WN_ERR_INVALID_PARAMETER);
        return 0;
    }
    uint32_t size;
    memcpy(&size, picce, 4);
    if (size < 8) {
        wn_last_error_set(WN_ERR_INVALID_PARAMETER);
        return 0;
    }
    wn_log(WN_LOG_INFO, "comctl32: InitCommonControlsEx accepted "
           "(control classes are still being implemented; missing ones fail "
           "loudly at CreateWindow)");
    return 1;
}

static WN_API void cc_InitCommonControls(void)
{
    wn_log(WN_LOG_DEBUG, "comctl32: InitCommonControls (no-op; classes on "
           "demand)");
}

/* DLLVERSIONINFO {cbSize, dwMajor, dwMinor, dwBuild, dwPlatform}. We report
 * the comctl32 5.8x classic (non-themed) behavior we actually implement. */
static WN_API int32_t cc_DllGetVersion(void *pdvi)
{
    if (!pdvi)
        return -2147467259; /* E_FAIL */
    uint32_t cb;
    memcpy(&cb, pdvi, 4);
    if (cb < 20) {
        wn_last_error_set(WN_ERR_INVALID_PARAMETER);
        return -2147467259;
    }
    uint32_t vals[4] = { 5, 82, 0, 1 /* COMCTL32_PLATFORM */ };
    memcpy((uint8_t *)pdvi + 4, vals, sizeof vals);
    return 0; /* S_OK */
}

/* _TrackMouseEvent: posts WM_MOUSELEAVE/WM_MOUSEHOVER. Not yet wired into the
 * message pump — honest failure so callers fall back to polling. */
static WN_API int32_t cc_TrackMouseEvent(void *evt)
{
    (void)evt;
    wn_log(WN_LOG_WARN, "comctl32: _TrackMouseEvent not implemented "
           "(returning FALSE; callers should poll)");
    wn_last_error_set(WN_ERR_CALL_NOT_IMPLEMENTED);
    return 0;
}

static WN_API int32_t cc_ImageList_Create(uint32_t cx, uint32_t cy,
                                          uint32_t flags, uint32_t initial,
                                          uint32_t grow)
{
    (void)cx; (void)cy; (void)flags; (void)initial; (void)grow;
    wn_log(WN_LOG_WARN, "comctl32: ImageList_Create not implemented");
    wn_last_error_set(WN_ERR_CALL_NOT_IMPLEMENTED);
    return 0;
}

const wn_export_entry wn_comctl32_exports[] = {
    { "InitCommonControls",    cc_InitCommonControls },
    { "InitCommonControlsEx",  cc_InitCommonControlsEx },
    { "DllGetVersion",         cc_DllGetVersion },
    { "_TrackMouseEvent",      cc_TrackMouseEvent },
    { "ImageList_Create",      cc_ImageList_Create },
    { NULL, NULL },
};
