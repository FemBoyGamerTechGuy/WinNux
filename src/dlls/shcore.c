/* shcore.c — builtin shcore.dll (DPI awareness) + hhctrl.ocx (HTML help).
 *
 * shcore: we render at native pixels, so per-monitor DPI answers are the
 * screen truth (96 until real per-monitor scaling lands). SetProcessDpi-
 * Awareness is accepted so apps stop second-guessing our coordinates —
 * putty delay-loads shcore at startup and its absence was visible noise.
 *
 * hhctrl.ocx: HtmlHelp has no CHM viewer behind it — a loud, honest stub
 * that returns 0 (help window "not shown"), which is what apps check.
 */
#include "wn_dll.h"
#include "wn_log.h"
#include "wn_util.h"

#include <stdint.h>
#include <stdlib.h>

/* --- shcore ---------------------------------------------------------------------- */

static WN_API int32_t sc_SetProcessDpiAwareness(uint32_t value)
{
    /* S_OK. (PROCESS_DPI_UNAWARE=0/DISABLED... apps pass 1/2.) */
    wn_log(WN_LOG_DEBUG, "shcore: SetProcessDpiAwareness(%u) -> S_OK", value);
    return 0;
}

static WN_API int32_t sc_GetDpiForMonitor(wn_abiword hmon, uint32_t type,
                                          uint32_t *x, uint32_t *y)
{
    (void)hmon;
    (void)type;   /* MDT_EFFECTIVE/RAW/ANGLE */
    if (x)
        *x = 96;
    if (y)
        *y = 96;
    return 0;     /* S_OK */
}

static WN_API int32_t sc_GetScaleFactorForMonitor(wn_abiword hmon, uint32_t *scale)
{
    (void)hmon;
    if (scale)
        *scale = 100;   /* SCALE_100_PERCENT */
    return 0;
}

const wn_export_entry wn_shcore_exports[] = {
    { "SetProcessDpiAwareness", sc_SetProcessDpiAwareness },
    { "GetDpiForMonitor", sc_GetDpiForMonitor },
    { "GetScaleFactorForMonitor", sc_GetScaleFactorForMonitor },
    { NULL, NULL },
};

/* --- hhctrl.ocx (HTML help) -------------------------------------------------------- */

static WN_API uint64_t hh_HtmlHelpA(wn_abiword hwnd, const char *file,
                                    uint32_t cmd, wn_abiword data)
{
    (void)hwnd; (void)cmd; (void)data;
    wn_log(WN_LOG_WARN, "hhctrl: HtmlHelpA('%s') — no CHM viewer, returning 0",
           file ? file : "(null)");
    return 0;
}

static WN_API uint64_t hh_HtmlHelpW(wn_abiword hwnd, const uint16_t *file,
                                    uint32_t cmd, wn_abiword data)
{
    char *a = file ? wn_utf16_to_utf8(file, 256) : NULL;
    uint64_t r = hh_HtmlHelpA(hwnd, a, cmd, data);
    free(a);
    return r;
}

const wn_export_entry wn_hhctrl_exports[] = {
    { "HtmlHelpA", hh_HtmlHelpA },
    { "HtmlHelpW", hh_HtmlHelpW },
    { NULL, NULL },
};
