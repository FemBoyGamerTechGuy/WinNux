/* thememedia.c — UX theme, DWM and multimedia shims.
 *
 * uxtheme: OpenThemeData returns NULL (no theme engine); apps fall back to
 * classic drawing exactly like pre-theme Windows. IsAppThemed()=FALSE.
 * dwmapi: composition disabled answers (the honest state: no compositor
 * integration).
 * winmm: the time* family is REAL (timeGetTime on the monotonic clock, dev
 * caps, period no-ops); waveOut/midiOut/mciSendString honestly report "no
 * driver" - the audio stack (PipeWire/Pulse/ALSA, dlopen at runtime) is a
 * separate milestone.
 */
#include "wn_dll.h"
#include "wn_log.h"
#include "wn_process.h"
#include "wn_util.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* --- uxtheme -------------------------------------------------------------------- */

static WN_API int32_t ut_IsAppThemed(void)
{
    return 0;
}

static WN_API int32_t ut_IsThemeActive(void)
{
    return 0;
}

static WN_API uint64_t ut_OpenThemeData(uint64_t hwnd, const uint16_t *classlist)
{
    (void)hwnd;
    (void)classlist;
    wn_log(WN_LOG_DEBUG, "uxtheme: OpenThemeData -> NULL (classic drawing)");
    return 0;
}

static WN_API uint64_t ut_GetWindowTheme(uint64_t hwnd)
{
    (void)hwnd;
    return 0;
}

static WN_API int32_t ut_CloseThemeData(uint64_t theme)
{
    (void)theme;
    return (int32_t)0x80070006;   /* E_HANDLE: no theme handles exist */
}

static WN_API int32_t ut_SetWindowTheme(uint64_t hwnd, const uint16_t *sub,
                                        const uint16_t *name)
{
    (void)hwnd; (void)sub; (void)name;
    return 1;   /* S_FALSE: not applied, not an error */
}

static WN_API int32_t ut_DrawThemeBackground(uint64_t theme, uint64_t hdc,
                                             int32_t part, int32_t state,
                                             const void *rect, const void *clip)
{
    (void)theme; (void)hdc; (void)part; (void)state; (void)rect; (void)clip;
    return (int32_t)0x80070006;   /* E_HANDLE */
}

const wn_export_entry wn_uxtheme_exports[] = {
    { "IsAppThemed",        ut_IsAppThemed },
    { "IsThemeActive",      ut_IsThemeActive },
    { "OpenThemeData",      ut_OpenThemeData },
    { "GetWindowTheme",     ut_GetWindowTheme },
    { "CloseThemeData",     ut_CloseThemeData },
    { "SetWindowTheme",     ut_SetWindowTheme },
    { "DrawThemeBackground", ut_DrawThemeBackground },
    { NULL, NULL },
};

/* --- dwmapi ---------------------------------------------------------------------- */

#define DWM_E_COMPOSITIONDISABLED ((int32_t)0x80263001)

static WN_API int32_t dw_DwmIsCompositionEnabled(int32_t *enabled)
{
    if (enabled)
        *enabled = 0;
    return 0;   /* S_OK: the honest answer is "disabled" */
}

static WN_API int32_t dw_DwmExtendFrameIntoClientArea(uint64_t hwnd,
                                                      const void *margins)
{
    (void)hwnd;
    (void)margins;
    wn_log(WN_LOG_DEBUG, "dwmapi: DwmExtendFrameIntoClientArea -> "
           "DWM_E_COMPOSITIONDISABLED");
    return DWM_E_COMPOSITIONDISABLED;
}

static WN_API int32_t dw_DwmSetWindowAttribute(uint64_t hwnd, uint32_t attr,
                                               const void *val, uint32_t size)
{
    (void)hwnd; (void)attr; (void)val; (void)size;
    return DWM_E_COMPOSITIONDISABLED;
}

static WN_API int32_t dw_DwmFlush(void)
{
    return DWM_E_COMPOSITIONDISABLED;
}

const wn_export_entry wn_dwmapi_exports[] = {
    { "DwmIsCompositionEnabled",       dw_DwmIsCompositionEnabled },
    { "DwmExtendFrameIntoClientArea",  dw_DwmExtendFrameIntoClientArea },
    { "DwmSetWindowAttribute",         dw_DwmSetWindowAttribute },
    { "DwmFlush",                      dw_DwmFlush },
    { NULL, NULL },
};

/* --- winmm ----------------------------------------------------------------------- */

#define TIMERR_NOERROR 0
#define TIMERR_NOCANDO 98

static WN_API uint32_t mm_timeGetTime(void)
{
    return (uint32_t)(wn_monotonic_ns() / 1000000);
}

static WN_API uint32_t mm_timeBeginPeriod(uint32_t ms)
{
    (void)ms;
    return TIMERR_NOERROR;   /* host scheduler periods accepted as-is */
}

static WN_API uint32_t mm_timeEndPeriod(uint32_t ms)
{
    (void)ms;
    return TIMERR_NOERROR;
}

static WN_API uint32_t mm_timeGetDevCaps(void *caps, uint32_t size)
{
    if (!caps || size < 8)
        return TIMERR_NOCANDO;
    uint32_t vals[2] = { 1, 1000000 };   /* min/max period (ms) */
    memcpy(caps, vals, 8);
    if (size >= 12) {
        uint32_t n = 1;
        memcpy((uint8_t *)caps + 8, &n, 4);
    }
    return TIMERR_NOERROR;
}

static WN_API uint32_t mm_waveOutOpen(uint64_t *out, uint32_t dev,
                                      const void *fmt, uint64_t cb,
                                      uint64_t inst, uint32_t flags)
{
    (void)out; (void)dev; (void)fmt; (void)cb; (void)inst; (void)flags;
    wn_log(WN_LOG_WARN, "winmm: waveOutOpen -> MMSYSERR_NODRIVER "
           "(audio output is a TODO: PipeWire/Pulse/ALSA via dlopen)");
    return 2;   /* MMSYSERR_NODRIVER */
}

static WN_API uint32_t mm_midiOutOpen(uint64_t *out, uint32_t dev, uint64_t cb,
                                      uint64_t inst, uint32_t flags)
{
    (void)out; (void)dev; (void)cb; (void)inst; (void)flags;
    return 2;
}

static WN_API uint32_t mm_mciSendStringA(const char *cmd, char *ret,
                                         uint32_t retlen, uint64_t hwnd)
{
    (void)cmd; (void)ret; (void)retlen; (void)hwnd;
    wn_log(WN_LOG_WARN, "winmm: mciSendStringA('%s') unsupported -> "
           "MCIERR_INVALID_DEVICE_ID", cmd ? cmd : "?");
    return 257;   /* MCIERR_INVALID_DEVICE_ID */
}

static WN_API int32_t mm_PlaySoundA(const char *sound, uint64_t hmod,
                                    uint32_t flags)
{
    (void)sound; (void)hmod; (void)flags;
    wn_log(WN_LOG_WARN, "winmm: PlaySoundA('%s') -> FALSE (no audio yet)",
           sound ? sound : "?");
    return 0;
}

static WN_API uint32_t mm_waveOutGetNumDevs(void)
{
    return 0;   /* honest: zero audio devices */
}

const wn_export_entry wn_winmm_exports[] = {
    { "timeGetTime",      mm_timeGetTime },
    { "timeBeginPeriod",  mm_timeBeginPeriod },
    { "timeEndPeriod",    mm_timeEndPeriod },
    { "timeGetDevCaps",   mm_timeGetDevCaps },
    { "waveOutOpen",      mm_waveOutOpen },
    { "waveOutGetNumDevs", mm_waveOutGetNumDevs },
    { "midiOutOpen",      mm_midiOutOpen },
    { "mciSendStringA",   mm_mciSendStringA },
    { "PlaySoundA",       mm_PlaySoundA },
    { NULL, NULL },
};
