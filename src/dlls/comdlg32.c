/* comdlg32.c — Common dialogs (file open/save, color, font, print).
 *
 * No dialog engine yet: every entry point returns the documented failure for
 * "dialog subsystem unavailable" and sets a commdlg extended error callers
 * can query. Loud logs, never fake success. (CDERR_INITIALIZATION = 2.)
 */
#include "wn_dll.h"
#include "wn_log.h"
#include "wn_process.h"
#include "wn_util.h"

#include <stdint.h>

static uint32_t g_ext_err = 2; /* CDERR_INITIALIZATION */

static WN_API int32_t cd_GetOpenFileNameA(void *ofn)
{
    (void)ofn;
    wn_log(WN_LOG_WARN, "comdlg32: GetOpenFileNameA unavailable (no dialog "
           "engine yet) -> FALSE");
    g_ext_err = 2;
    wn_last_error_set(WN_ERR_CALL_NOT_IMPLEMENTED);
    return 0;
}

static WN_API int32_t cd_GetOpenFileNameW(void *ofn)
{
    (void)ofn;
    wn_log(WN_LOG_WARN, "comdlg32: GetOpenFileNameW unavailable (no dialog "
           "engine yet) -> FALSE");
    g_ext_err = 2;
    wn_last_error_set(WN_ERR_CALL_NOT_IMPLEMENTED);
    return 0;
}

static WN_API int32_t cd_GetSaveFileNameA(void *ofn)
{
    (void)ofn;
    wn_log(WN_LOG_WARN, "comdlg32: GetSaveFileNameA unavailable -> FALSE");
    g_ext_err = 2;
    wn_last_error_set(WN_ERR_CALL_NOT_IMPLEMENTED);
    return 0;
}

static WN_API int32_t cd_GetSaveFileNameW(void *ofn)
{
    (void)ofn;
    wn_log(WN_LOG_WARN, "comdlg32: GetSaveFileNameW unavailable -> FALSE");
    g_ext_err = 2;
    wn_last_error_set(WN_ERR_CALL_NOT_IMPLEMENTED);
    return 0;
}

static WN_API int32_t cd_ChooseColorA(void *cc)
{
    (void)cc;
    wn_log(WN_LOG_WARN, "comdlg32: ChooseColorA unavailable -> FALSE");
    g_ext_err = 2;
    return 0;
}

static WN_API int32_t cd_ChooseFontA(void *cf)
{
    (void)cf;
    wn_log(WN_LOG_WARN, "comdlg32: ChooseFontA unavailable -> FALSE");
    g_ext_err = 2;
    return 0;
}

static WN_API int32_t cd_ChooseFontW(void *cf)
{
    (void)cf;
    wn_log(WN_LOG_WARN, "comdlg32: ChooseFontW unavailable -> FALSE");
    g_ext_err = 2;
    return 0;
}

static WN_API int32_t cd_PrintDlgA(void *pd)
{
    (void)pd;
    wn_log(WN_LOG_WARN, "comdlg32: PrintDlgA unavailable -> FALSE");
    g_ext_err = 2;
    return 0;
}

static WN_API int32_t cd_PrintDlgW(void *pd)
{
    (void)pd;
    wn_log(WN_LOG_WARN, "comdlg32: PrintDlgW unavailable -> FALSE");
    g_ext_err = 2;
    return 0;
}

static WN_API int32_t cd_CommDlgExtendedError(void)
{
    return (int32_t)g_ext_err;
}

const wn_export_entry wn_comdlg32_exports[] = {
    { "GetOpenFileNameA",        cd_GetOpenFileNameA },
    { "GetOpenFileNameW",        cd_GetOpenFileNameW },
    { "GetSaveFileNameA",        cd_GetSaveFileNameA },
    { "GetSaveFileNameW",        cd_GetSaveFileNameW },
    { "ChooseColorA",            cd_ChooseColorA },
    { "ChooseFontA",             cd_ChooseFontA },
    { "ChooseFontW",             cd_ChooseFontW },
    { "PrintDlgA",               cd_PrintDlgA },
    { "PrintDlgW",               cd_PrintDlgW },
    { "CommDlgExtendedError",    cd_CommDlgExtendedError },
    { NULL, NULL },
};
