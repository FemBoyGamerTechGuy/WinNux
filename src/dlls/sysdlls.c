/* sysdlls.c — builtin "presence-probe" system DLLs that real Windows has
 * and real apps feature-detect via LoadLibrary + GetProcAddress.
 *
 * The six covered here are exactly what Inno Setup-era installers (and
 * many Delphi/MSVC apps) probe at startup: apphelp, propsys, oleacc,
 * profapi, comres, clbcatq. Before they existed, every probe failed with
 * ERROR_MOD_NOT_FOUND; apps then take their "OS too old" code paths or
 * silently skip features that actually work here.
 *
 * Semantics policy: loads SUCCEED (the DLL exists, like on Windows);
 * functions that would need real subsystems return honest failures
 * (0 / E_NOTIMPL / S_FALSE) with a log line, so callers fall back
 * gracefully. GetProcAddress for names not listed returns NULL exactly
 * like a real (older) Windows build would.
 */
#include "wn_dll.h"
#include "wn_log.h"
#include "wn_util.h"
#include "wn_process.h"

#include <stdint.h>
#include <string.h>

/* --- apphelp.dll — application compatibility checks ------------------------- */

/* Returns nonzero = "run it". Apps/Explorer call this before executing
 * legacy installers; 1 keeps every package running unblocked. */
static WN_API int32_t ah_AppHelpCheckShellExecute(const void *pw, const char *exe)
{
    (void)pw;
    wn_log(WN_LOG_DEBUG, "apphelp: AppHelpCheckShellExecute('%s') -> allowed",
           exe ? exe : "(null)");
    return 1;
}

static WN_API int32_t ah_AppHelpCheckInstallShieldPackage(const char *pkg)
{
    wn_log(WN_LOG_DEBUG, "apphelp: AppHelpCheckInstallShieldPackage('%s') -> 1",
           pkg ? pkg : "(null)");
    return 1;
}

const wn_export_entry wn_apphelp_exports[] = {
    { "AppHelpCheckShellExecute", ah_AppHelpCheckShellExecute },
    { "AppHelpCheckInstallShieldPackage", ah_AppHelpCheckInstallShieldPackage },
    { NULL, NULL },
};

/* --- propsys.dll — Windows Property System ----------------------------------- */

/* PKEY lookup by friendly name: we keep no property metadata. */
static WN_API int32_t ps_PSGetPropertyKeyFromName(const char *name, void *key)
{
    (void)name;
    if (key)
        memset(key, 0, 20);            /* PROPERTYKEY = fmtid(16) + pid(4) */
    return 0x80004001;                 /* E_NOTIMPL */
}

static WN_API int32_t ps_PSStringFromPropertyKey(const void *key,
                                                 char *buf, uint32_t cap)
{
    (void)key;
    if (buf && cap)
        buf[0] = 0;
    return 0x80004001;                 /* E_NOTIMPL */
}

const wn_export_entry wn_propsys_exports[] = {
    { "PSGetPropertyKeyFromName", ps_PSGetPropertyKeyFromName },
    { "PSStringFromPropertyKey", ps_PSStringFromPropertyKey },
    { NULL, NULL },
};

/* --- oleacc.dll — Active Accessibility --------------------------------------- */

/* MSAA server objects need a real accessibility bridge; report "none" so
 * clients degrade to plain windows (what every non-MSAA host does). */
static WN_API int32_t oa_AccessibleObjectFromWindow(wn_abiword hwnd,
                                                    uint32_t id,
                                                    const void *riid, void **ppv)
{
    (void)hwnd; (void)id; (void)riid;
    if (ppv)
        *ppv = NULL;
    wn_log(WN_LOG_DEBUG, "oleacc: AccessibleObjectFromWindow -> S_FALSE (no MSAA)");
    return 1;                          /* S_FALSE: object not available */
}

static WN_API int32_t oa_CreateStdAccessibleObjectA(wn_abiword hwnd,
                                                    uint32_t id,
                                                    const void *riid, void **ppv)
{
    (void)hwnd; (void)id; (void)riid;
    if (ppv)
        *ppv = NULL;
    return 1;                          /* S_FALSE */
}

static WN_API int32_t oa_NotifyWinEvent(uint32_t event, wn_abiword hwnd,
                                        uint32_t id_object, uint32_t id_child)
{
    (void)event; (void)hwnd; (void)id_object; (void)id_child;
    return 0;                          /* no-op: nobody listens */
}

static WN_API uint32_t oa_GetRoleTextA(uint32_t role, char *buf, uint32_t max)
{
    (void)role;
    if (buf && max)
        buf[0] = 0;
    return 0;                          /* zero-length text */
}

static WN_API uint32_t oa_GetStateTextA(uint32_t state, char *buf, uint32_t max)
{
    (void)state;
    if (buf && max)
        buf[0] = 0;
    return 0;
}

const wn_export_entry wn_oleacc_exports[] = {
    { "AccessibleObjectFromWindow", oa_AccessibleObjectFromWindow },
    { "CreateStdAccessibleObjectA", oa_CreateStdAccessibleObjectA },
    { "NotifyWinEvent", oa_NotifyWinEvent },
    { "GetRoleTextA", oa_GetRoleTextA },
    { "GetStateTextA", oa_GetStateTextA },
    { NULL, NULL },
};

/* --- profapi.dll — user profile queries --------------------------------------- */

static WN_API int32_t pf_GetProfileType(uint32_t *type)
{
    if (!type)
        return 0x80070057;             /* E_INVALIDARG */
    *type = 1;                         /* PT_ROAMING — normal user profile */
    return 0;                          /* S_OK */
}

const wn_export_entry wn_profapi_exports[] = {
    { "GetProfileType", pf_GetProfileType },
    { NULL, NULL },
};

/* --- comres.dll / clbcatq.dll — COM+ runtime + catalog ----------------------- */

/* Presence probes: COM+ services. Exported surface is almost entirely
 * ordinal-based internal machinery; apps load the module to ask "is the
 * COM+ machinery installed" and let the OLE layer drive the rest. */
const wn_export_entry wn_comres_exports[] = {
    { NULL, NULL },
};

const wn_export_entry wn_clbcatq_exports[] = {
    { NULL, NULL },
};

/* --- mpr.dll - Windows networking (WNet*) -------------------------------
 * Inno Setup links mpr.dll for network-path handling. No network here:
 * every WNet call fails cleanly with ERROR_NOT_CONNECTED (2250). One
 * wrapper per real arity - the wow64 signature table derives its stack
 * cleanup from the parameter count. */
static WN_API uint32_t mpr_w0(wn_abiword a1, wn_abiword a2, wn_abiword a3) { (void)a1; (void)a2; (void)a3; wn_last_error_set(2250); return 2250; }
static WN_API uint32_t mpr_w1(wn_abiword a1, wn_abiword a2, wn_abiword a3) { (void)a1; (void)a2; (void)a3; wn_last_error_set(2250); return 2250; }
static WN_API uint32_t mpr_w2(wn_abiword a1, wn_abiword a2, wn_abiword a3, wn_abiword a4) { (void)a1; (void)a2; (void)a3; (void)a4; wn_last_error_set(2250); return 2250; }
static WN_API uint32_t mpr_w3(wn_abiword a1, wn_abiword a2, wn_abiword a3, wn_abiword a4) { (void)a1; (void)a2; (void)a3; (void)a4; wn_last_error_set(2250); return 2250; }
static WN_API uint32_t mpr_w4(wn_abiword a1, wn_abiword a2, wn_abiword a3, wn_abiword a4, wn_abiword a5) { (void)a1; (void)a2; (void)a3; (void)a4; (void)a5; wn_last_error_set(2250); return 2250; }
static WN_API uint32_t mpr_w5(wn_abiword a1, wn_abiword a2, wn_abiword a3, wn_abiword a4, wn_abiword a5) { (void)a1; (void)a2; (void)a3; (void)a4; (void)a5; wn_last_error_set(2250); return 2250; }
static WN_API uint32_t mpr_w6(wn_abiword a1, wn_abiword a2, wn_abiword a3) { (void)a1; (void)a2; (void)a3; wn_last_error_set(2250); return 2250; }
static WN_API uint32_t mpr_w7(wn_abiword a1, wn_abiword a2, wn_abiword a3) { (void)a1; (void)a2; (void)a3; wn_last_error_set(2250); return 2250; }
static WN_API uint32_t mpr_w8(wn_abiword a1, wn_abiword a2) { (void)a1; (void)a2; wn_last_error_set(2250); return 2250; }
static WN_API uint32_t mpr_w9(wn_abiword a1, wn_abiword a2) { (void)a1; (void)a2; wn_last_error_set(2250); return 2250; }
static WN_API uint32_t mpr_w10(wn_abiword a1, wn_abiword a2, wn_abiword a3, wn_abiword a4, wn_abiword a5) { (void)a1; (void)a2; (void)a3; (void)a4; (void)a5; wn_last_error_set(2250); return 2250; }
static WN_API uint32_t mpr_w11(wn_abiword a1, wn_abiword a2, wn_abiword a3, wn_abiword a4, wn_abiword a5) { (void)a1; (void)a2; (void)a3; (void)a4; (void)a5; wn_last_error_set(2250); return 2250; }
static WN_API uint32_t mpr_w12(wn_abiword a1) { (void)a1; wn_last_error_set(2250); return 2250; }
static WN_API uint32_t mpr_w13(wn_abiword a1, wn_abiword a2, wn_abiword a3, wn_abiword a4) { (void)a1; (void)a2; (void)a3; (void)a4; wn_last_error_set(2250); return 2250; }
static WN_API uint32_t mpr_w14(wn_abiword a1, wn_abiword a2, wn_abiword a3, wn_abiword a4) { (void)a1; (void)a2; (void)a3; (void)a4; wn_last_error_set(2250); return 2250; }
static WN_API uint32_t mpr_w15(wn_abiword a1, wn_abiword a2, wn_abiword a3, wn_abiword a4, wn_abiword a5) { (void)a1; (void)a2; (void)a3; (void)a4; (void)a5; wn_last_error_set(2250); return 2250; }
static WN_API uint32_t mpr_w16(wn_abiword a1, wn_abiword a2, wn_abiword a3, wn_abiword a4, wn_abiword a5) { (void)a1; (void)a2; (void)a3; (void)a4; (void)a5; wn_last_error_set(2250); return 2250; }
static WN_API uint32_t mpr_w17(wn_abiword a1, wn_abiword a2, wn_abiword a3) { (void)a1; (void)a2; (void)a3; wn_last_error_set(2250); return 2250; }
static WN_API uint32_t mpr_w18(wn_abiword a1, wn_abiword a2, wn_abiword a3) { (void)a1; (void)a2; (void)a3; wn_last_error_set(2250); return 2250; }
static WN_API uint32_t mpr_w19(wn_abiword a1, wn_abiword a2, wn_abiword a3, wn_abiword a4, wn_abiword a5, wn_abiword a6, wn_abiword a7, wn_abiword a8) { (void)a1; (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7; (void)a8; wn_last_error_set(2250); return 2250; }
static WN_API uint32_t mpr_w20(wn_abiword a1, wn_abiword a2, wn_abiword a3, wn_abiword a4, wn_abiword a5, wn_abiword a6, wn_abiword a7, wn_abiword a8) { (void)a1; (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7; (void)a8; wn_last_error_set(2250); return 2250; }

const wn_export_entry wn_mpr_exports[] = {
    { "WNetGetConnectionA", mpr_w0 },
    { "WNetGetConnectionW", mpr_w1 },
    { "WNetAddConnection2A", mpr_w2 },
    { "WNetAddConnection2W", mpr_w3 },
    { "WNetAddConnection3A", mpr_w4 },
    { "WNetAddConnection3W", mpr_w5 },
    { "WNetCancelConnection2A", mpr_w6 },
    { "WNetCancelConnection2W", mpr_w7 },
    { "WNetCancelConnectionA", mpr_w8 },
    { "WNetCancelConnectionW", mpr_w9 },
    { "WNetOpenEnumA", mpr_w10 },
    { "WNetOpenEnumW", mpr_w11 },
    { "WNetCloseEnum", mpr_w12 },
    { "WNetEnumResourceA", mpr_w13 },
    { "WNetEnumResourceW", mpr_w14 },
    { "WNetGetLastErrorA", mpr_w15 },
    { "WNetGetLastErrorW", mpr_w16 },
    { "WNetGetUserA", mpr_w17 },
    { "WNetGetUserW", mpr_w18 },
    { "WNetUseConnectionA", mpr_w19 },
    { "WNetUseConnectionW", mpr_w20 },
    { NULL, NULL },
};

/* --- msimg32.dll - GDI image helpers -----------------------------------------
 * Inno links it for AlphaBlend/GradientFill (progress graphics). The
 * functions fail cleanly (return 0); drawing falls back to solid fills. */
static WN_API int32_t ms_fail(wn_abiword a, wn_abiword b, wn_abiword c,
                              wn_abiword d, wn_abiword e, wn_abiword f,
                              wn_abiword g, wn_abiword h)
{
    (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h;
    wn_last_error_set(1 /* ERROR_INVALID_FUNCTION */);
    return 0;
}

const wn_export_entry wn_msimg32_exports[] = {
    { "AlphaBlend", ms_fail },
    { "GradientFill", ms_fail },
    { "TransparentBlt", ms_fail },
    { "vSetDIBitsToDevice", ms_fail },
    { NULL, NULL },
};
