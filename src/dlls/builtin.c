/* builtin.c — builtin DLL registry + api-set name normalization. */
#include "wn_dll.h"
#include "wn_log.h"
#include "wn_util.h"
#include "wn_path.h"
#include "wn_files.h"
#include "wn_seh.h"
#include "wn_process.h"

#include <string.h>

/* Lazy init executed once, on first builtin load. */
static int g_subsys_init = 0;

void wn_builtin_subsys_init(void)
{
    if (g_subsys_init)
        return;
    g_subsys_init = 1;
    wn_files_std_init();
    wn_seh_init();
}

/* The registry. Order does not matter (exact name match after
 * normalization). Multiple names may share one export table. */
const wn_builtin_dll wn_builtin_table[] = {
    /* core */
    { "ntdll.dll",      wn_ntdll_exports,      NULL },
    { "kernel32.dll",   wn_kernel32_exports,   NULL },
    { "kernelbase.dll", wn_kernel32_exports,   NULL },
    { "msvcrt.dll",     wn_msvcrt_exports,     NULL },
    { "ucrtbase.dll",   wn_msvcrt_exports,     NULL },
    /* old MSVC CRTs + modern vcruntime: routed to the msvcrt engine */
    { "msvcr90.dll",    wn_msvcrt_exports,     NULL },
    { "msvcr100.dll",   wn_msvcrt_exports,     NULL },
    { "msvcr110.dll",   wn_msvcrt_exports,     NULL },
    { "msvcr120.dll",   wn_msvcrt_exports,     NULL },
    { "msvcrtd.dll",    wn_msvcrt_exports,     NULL },
    { "vcruntime140.dll",     wn_msvcrt_exports, NULL },
    { "vcruntime140_1.dll",   wn_msvcrt_exports, NULL },
    /* advapi/user/gdi/sockets */
    { "advapi32.dll",   wn_advapi32_exports,   NULL },
    { "sechext.dll",    wn_advapi32_exports,   NULL },   /* sechost alias */
    { "user32.dll",     wn_user32_exports,     NULL },
    { "gdi32.dll",      wn_gdi32_exports,      NULL },
    { "ws2_32.dll",     wn_ws2_32_exports,     NULL },
    { "wsock32.dll",    wn_ws2_32_exports,    NULL },   /* WinSock1 compat */
    /* shell / UI support */
    { "imm32.dll",      wn_imm32_exports,      NULL },
    { "comctl32.dll",   wn_comctl32_exports,   NULL },
    { "comdlg32.dll",   wn_comdlg32_exports,   NULL },
    { "shell32.dll",    wn_shell32_exports,    NULL },
    { "shlwapi.dll",    wn_shlwapi_exports,    NULL },
    { "uxtheme.dll",    wn_uxtheme_exports,    NULL },
    { "dwmapi.dll",     wn_dwmapi_exports,     NULL },
    /* COM + RPC */
    { "ole32.dll",      wn_ole32_exports,      NULL },
    { "oleaut32.dll",   wn_oleaut32_exports,   NULL },
    { "rpcrt4.dll",     wn_rpcrt4_exports,     NULL },
    { "uuid.dll",       wn_rpcrt4_exports,     NULL },
    /* system info / diagnostics */
    { "version.dll",    wn_version_exports,    NULL },
    { "psapi.dll",      wn_psapi_exports,      NULL },
    { "dbghelp.dll",    wn_dbghelp_exports,    NULL },
    { "userenv.dll",    wn_userenv_exports,    NULL },
    { "setupapi.dll",   wn_setupapi_exports,   NULL },
    { "winspool.drv",   wn_winspool_exports,   NULL },
    { "winspool.dll",   wn_winspool_exports,   NULL },
    /* networking */
    { "wininet.dll",    wn_wininet_exports,    NULL },
    { "winhttp.dll",    wn_winhttp_exports,    NULL },
    { "mswsock.dll",    wn_mswsock_exports,    NULL },
    { "iphlpapi.dll",   wn_iphlpapi_exports,   NULL },
    { "dnsapi.dll",     wn_dnsapi_exports,     NULL },
    /* crypto / security */
    { "crypt32.dll",    wn_crypt32_exports,    NULL },
    { "bcrypt.dll",     wn_bcrypt_exports,     NULL },
    { "cryptbase.dll",  wn_cryptbase_exports,  NULL },
    { "secur32.dll",    wn_secur32_exports,    NULL },
    { "sspicli.dll",    wn_secur32_exports,    NULL },
    /* media + C++ runtime presence */
    { "winmm.dll",      wn_winmm_exports,      NULL },
    { "msvcp140.dll",   wn_msvcp140_exports,   NULL },
    { "msvcp140_1.dll", wn_msvcp140_exports,   NULL },
    { "msvcp140_2.dll", wn_msvcp140_exports,   NULL },
    { "concrt140.dll",  wn_msvcp140_exports,   NULL },
    { "vcomp140.dll",   wn_msvcp140_exports,   NULL },
    { NULL, NULL, NULL },
};

const char *wn_dll_normalize_name(const char *name)
{
    if (wn_strcaseprefix(name, "api-ms-win-crt-"))
        return "ucrtbase.dll";
    if (wn_strcaseprefix(name, "api-ms-win-") ||
        wn_strcaseprefix(name, "ext-ms-"))
        return "kernelbase.dll";   /* core/system api-sets -> kernel surface */
    return name;
}
