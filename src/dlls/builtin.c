/* builtin.c — builtin DLL registry + api-set name normalization. */
#include "wn_dll.h"
#include "wn_log.h"
#include "wn_util.h"
#include "wn_path.h"
#include "wn_files.h"
#include "wn_seh.h"
#include "wn_process.h"
#include "wn_path.h"
#include "wn_files.h"
#include "wn_registry.h"
#include "wn_seh.h"

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

const wn_builtin_dll wn_builtin_table[] = {
    { "ntdll.dll",     wn_ntdll_exports,     NULL },
    { "kernel32.dll",  wn_kernel32_exports,  NULL },
    { "msvcrt.dll",    wn_msvcrt_exports,    NULL },
    { "ucrtbase.dll",  wn_msvcrt_exports,    NULL },
    { "advapi32.dll",  wn_advapi32_exports,  NULL },
    { "user32.dll",    wn_user32_exports,    NULL },
    { "gdi32.dll",     wn_gdi32_exports,     NULL },
    { "ws2_32.dll",    wn_ws2_32_exports,    NULL },
    { "kernelbase.dll", wn_kernel32_exports, NULL },
    { NULL, NULL, NULL },
};

const char *wn_dll_normalize_name(const char *name)
{
    if (wn_strcaseprefix(name, "api-ms-win-crt-") ||
        wn_strcaseprefix(name, "api-ms-win-core-"))
        return "ucrtbase.dll";
    if (wn_strcaseprefix(name, "ext-ms-"))
        return "ucrtbase.dll";
    return name;
}
