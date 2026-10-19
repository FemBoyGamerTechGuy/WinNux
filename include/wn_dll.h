/* wn_dll.h — builtin DLL export tables.
 *
 * Every exported function is ms_abi (WN_API) so guest code calls it directly
 * through the IAT. Data exports pass the address of a C object.
 */
#ifndef WN_DLL_H
#define WN_DLL_H

#include "wn_module.h"

/* Export tables (defined next to their implementation). */
extern const wn_export_entry wn_ntdll_exports[];
extern const wn_export_entry wn_kernel32_exports[];
extern const wn_export_entry wn_msvcrt_exports[];
extern const wn_export_entry wn_advapi32_exports[];
extern const wn_export_entry wn_user32_exports[];
extern const wn_export_entry wn_gdi32_exports[];
extern const wn_export_entry wn_ws2_32_exports[];
extern const wn_export_entry wn_imm32_exports[];
extern const wn_export_entry wn_comctl32_exports[];
extern const wn_export_entry wn_comdlg32_exports[];
extern const wn_export_entry wn_shell32_exports[];
extern const wn_export_entry wn_shlwapi_exports[];
extern const wn_export_entry wn_ole32_exports[];
extern const wn_export_entry wn_oleaut32_exports[];
extern const wn_export_entry wn_rpcrt4_exports[];
extern const wn_export_entry wn_version_exports[];
extern const wn_export_entry wn_psapi_exports[];
extern const wn_export_entry wn_dbghelp_exports[];
extern const wn_export_entry wn_userenv_exports[];
extern const wn_export_entry wn_setupapi_exports[];
extern const wn_export_entry wn_winspool_exports[];
extern const wn_export_entry wn_wininet_exports[];
extern const wn_export_entry wn_winhttp_exports[];
extern const wn_export_entry wn_mswsock_exports[];
extern const wn_export_entry wn_iphlpapi_exports[];
extern const wn_export_entry wn_dnsapi_exports[];
extern const wn_export_entry wn_crypt32_exports[];
extern const wn_export_entry wn_bcrypt_exports[];
extern const wn_export_entry wn_cryptbase_exports[];
extern const wn_export_entry wn_secur32_exports[];
extern const wn_export_entry wn_uxtheme_exports[];
extern const wn_export_entry wn_dwmapi_exports[];
extern const wn_export_entry wn_winmm_exports[];
extern const wn_export_entry wn_msvcp140_exports[];
extern const wn_export_entry wn_wship6_exports[];
extern const wn_export_entry wn_shcore_exports[];
extern const wn_export_entry wn_hhctrl_exports[];
extern const wn_export_entry wn_apphelp_exports[];
extern const wn_export_entry wn_propsys_exports[];
extern const wn_export_entry wn_oleacc_exports[];
extern const wn_export_entry wn_profapi_exports[];
extern const wn_export_entry wn_comres_exports[];
extern const wn_export_entry wn_clbcatq_exports[];
extern const wn_export_entry wn_mpr_exports[];
extern const wn_export_entry wn_msimg32_exports[];

/* The full builtin table (name -> exports). */
extern const wn_builtin_dll wn_builtin_table[];

/* Normalize DLL names to a canonical builtin (api-ms-* -> ucrtbase etc).
 * Returns canonical name (static storage or the input). */
const char *wn_dll_normalize_name(const char *name);

/* Create placeholder files in <prefix>/drive_c/windows/system32 for every
 * builtin DLL (Wine-style: the file exists so apps that stat it, enumerate
 * it, or LoadLibrary it by full path succeed; the loader maps the basename
 * to the in-process builtin). Idempotent; derives from wn_builtin_table at
 * runtime so new builtins are picked up automatically. Returns 0 on success. */
int  wn_dll_sync_placeholders(void);

#endif /* WN_DLL_H */
