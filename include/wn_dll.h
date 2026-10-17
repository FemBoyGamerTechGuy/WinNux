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

/* The full builtin table (name -> exports). */
extern const wn_builtin_dll wn_builtin_table[];

/* Normalize DLL names to a canonical builtin (api-ms-* -> ucrtbase etc).
 * Returns canonical name (static storage or the input). */
const char *wn_dll_normalize_name(const char *name);

#endif /* WN_DLL_H */
