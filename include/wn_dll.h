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
extern const wn_export_entry wn_riched32_exports[];
extern const wn_export_entry wn_riched20_exports[];
extern const wn_export_entry wn_riched30_exports[];
extern const wn_export_entry wn_msftedit_exports[];
extern const wn_export_entry wn_rstrtmgr_exports[];

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

/* --- cross-DLL internal helpers (not guest exports) -------------------------
 * Declared here so one builtin DLL can use another's machinery without
 * reaching into its private state; defined next to what they wrap. */

/* kernel32.c — resource walker: entry count / entry id of a resource TYPE
 * directory (`type` = type-name string or MAKEINTRESOURCE id in the low
 * word; the FindResource convention). wn_res_type_id_at returns -1 when the
 * entry is string-named (id_out 0), 0 when type/index is absent. */
int wn_res_type_count(uint64_t hmod, const char *type, uint32_t *count_out);
int wn_res_type_id_at(uint64_t hmod, const char *type, uint32_t index,
                      uint32_t *id_out);

/* kernel32.c — FindResource + the DATA ENTRY's bytes in one step: the raw
 * resource payload (mapped image bytes, valid while the module lives). */
int wn_res_lookup_bytes(uint64_t hmod, const char *type, const char *name,
                        const uint8_t **out, uint32_t *size_out);

/* user32.c — allocate the shared HICON-handle shape (resource id + is_icon +
 * owning module base for module icons): the same object LoadIconA hands
 * out, so DestroyIcon and the icon drawing path treat it identically. */
wn_handle wn_icon_handle_alloc(uint32_t id, int is_icon, uint64_t mod_base);

/* gdi32.c — allocate the shared HBITMAP shape (32bpp pixel storage, the
 * same object CreateDIBSection/CreateCompatibleBitmap hand out), for
 * user32's LoadBitmap OBM_* path. */
wn_handle wn_bitmap_handle_alloc(int w, int h);

/* gdi32.c — blit a raw DIB (BITMAPINFOHEADER + pixels, 24/32bpp, top-down
 * or bottom-up) into a DC, scaled to cx/cy; the pixel writer behind
 * user32's DrawIconEx. */
int wn_gdi_draw_dib(wn_handle hdc, int x, int y, int cx, int cy,
                    const uint8_t *dib, uint32_t dib_size);

/* gdi32.c — a loadable HBITMAP from a raw RT_BITMAP-style DIB, normalized
 * to 32bpp top-down storage (behind user32's LoadBitmapA). */
wn_handle wn_gdi_bitmap_from_dib(const uint8_t *dib, uint32_t dib_size);

#endif /* WN_DLL_H */
