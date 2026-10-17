/* psapi.c — process/module status.
 *
 * REAL: process/module enumeration over WinNux's own module list (self +
 * loaded images), module base/file names, module info, EmptyWorkingSet
 * (no-op success: nothing to trim — documented).
 */
#include "wn_dll.h"
#include "wn_log.h"
#include "wn_module.h"
#include "wn_process.h"
#include "wn_util.h"

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <unistd.h>

static WN_API int32_t ps_EnumProcesses(uint32_t *ids, uint32_t cb,
                                       uint32_t *needed)
{
    /* One process exists: the guest itself. */
    if (!needed)
        return 0;
    *needed = 4;
    if (cb >= 4 && ids)
        ids[0] = (uint32_t)getpid();
    return 1;
}

static wn_module **collect_modules(size_t *n)
{
    size_t cnt = 0;
    for (wn_module *m = wn_module_list_head(); m; m = m->next)
        cnt++;
    wn_module **arr = wn_xmalloc((cnt ? cnt : 1) * sizeof *arr);
    size_t i = 0;
    for (wn_module *m = wn_module_list_head(); m && i < cnt; m = m->next)
        arr[i++] = m;
    *n = i;
    return arr;
}

static WN_API int32_t ps_EnumProcessModules(uint64_t h, uint64_t *mods,
                                            uint32_t cb, uint32_t *needed)
{
    (void)h;
    size_t n;
    wn_module **arr = collect_modules(&n);
    size_t bytes = n * 8;
    if (needed)
        *needed = (uint32_t)bytes;
    int32_t ok = 1;
    if (cb < bytes || !mods)
        ok = 0;
    else
        for (size_t i = 0; i < n; i++)
            mods[i] = (uint64_t)(uintptr_t)arr[i]->base;
    free(arr);
    if (!ok)
        wn_last_error_set(WN_ERR_INSUFFICIENT_BUFFER);
    return ok;
}

static wn_module *mod_from_hmod(uint64_t hmod)
{
    for (wn_module *m = wn_module_list_head(); m; m = m->next)
        if ((uint64_t)(uintptr_t)m->base == hmod)
            return m;
    return NULL;
}

static int copy_name(wn_module *m, char *out, uint32_t cap)
{
    if (!m)
        return 0;
    size_t l = strlen(m->name);
    if (l + 1 > cap) {
        wn_last_error_set(WN_ERR_INSUFFICIENT_BUFFER);
        return 0;
    }
    memcpy(out, m->name, l + 1);
    return (int)(l + 1);
}

static WN_API int32_t ps_GetModuleBaseNameA(uint64_t h, uint64_t hmod,
                                            char *base, uint32_t cap)
{
    (void)h;
    return copy_name(mod_from_hmod(hmod ? hmod
                            : (g_proc.exe ? (uint64_t)(uintptr_t)g_proc.exe->base : 0)),
                     base, cap);
}

static WN_API int32_t ps_GetModuleFileNameExA(uint64_t h, uint64_t hmod,
                                              char *out, uint32_t cap)
{
    (void)h;
    wn_module *m = mod_from_hmod(hmod ? hmod
                     : (g_proc.exe ? (uint64_t)(uintptr_t)g_proc.exe->base : 0));
    if (!m || !out || cap == 0)
        return 0;
    char win[1100];
    wn_module_win_path(m, win, sizeof win);
    size_t l = strlen(win);
    if (l + 1 > cap) {
        wn_last_error_set(WN_ERR_INSUFFICIENT_BUFFER);
        return 0;
    }
    memcpy(out, win, l + 1);
    return (int32_t)(l + 1);
}

static WN_API int32_t ps_GetModuleFileNameExW(uint64_t h, uint64_t hmod,
                                              uint16_t *out, uint32_t cap)
{
    (void)h;
    wn_module *m = mod_from_hmod(hmod ? hmod
                     : (g_proc.exe ? (uint64_t)(uintptr_t)g_proc.exe->base : 0));
    if (!m || !out || cap == 0)
        return 0;
    char win[1100];
    wn_module_win_path(m, win, sizeof win);
    uint16_t *w = wn_utf8_to_utf16(win, NULL);
    if (!w)
        return 0;
    size_t l = 0;
    while (w[l])
        l++;
    int32_t rv = 0;
    if (l + 1 <= cap) {
        memcpy(out, w, (l + 1) * 2);
        rv = (int32_t)l;
    } else {
        wn_last_error_set(WN_ERR_INSUFFICIENT_BUFFER);
    }
    free(w);
    return rv;
}

/* MODULEINFO {lpBaseOfImage; DWORD SizeOfImage; DWORD EntryPoint;} */
static WN_API int32_t ps_GetModuleInformation(uint64_t h, uint64_t hmod,
                                              void *mi, uint32_t cb)
{
    (void)h;
    wn_module *m = mod_from_hmod(hmod);
    if (!m || !mi || cb < 16)
        return 0;
    uint64_t base = (uint64_t)(uintptr_t)m->base;
    uint32_t size = (uint32_t)m->size;
    uint32_t entry = (m->kind == WN_MOD_PE && m->pe.entry_rva)
                     ? (uint32_t)(uintptr_t)(m->base + m->pe.entry_rva) : 0;
    memcpy(mi, &base, 8);
    memcpy((uint8_t *)mi + 8, &size, 4);
    memcpy((uint8_t *)mi + 12, &entry, 4);
    return 1;
}

static WN_API int32_t ps_EmptyWorkingSet(uint64_t h)
{
    (void)h;
    /* Nothing to trim: host kernel manages residency. Documented no-op
     * success (the call's contract is best-effort). */
    return 1;
}

const wn_export_entry wn_psapi_exports[] = {
    { "EnumProcesses",        ps_EnumProcesses },
    { "EnumProcessModules",   ps_EnumProcessModules },
    { "GetModuleBaseNameA",   ps_GetModuleBaseNameA },
    { "GetModuleFileNameExA", ps_GetModuleFileNameExA },
    { "GetModuleFileNameExW", ps_GetModuleFileNameExW },
    { "GetModuleInformation", ps_GetModuleInformation },
    { "EmptyWorkingSet",      ps_EmptyWorkingSet },
    { NULL, NULL },
};
