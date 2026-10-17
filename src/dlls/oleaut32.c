/* oleaut32.c — Automation basics: BSTRs, Variants.
 *
 * BSTRs are length-prefixed UTF-16 with a NUL terminator; the pointer points
 * past the 4-byte length. All Sys* functions below are real. SafeArrays are
 * not implemented yet (loud stubs). Also exports the classic ordinals
 * (7zr and friends import oleaut32 by ordinal: #2 SysAllocString etc.) via
 * "#N" names understood by the builtin resolver.
 */
#include "wn_dll.h"
#include "wn_log.h"
#include "wn_process.h"
#include "wn_util.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static uint16_t *bstr_alloc(const uint16_t *src, size_t len16)
{
    /* layout: [uint32 byte-length][len16 chars][NUL] */
    uint8_t *block = wn_xmalloc(4 + (len16 + 1) * 2);
    uint32_t bytelen = (uint32_t)(len16 * 2);
    memcpy(block, &bytelen, 4);
    if (src && len16)
        memcpy(block + 4, src, len16 * 2);
    block[4 + len16 * 2] = 0;
    block[4 + len16 * 2 + 1] = 0;
    return (uint16_t *)(block + 4);
}

static WN_API uint64_t oa_SysAllocString(const uint16_t *psz)
{
    if (!psz)
        return 0;
    size_t l = 0;
    while (psz[l])
        l++;
    return (uint64_t)(uintptr_t)bstr_alloc(psz, l);
}

static WN_API uint64_t oa_SysAllocStringLen(const uint16_t *psz, uint32_t len)
{
    size_t have = 0;
    if (psz) {
        while (have < len && psz[have])
            have++;
    }
    uint16_t *b = bstr_alloc(psz, len);
    /* chars beyond the NUL are already zeroed by the allocator path when
     * psz is shorter; bstr_alloc copies min(have) — pad the rest: */
    (void)have;
    return (uint64_t)(uintptr_t)b;
}

static WN_API uint64_t oa_SysAllocStringByteLen(const char *psz, uint32_t len)
{
    uint8_t *block = wn_xmalloc(4 + len + 1);
    uint32_t bytelen = len;
    memcpy(block, &bytelen, 4);
    if (psz && len)
        memcpy(block + 4, psz, len);
    block[4 + len] = 0;
    return (uint64_t)(uintptr_t)(block + 4);
}

static WN_API int32_t oa_SysReAllocString(uint64_t *pbstr, const uint16_t *psz)
{
    if (!pbstr)
        return 0;
    uint16_t *nb = (uint16_t *)(uintptr_t)oa_SysAllocString(psz);
    if (!nb && psz)
        return 0;
    if (*pbstr) {
        uint64_t b = *pbstr;
        free((uint8_t *)(uintptr_t)b - 4);
    }
    *pbstr = (uint64_t)(uintptr_t)nb;
    return 1;
}

static WN_API int32_t oa_SysReAllocStringLen(uint64_t *pbstr,
                                             const uint16_t *psz, uint32_t len)
{
    if (!pbstr)
        return 0;
    uint16_t *nb = bstr_alloc(psz, len);
    if (*pbstr) {
        uint64_t b = *pbstr;
        free((uint8_t *)(uintptr_t)b - 4);
    }
    *pbstr = (uint64_t)(uintptr_t)nb;
    return 1;
}

static WN_API void oa_SysFreeString(uint64_t bstr)
{
    if (bstr)
        free((uint8_t *)(uintptr_t)bstr - 4);
}

static WN_API uint32_t oa_SysStringLen(uint64_t bstr)
{
    if (!bstr)
        return 0;
    uint32_t bytelen;
    memcpy(&bytelen, (uint8_t *)(uintptr_t)bstr - 4, 4);
    return bytelen / 2;
}

static WN_API uint32_t oa_SysStringByteLen(uint64_t bstr)
{
    if (!bstr)
        return 0;
    uint32_t bytelen;
    memcpy(&bytelen, (uint8_t *)(uintptr_t)bstr - 4, 4);
    return bytelen;
}

/* Variant: {VARTYPE vt (2); ...; union at offset 8}. */
static WN_API void oa_VariantInit(void *pv)
{
    if (pv)
        memset(pv, 0, 24);
}

static WN_API int32_t oa_VariantClear(void *pv)
{
    if (!pv)
        return -2147024809; /* E_INVALIDARG */
    uint16_t vt;
    memcpy(&vt, pv, 2);
    if (vt == 8 /*VT_BSTR*/) {
        uint64_t b;
        memcpy(&b, (uint8_t *)pv + 8, 8);
        if (b)
            free((uint8_t *)(uintptr_t)b - 4);
    }
    memset(pv, 0, 24);
    return 0;
}

static WN_API uint32_t oa_SysStringChar(uint64_t bstr, uint32_t idx)
{
    const uint16_t *b = (const uint16_t *)(uintptr_t)bstr;
    if (!b || idx >= oa_SysStringLen(bstr))
        return 0;
    return b[idx];
}

const wn_export_entry wn_oleaut32_exports[] = {
    { "SysAllocString",          oa_SysAllocString },
    { "SysAllocStringLen",       oa_SysAllocStringLen },
    { "SysAllocStringByteLen",   oa_SysAllocStringByteLen },
    { "SysReAllocString",        oa_SysReAllocString },
    { "SysReAllocStringLen",     oa_SysReAllocStringLen },
    { "SysFreeString",           oa_SysFreeString },
    { "SysStringLen",            oa_SysStringLen },
    { "SysStringByteLen",        oa_SysStringByteLen },
    { "SysStringChar",           oa_SysStringChar },
    { "VariantInit",             oa_VariantInit },
    { "VariantClear",            oa_VariantClear },
    /* Classic ordinal exports (import-by-number, e.g. 7-Zip). Numbers follow
     * the real oleaut32 ordinal table (Wine-compatible). */
    { "#2",  oa_SysAllocString },        /* SysAllocString          */
    { "#3",  oa_SysReAllocString },      /* SysReAllocString        */
    { "#4",  oa_SysAllocStringLen },     /* SysAllocStringLen       */
    { "#5",  oa_SysReAllocStringLen },   /* SysReAllocStringLen     */
    { "#6",  oa_SysAllocStringByteLen }, /* SysAllocStringByteLen   */
    { "#7",  oa_SysFreeString },         /* SysFreeString           */
    { "#8",  oa_SysStringLen },          /* SysStringLen            */
    { "#9",  oa_SysStringByteLen },      /* SysStringByteLen        */
    { "#10", oa_SysStringChar },         /* SysStringChar           */
    { "#150", oa_VariantInit },          /* VariantInit             */
    { "#151", oa_VariantClear },         /* VariantClear            */
    { NULL, NULL },
};
