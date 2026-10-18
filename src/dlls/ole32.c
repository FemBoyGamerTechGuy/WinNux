/* ole32.c — COM fundamentals.
 *
 * REAL: CoInitialize/Ex bookkeeping, CoTaskMem heap, GUID <-> string
 * conversion, CoCreateGuid (real randomness). CoCreateInstance honestly
 * returns REGDB_E_CLASSNOTREG — WinNux hosts no COM servers yet, and
 * pretending otherwise would break silently later.
 */
#include "wn_dll.h"
#include "wn_log.h"
#include "wn_process.h"
#include "wn_util.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define S_OK          ((int32_t)0)
#define S_FALSE       ((int32_t)1)
#define E_FAIL        ((int32_t)0x80004005)
#define E_NOTIMPL     ((int32_t)0x80004001)
#define E_INVALIDARG  ((int32_t)0x80070057)
#define REGDB_E_CLASSNOTREG ((int32_t)0x80040154)
#define CO_E_CLASSSTRING    ((int32_t)0x800401F3)

static uint32_t g_com_init_count;

static WN_API int32_t ole_CoInitialize(void *pv)
{
    (void)pv;
    g_com_init_count++;
    return g_com_init_count > 1 ? S_FALSE : S_OK;
}

static WN_API int32_t ole_CoInitializeEx(void *pv, uint32_t mode)
{
    (void)pv;
    (void)mode;
    g_com_init_count++;
    return g_com_init_count > 1 ? S_FALSE : S_OK;
}

static WN_API void ole_CoUninitialize(void)
{
    if (g_com_init_count)
        g_com_init_count--;
}

static WN_API int32_t ole_CoGetCurrentProcess(void)
{
    /* Arbitrary but stable per-process non-zero value. */
    return 0x10 + (int32_t)(getpid() & 0xFFFF);
}

/* --- task allocator: plain malloc (documented) -------------------------------- */

static WN_API void *ole_CoTaskMemAlloc(wn_abiword size)
{
    if (size == 0)
        return NULL;
    return malloc((size_t)size);
}

static WN_API void *ole_CoTaskMemRealloc(void *p, wn_abiword size)
{
    if (size == 0) {
        free(p);
        return NULL;
    }
    return realloc(p, (size_t)size);
}

static WN_API void ole_CoTaskMemFree(void *p)
{
    free(p);
}

/* --- GUIDs --------------------------------------------------------------------- */

typedef struct {
    uint32_t d1;
    uint16_t d2, d3;
    uint8_t  d4[8];
} wn_guid;

static void fill_guid_random(wn_guid *g)
{
    uint8_t *b = (uint8_t *)g;
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        (void)!fread(b, 1, 16, f);
        fclose(f);
    } else {
        uint64_t t = (uint64_t)time(NULL) * 2654435761u + (uint64_t)(uintptr_t)&g;
        for (int i = 0; i < 16; i++) {
            t = t * 6364136223846793005ULL + 1442695040888963407ULL;
            b[i] = (uint8_t)(t >> 33);
        }
    }
    /* RFC 4122 version 4, variant 10. */
    b[7] = (uint8_t)((b[7] & 0x0F) | 0x40);
    b[8] = (uint8_t)((b[8] & 0x3F) | 0x80);
}

static WN_API int32_t ole_CoCreateGuid(wn_guid *g)
{
    if (!g)
        return E_INVALIDARG;
    fill_guid_random(g);
    return S_OK;
}

static int guid_snprintf(char *buf, size_t cap, const wn_guid *g)
{
    return snprintf(buf, cap,
        "{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
        g->d1, g->d2, g->d3, g->d4[0], g->d4[1], g->d4[2], g->d4[3],
        g->d4[4], g->d4[5], g->d4[6], g->d4[7]);
}

static WN_API int32_t ole_StringFromGUID2(const wn_guid *g, uint16_t *out,
                                          int32_t cch)
{
    if (!g || !out || cch < 39)
        return 0;
    char tmp[40];
    guid_snprintf(tmp, sizeof tmp, g);
    for (int i = 0; i <= 38; i++)
        out[i] = (uint16_t)(unsigned char)tmp[i];
    return 39;
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_hex4(const char *s, uint32_t *out)
{
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) {
        int h = hexval(s[i]);
        if (h < 0)
            return -1;
        v = (v << 4) | (uint32_t)h;
    }
    *out = v;
    return 0;
}

static int parse_hex2(const char *s, uint8_t *out)
{
    int a = hexval(s[0]), b = hexval(s[1]);
    if (a < 0 || b < 0)
        return -1;
    *out = (uint8_t)((a << 4) | b);
    return 0;
}

/* Accepts "{...}" and plain forms. */
static int guid_from_string(const char *s, wn_guid *g)
{
    if (!s || !g)
        return -1;
    if (*s == '{')
        s++;
    size_t len = strspn(s, "0123456789abcdefABCDEF-");
    if (len < 32)
        return -1;
    {
        uint32_t v;
        if (parse_hex4(s, &v) != 0) return -1;
        g->d1 = v;
        s += 4; if (*s == '-') s++;
        if (parse_hex4(s, &v) != 0) return -1;
        g->d2 = (uint16_t)v;
        s += 4; if (*s == '-') s++;
        if (parse_hex4(s, &v) != 0) return -1;
        g->d3 = (uint16_t)v;
        s += 4; if (*s == '-') s++;
    }
    for (int i = 0; i < 8; i++) {
        if (parse_hex2(s, &g->d4[i]) != 0)
            return -1;
        s += 2;
    }
    return 0;
}

static WN_API int32_t ole_CLSIDFromString(const uint16_t *s, wn_guid *g)
{
    if (!s || !g)
        return E_INVALIDARG;
    size_t l = 0;
    while (s[l])
        l++;
    char *a = wn_utf16_to_utf8(s, l);
    if (!a)
        return E_INVALIDARG;
    int rc = guid_from_string(a, g);
    free(a);
    return rc == 0 ? S_OK : CO_E_CLASSSTRING;
}

static WN_API int32_t ole_IIDFromString(const uint16_t *s, wn_guid *g)
{
    return ole_CLSIDFromString(s, g);
}

static WN_API int32_t ole_CoCreateInstance(const wn_guid *clsid, void *outer,
                                           uint32_t clsctx, const wn_guid *riid,
                                           void **ppv)
{
    (void)outer;
    (void)clsctx;
    (void)riid;
    if (ppv)
        *ppv = NULL;
    wn_log(WN_LOG_WARN, "ole32: CoCreateInstance class {%08x-...} -> "
           "REGDB_E_CLASSNOTREG (no COM servers hosted yet)",
           clsid ? clsid->d1 : 0);
    return REGDB_E_CLASSNOTREG;
}

static WN_API int32_t ole_IsEqualGUID(const wn_guid *a, const wn_guid *b)
{
    if (!a || !b)
        return 0;
    return memcmp(a, b, sizeof *a) == 0;
}

static WN_API int32_t ole_CoGetMalloc(uint32_t ctx, void **ppmalloc)
{
    (void)ctx;
    if (ppmalloc)
        *ppmalloc = NULL;
    wn_log(WN_LOG_WARN, "ole32: CoGetMalloc not implemented -> E_FAIL");
    return E_FAIL;
}

/* PropVariantInit: VT_EMPTY (layout {VARTYPE vt; ...}, vt at offset 0). */
static WN_API void ole_PropVariantInit(void *pv)
{
    if (pv)
        memset(pv, 0, 16);
}

static WN_API int32_t ole_PropVariantClear(void *pv)
{
    if (!pv)
        return E_INVALIDARG;
    uint16_t vt;
    memcpy(&vt, pv, 2);
    if (vt == 31 /*VT_LPWSTR*/ || vt == 30 /*VT_LPSTR*/) {
        void *p;
        memcpy(&p, (uint8_t *)pv + 8, sizeof p);
        free(p);
    } else if (vt == 8 /*VT_BSTR*/) {
        void *p;
        memcpy(&p, (uint8_t *)pv + 8, sizeof p);
        if (p)
            free((uint8_t *)p - 4);
    }
    memset(pv, 0, 16);
    return S_OK;
}

const wn_export_entry wn_ole32_exports[] = {
    { "CoInitialize",        ole_CoInitialize },
    { "CoInitializeEx",      ole_CoInitializeEx },
    { "CoUninitialize",      ole_CoUninitialize },
    { "CoGetCurrentProcess", ole_CoGetCurrentProcess },
    { "CoTaskMemAlloc",      ole_CoTaskMemAlloc },
    { "CoTaskMemRealloc",    ole_CoTaskMemRealloc },
    { "CoTaskMemFree",       ole_CoTaskMemFree },
    { "CoCreateGuid",        ole_CoCreateGuid },
    { "StringFromGUID2",     ole_StringFromGUID2 },
    { "CLSIDFromString",     ole_CLSIDFromString },
    { "IIDFromString",       ole_IIDFromString },
    { "CoCreateInstance",    ole_CoCreateInstance },
    { "IsEqualGUID",         ole_IsEqualGUID },
    { "CoGetMalloc",         ole_CoGetMalloc },
    { "PropVariantInit",     ole_PropVariantInit },
    { "PropVariantClear",    ole_PropVariantClear },
    { NULL, NULL },
};
