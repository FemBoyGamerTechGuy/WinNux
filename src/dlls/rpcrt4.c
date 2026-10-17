/* rpcrt4.c — RPC runtime subset: UUIDs (also serves uuid.dll imports).
 *
 * UuidCreate* and string forms are real (RFC 4122 v4, /dev/urandom).
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

typedef struct {
    uint32_t d1;
    uint16_t d2, d3;
    uint8_t  d4[8];
} wn_guid;

#define RPC_S_OK 0

static void fill_guid(wn_guid *g)
{
    uint8_t *b = (uint8_t *)g;
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        (void)!fread(b, 1, 16, f);
        fclose(f);
    } else {
        uint64_t t = (uint64_t)time(NULL) * 6364136223846793005ULL
                   + (uint64_t)(uintptr_t)g;
        for (int i = 0; i < 16; i++) {
            t = t * 6364136223846793005ULL + 1442695040888963407ULL;
            b[i] = (uint8_t)(t >> 33);
        }
    }
    b[7] = (uint8_t)((b[7] & 0x0F) | 0x40);
    b[8] = (uint8_t)((b[8] & 0x3F) | 0x80);
}

static WN_API int32_t rp_UuidCreate(wn_guid *g)
{
    if (!g)
        return 1730; /* RPC_S_INVALID_ARG */
    fill_guid(g);
    return RPC_S_OK;
}

static WN_API int32_t rp_UuidCreateSequential(wn_guid *g)
{
    /* We do not embed a MAC; a random v4 is a legal substitute (RFC 4122
     * allows either; documented deviation: no ordering guarantee). */
    return rp_UuidCreate(g);
}

static int guid_snprintf(char *buf, size_t cap, const wn_guid *g)
{
    return snprintf(buf, cap, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                    g->d1, g->d2, g->d3, g->d4[0], g->d4[1], g->d4[2],
                    g->d4[3], g->d4[4], g->d4[5], g->d4[6], g->d4[7]);
}

static WN_API int32_t rp_UuidToStringA(const wn_guid *g, char **out)
{
    if (!g || !out)
        return 1730;
    *out = wn_xmalloc(37);
    guid_snprintf(*out, 37, g);
    return RPC_S_OK;
}

static WN_API int32_t rp_UuidToStringW(const wn_guid *g, uint16_t **out)
{
    if (!g || !out)
        return 1730;
    char a[37];
    guid_snprintf(a, sizeof a, g);
    *out = wn_utf8_to_utf16(a, NULL);
    return RPC_S_OK;
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int guid_parse(const char *s, wn_guid *g)
{
    if (!s)
        return -1;
    if (*s == '{')
        s++;
    if (strspn(s, "0123456789abcdefABCDEF-") < 32)
        return -1;
    uint32_t v = 0;
    #define H4(dst) do { v = 0; for (int i = 0; i < 4; i++) { \
        int h = hexval(s[i]); if (h < 0) return -1; v = v << 4 | (uint32_t)h; } \
        (dst) = v; s += 4; if (*s == '-') s++; } while (0)
    H4(g->d1);
    H4(v); g->d2 = (uint16_t)v;
    H4(v); g->d3 = (uint16_t)v;
    #undef H4
    for (int i = 0; i < 8; i++) {
        int a = hexval(s[0]), b = hexval(s[1]);
        if (a < 0 || b < 0)
            return -1;
        g->d4[i] = (uint8_t)((a << 4) | b);
        s += 2;
    }
    return 0;
}

static WN_API int32_t rp_UuidFromStringA(const char *s, wn_guid *g)
{
    if (!s || !*s) {
        if (g)
            memset(g, 0, sizeof *g);
        return RPC_S_OK;
    }
    if (!g || guid_parse(s, g) != 0)
        return 1733; /* RPC_S_INVALID_STRING_UUID */
    return RPC_S_OK;
}

static WN_API int32_t rp_UuidFromStringW(const uint16_t *s, wn_guid *g)
{
    if (!s || !s[0]) {
        if (g)
            memset(g, 0, sizeof *g);
        return RPC_S_OK;
    }
    size_t l = 0;
    while (s[l])
        l++;
    char *a = wn_utf16_to_utf8(s, l);
    if (!a)
        return 1733;
    int rc = guid_parse(a, g);
    free(a);
    return rc == 0 ? RPC_S_OK : 1733;
}

static WN_API int32_t rp_RpcStringFreeA(char **s)
{
    if (s && *s) {
        free(*s);
        *s = NULL;
    }
    return RPC_S_OK;
}

static WN_API int32_t rp_RpcStringFreeW(uint16_t **s)
{
    if (s && *s) {
        free(*s);
        *s = NULL;
    }
    return RPC_S_OK;
}

static WN_API int32_t rp_UuidIsNil(const wn_guid *g, int32_t *is_nil)
{
    if (!g || !is_nil)
        return 1730;
    uint8_t allzero = 0;
    for (size_t i = 0; i < sizeof *g; i++)
        allzero |= ((const uint8_t *)g)[i];
    *is_nil = allzero == 0;
    return RPC_S_OK;
}

static WN_API int32_t rp_UuidEqual(const wn_guid *a, const wn_guid *b,
                                   int32_t *status)
{
    if (status)
        *status = RPC_S_OK;
    if (!a || !b)
        return 0;
    return memcmp(a, b, sizeof *a) == 0;
}

static WN_API int32_t rp_UuidCompare(const wn_guid *a, const wn_guid *b,
                                     int32_t *status)
{
    if (status)
        *status = RPC_S_OK;
    if (!a || !b)
        return 2;
    int rc = memcmp(a, b, sizeof *a);
    return rc > 0 ? 1 : rc < 0 ? -1 : 0;
}

const wn_export_entry wn_rpcrt4_exports[] = {
    { "UuidCreate",             rp_UuidCreate },
    { "UuidCreateSequential",   rp_UuidCreateSequential },
    { "UuidToStringA",          rp_UuidToStringA },
    { "UuidToStringW",          rp_UuidToStringW },
    { "UuidFromStringA",        rp_UuidFromStringA },
    { "UuidFromStringW",        rp_UuidFromStringW },
    { "RpcStringFreeA",         rp_RpcStringFreeA },
    { "RpcStringFreeW",         rp_RpcStringFreeW },
    { "UuidIsNil",              rp_UuidIsNil },
    { "UuidEqual",              rp_UuidEqual },
    { "UuidCompare",            rp_UuidCompare },
    { NULL, NULL },
};
