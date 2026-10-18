/* crypt.c — crypto provider shims: crypt32, bcrypt (+ cryptbase alias).
 *
 * REAL: BCryptGenRandom via /dev/urandom (used by many apps for keys and
 * cookie randomness) and cryptbase!SystemFunction036 (RtlGenRandom) which is
 * the same primitive under its legacy name; CryptStringToBinary/
 * CryptBinaryToString implement real base64. Cert stores and DPAPI honestly
 * fail: no certificate database, no keyring. bcrypt non-RNG algorithms
 * report STATUS_NOT_IMPLEMENTED (hashing lands with the shader/crypto push).
 */
#include "wn_dll.h"
#include "wn_log.h"
#include "wn_process.h"
#include "wn_util.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STATUS_NOT_IMPLEMENTED ((uint32_t)0xC0000002)
#define STATUS_INVALID_PARAMETER ((uint32_t)0xC000000D)
#define STATUS_SUCCESS 0u

static int urandom_fill(void *buf, size_t n)
{
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f)
        return -1;
    size_t got = fread(buf, 1, n, f);
    fclose(f);
    return got == n ? 0 : -1;
}

/* --- bcrypt --------------------------------------------------------------------- */

static WN_API uint32_t bc_BCryptOpenAlgorithmProvider(uint64_t *handle,
                                                      const uint16_t *algid,
                                                      const uint16_t *impl,
                                                      uint32_t flags)
{
    (void)impl;
    (void)flags;
    if (!handle || !algid)
        return STATUS_INVALID_PARAMETER;
    /* Only "RNG" gets a real (magic) handle: GenRandom is genuinely served. */
    static const uint16_t rng[] = { L'R', L'N', L'G', 0 };
    int same = 1;
    for (int i = 0; rng[i] || algid[i]; i++)
        if (rng[i] != algid[i]) { same = 0; break; }
    if (same) {
        *handle = 0x524E4731;   /* "RNG1" magic handle */
        return STATUS_SUCCESS;
    }
    if (algid[0]) {
        char *a = NULL;
        size_t l = 0;
        while (algid[l])
            l++;
        a = malloc(l + 1);
        if (a) {
            for (size_t i = 0; i < l; i++)
                a[i] = (char)algid[i];
            a[l] = 0;
            wn_log(WN_LOG_WARN, "bcrypt: algorithm '%s' not implemented "
                   "(RNG only)", a);
            free(a);
        }
    }
    *handle = 0;
    return STATUS_NOT_IMPLEMENTED;
}

static WN_API uint32_t bc_BCryptGenRandom(wn_abiword handle, uint8_t *buf,
                                          uint32_t len, uint32_t flags)
{
    (void)handle;
    (void)flags;
    if (!buf && len)
        return STATUS_INVALID_PARAMETER;
    if (len == 0)
        return STATUS_SUCCESS;
    if (urandom_fill(buf, len) != 0) {
        wn_log(WN_LOG_ERR, "bcrypt: /dev/urandom unavailable");
        return (uint32_t)0xC0000184; /* STATUS_DEVICE_NOT_READY */
    }
    return STATUS_SUCCESS;
}

static WN_API uint32_t bc_BCryptCloseAlgorithmProvider(wn_abiword handle,
                                                       uint32_t flags)
{
    (void)handle;
    (void)flags;
    return STATUS_SUCCESS;
}

const wn_export_entry wn_bcrypt_exports[] = {
    { "BCryptOpenAlgorithmProvider", bc_BCryptOpenAlgorithmProvider },
    { "BCryptGenRandom",             bc_BCryptGenRandom },
    { "BCryptCloseAlgorithmProvider", bc_BCryptCloseAlgorithmProvider },
    { NULL, NULL },
};

/* cryptbase!SystemFunction036 == RtlGenRandom: legacy random. */
static WN_API int32_t cb_SystemFunction036(uint8_t *buf, uint32_t len)
{
    if (!buf && len)
        return 0;
    if (len && urandom_fill(buf, len) != 0)
        return 0;
    return 1;
}

const wn_export_entry wn_cryptbase_exports[] = {
    { "SystemFunction036", cb_SystemFunction036 },
    { NULL, NULL },
};

/* --- crypt32: base64 is real, the rest is honest failure ------------------------ */

static int b64_idx(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static char b64_char(int v)
{
    static const char tab[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    return tab[v & 63];
}

/* CRYPT_STRING_BASE64: with header/footer lines. flags 1 = BASE64, 3 = ... */
static WN_API int32_t c32_CryptBinaryToStringA(const uint8_t *bin,
                                               uint32_t len, uint32_t flags,
                                               char *out, uint32_t *outlen)
{
    if (!bin || !outlen || (flags & ~1u) != 0)
        return 0;
    uint32_t need = 0;
    if (flags & 1 /* CRYPT_STRING_BASE64: plain, no headers */) {
        need = ((len + 2) / 3) * 4 + 2;
    } else {
        need = ((len + 2) / 3) * 4 + 2;
    }
    if (!out || *outlen < need) {
        *outlen = need;
        wn_last_error_set(WN_ERR_INSUFFICIENT_BUFFER);
        return 0;
    }
    uint32_t oi = 0;
    for (uint32_t i = 0; i < len; i += 3) {
        uint32_t v = bin[i] << 16;
        if (i + 1 < len) v |= bin[i + 1] << 8;
        if (i + 2 < len) v |= bin[i + 2];
        out[oi++] = b64_char(v >> 18);
        out[oi++] = b64_char(v >> 12);
        out[oi++] = (i + 1 < len) ? b64_char(v >> 6) : '=';
        out[oi++] = (i + 2 < len) ? b64_char(v) : '=';
    }
    out[oi++] = '\r';
    out[oi++] = '\n';
    out[oi] = 0;
    *outlen = oi;
    return 1;
}

static WN_API int32_t c32_CryptStringToBinaryA(const char *str, uint32_t len,
                                               uint32_t flags, uint8_t *bin,
                                               uint32_t *binlen, uint32_t *skip,
                                               uint32_t *flagsret)
{
    (void)flags;
    (void)skip;
    (void)flagsret;
    if (!str || !binlen)
        return 0;
    if (!len)
        len = (uint32_t)strlen(str);
    /* strip whitespace + header/footer lines */
    uint8_t *tmp = wn_xmalloc(len ? len : 1);
    uint32_t n = 0;
    for (uint32_t i = 0; i < len; i++) {
        char c = str[i];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
            continue;
        tmp[n++] = (uint8_t)c;
    }
    uint32_t out = 0;
    for (uint32_t i = 0; i + 3 < n; i += 4) {
        int a = b64_idx((char)tmp[i]), b = b64_idx((char)tmp[i + 1]);
        int c = b64_idx((char)tmp[i + 2]), d = b64_idx((char)tmp[i + 3]);
        if (a < 0 || b < 0) { free(tmp); return 0; }
        int pad = 0;
        if (c < 0 || (char)tmp[i + 2] == '=') { c = 0; pad++; }
        if (d < 0 || (char)tmp[i + 3] == '=') { d = 0; pad++; }
        uint32_t v = (uint32_t)a << 18 | (uint32_t)b << 12
                   | (uint32_t)c << 6 | (uint32_t)d;
        if (out + 3 - (uint32_t)pad > (bin ? *binlen : 0xFFFFFFFFu) && bin) {
            free(tmp);
            wn_last_error_set(WN_ERR_INSUFFICIENT_BUFFER);
            return 0;
        }
        if (bin) {
            if (pad < 2) bin[out] = (uint8_t)(v >> 16);
            if (pad < 1) bin[out + 1] = (uint8_t)(v >> 8);
            bin[out + 2] = (uint8_t)v;
        }
        out += 3 - (uint32_t)pad;
        if (pad)
            break;
    }
    free(tmp);
    *binlen = out;
    return 1;
}

static WN_API void *c32_CertOpenSystemStoreA(uint64_t prov, const char *name)
{
    (void)prov;
    (void)name;
    wn_log(WN_LOG_WARN, "crypt32: CertOpenSystemStoreA('%s') -> NULL "
           "(no certificate store)", name ? name : "?");
    wn_last_error_set(WN_ERR_CALL_NOT_IMPLEMENTED);
    return NULL;
}

static WN_API int32_t c32_CryptProtectData(const void *in, const char *desc,
                                           const void *entropy, void *rsv,
                                           void *prompt, uint32_t flags,
                                           void *out)
{
    (void)in; (void)desc; (void)entropy; (void)rsv; (void)prompt; (void)flags;
    (void)out;
    wn_log(WN_LOG_WARN, "crypt32: CryptProtectData (DPAPI) not implemented "
           "-> FALSE");
    wn_last_error_set(WN_ERR_CALL_NOT_IMPLEMENTED);
    return 0;
}

static WN_API int32_t c32_CryptUnprotectData(const void *in, char **desc,
                                             const void *entropy, void *rsv,
                                             void *prompt, uint32_t flags,
                                             void *out)
{
    (void)in; (void)desc; (void)entropy; (void)rsv; (void)prompt; (void)flags;
    (void)out;
    wn_log(WN_LOG_WARN, "crypt32: CryptUnprotectData (DPAPI) not implemented "
           "-> FALSE");
    wn_last_error_set(WN_ERR_CALL_NOT_IMPLEMENTED);
    return 0;
}

const wn_export_entry wn_crypt32_exports[] = {
    { "CryptBinaryToStringA",   c32_CryptBinaryToStringA },
    { "CryptStringToBinaryA",   c32_CryptStringToBinaryA },
    { "CertOpenSystemStoreA",   c32_CertOpenSystemStoreA },
    { "CryptProtectData",       c32_CryptProtectData },
    { "CryptUnprotectData",     c32_CryptUnprotectData },
    { NULL, NULL },
};
