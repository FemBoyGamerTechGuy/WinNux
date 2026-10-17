/* wn_util.c — allocation, UTF conversion, string/path helpers. */
#include "wn_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void *wn_xmalloc(size_t n)
{
    void *p = malloc(n ? n : 1);
    if (!p) {
        /* Host-side OOM: abort loudly rather than fake success. */
        fprintf(stderr, "[winnux] fatal: out of memory (%zu bytes)\n", n);
        abort();
    }
    return p;
}

void *wn_xcalloc(size_t n, size_t sz)
{
    void *p = calloc(n ? n : 1, sz ? sz : 1);
    if (!p) {
        fprintf(stderr, "[winnux] fatal: out of memory (%zu x %zu)\n", n, sz);
        abort();
    }
    return p;
}

void *wn_xrealloc(void *p, size_t n)
{
    void *q = realloc(p, n ? n : 1);
    if (!q) {
        fprintf(stderr, "[winnux] fatal: out of memory (%zu bytes)\n", n);
        abort();
    }
    return q;
}

char *wn_xstrdup(const char *s)
{
    char *d = strdup(s ? s : "");
    if (!d) {
        fprintf(stderr, "[winnux] fatal: strdup OOM\n");
        abort();
    }
    return d;
}

static char fold_ascii(char c)
{
    if (c >= 'A' && c <= 'Z')
        return c + 32;
    return c;
}

int wn_strcaseeq(const char *a, const char *b)
{
    if (!a || !b)
        return a == b;
    while (*a && *b) {
        if (fold_ascii(*a) != fold_ascii(*b))
            return 0;
        a++; b++;
    }
    return *a == *b;
}

int wn_strcaseprefix(const char *s, const char *prefix)
{
    if (!s || !prefix)
        return 0;
    while (*prefix) {
        if (!*s)
            return 0;
        if (fold_ascii(*s) != fold_ascii(*prefix))
            return 0;
        s++; prefix++;
    }
    return 1;
}

void wn_strlower(char *dst, size_t cap, const char *src)
{
    size_t i = 0;
    for (; src[i] && i + 1 < cap; i++)
        dst[i] = fold_ascii(src[i]);
    dst[i] = '\0';
}

/* --- UTF-16 <-> UTF-8 ------------------------------------------------- */

uint16_t *wn_utf8_to_utf16_n(const char *utf8, size_t nbytes)
{
    size_t n = 0;
    uint16_t *out = wn_xmalloc((nbytes + 1) * 2 + 2);
    const unsigned char *s = (const unsigned char *)utf8;
    const unsigned char *end = s + nbytes;
    while (s < end) {
        uint32_t cp;
        int rem = (int)(end - s);
        if (s[0] < 0x80) { cp = s[0]; s += 1; }
        else if (rem >= 2 && (s[0] & 0xE0) == 0xC0 && (s[1] & 0xC0) == 0x80) {
            cp = ((uint32_t)(s[0] & 0x1F) << 6) | (s[1] & 0x3F); s += 2;
        } else if (rem >= 3 && (s[0] & 0xF0) == 0xE0 && (s[1] & 0xC0) == 0x80 &&
                   (s[2] & 0xC0) == 0x80) {
            cp = ((uint32_t)(s[0] & 0x0F) << 12) | ((uint32_t)(s[1] & 0x3F) << 6)
               | (s[2] & 0x3F);
            s += 3;
        } else if (rem >= 4 && (s[0] & 0xF8) == 0xF0 && (s[1] & 0xC0) == 0x80 &&
                   (s[2] & 0xC0) == 0x80 && (s[3] & 0xC0) == 0x80) {
            cp = ((uint32_t)(s[0] & 0x07) << 18) | ((uint32_t)(s[1] & 0x3F) << 12)
               | ((uint32_t)(s[2] & 0x3F) << 6) | (s[3] & 0x3F);
            s += 4;
        } else if (rem >= 1) {
            cp = 0xFFFD; s += 1;   /* tolerant: replace, don't fail */
        } else {
            break;
        }
        if (cp < 0x10000) {
            out[n++] = (uint16_t)cp;
        } else {
            cp -= 0x10000;
            out[n++] = 0xD800 | (cp >> 10);
            out[n++] = 0xDC00 | (cp & 0x3FF);
        }
    }
    out[n] = 0;
    return out;
}

char *wn_utf16_to_utf8(const uint16_t *w, size_t len16)
{
    /* Worst case: each UTF-16 unit becomes 3 bytes (BMP), pairs 4. */
    char *out = wn_xmalloc(len16 * 3 + 4);
    size_t n = 0, i = 0;
    while (i < len16 && w[i]) {
        uint32_t cp = w[i++];
        if (cp >= 0xD800 && cp <= 0xDBFF && i < len16 &&
            w[i] >= 0xDC00 && w[i] <= 0xDFFF) {
            cp = 0x10000 + ((cp - 0xD800) << 10) + (w[i] - 0xDC00);
            i++;
        } else if (cp >= 0xD800 && cp <= 0xDFFF) {
            cp = 0xFFFD; /* lone surrogate: replacement char */
        }
        if (cp < 0x80) {
            out[n++] = (char)cp;
        } else if (cp < 0x800) {
            out[n++] = (char)(0xC0 | (cp >> 6));
            out[n++] = (char)(0x80 | (cp & 0x3F));
        } else if (cp < 0x10000) {
            out[n++] = (char)(0xE0 | (cp >> 12));
            out[n++] = (char)(0x80 | ((cp >> 6) & 0x3F));
            out[n++] = (char)(0x80 | (cp & 0x3F));
        } else {
            out[n++] = (char)(0xF0 | (cp >> 18));
            out[n++] = (char)(0x80 | ((cp >> 12) & 0x3F));
            out[n++] = (char)(0x80 | ((cp >> 6) & 0x3F));
            out[n++] = (char)(0x80 | (cp & 0x3F));
        }
    }
    out[n] = '\0';
    return out;
}

const char *wn_path_basename(const char *path, size_t *dir_len)
{
    const char *slash = strrchr(path, '/');
    if (!slash) {
        if (dir_len) *dir_len = 0;
        return path;
    }
    if (dir_len) *dir_len = (size_t)(slash - path);
    return slash + 1;
}

/* --- growable buffer --------------------------------------------------- */

void wn_buf_init(wn_buf *b) { b->data = NULL; b->len = 0; b->cap = 0; }

void wn_buf_free(wn_buf *b) { free(b->data); wn_buf_init(b); }

void wn_buf_append(wn_buf *b, const void *data, size_t n)
{
    if (b->len + n > b->cap) {
        size_t cap = b->cap ? b->cap * 2 : 128;
        while (cap < b->len + n)
            cap *= 2;
        b->data = wn_xrealloc(b->data, cap);
        b->cap = cap;
    }
    memcpy(b->data + b->len, data, n);
    b->len += n;
}

void wn_buf_append_str(wn_buf *b, const char *s)
{
    wn_buf_append(b, s, strlen(s));
}

uint64_t wn_monotonic_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

uint16_t *wn_utf8_to_utf16(const char *utf8, size_t *out_len16)
{
    size_t n = strlen(utf8);
    uint16_t *w = wn_utf8_to_utf16_n(utf8, n);
    if (out_len16) {
        if (!w) { *out_len16 = 0; return NULL; }
        size_t l = 0;
        while (w[l]) l++;
        *out_len16 = l;
    }
    return w;
}
