/* msvcrt.c — builtin msvcrt.dll / ucrtbase.dll subset.
 *
 * The printf engine is written in-tree (no libc varargs pass-through: the
 * MS-ABI va_list is decoded with __builtin_ms_va_list, each argument is
 * extracted, then formatted with host snprintf — allowed: libc).
 */
#include "wn_dll.h"
#include "wn_types.h"
#include "wn_process.h"
#include "wn_log.h"
#include "wn_util.h"
#include "wn_path.h"
#include <fcntl.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <math.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* --- guest-visible CRT data -------------------------------------------------- */

static int g_fmode = 0;
static int g_commode = 0;
static char **g_initenv_ptr;          /* __initenv */

/* FILE shells for stdin/stdout/stderr.
 * MSVC CRT computes stdout as __iob_func() + N*sizeof(FILE) with
 * sizeof(FILE) == 48 on x64 — the shells MUST match that stride, and
 * fopen-returned FILEs carry a magic so we can validate guest pointers. */
#define WN_MS_FILE_MAGIC 0x574E4646u   /* 'WNFF' */
#define WN_MS_FILE_SIZE  48

typedef struct wn_ms_file {
    uint32_t magic;
    int32_t  fd;
    int32_t  owned;
    int32_t  eof;
    uint8_t  pad[WN_MS_FILE_SIZE - 16];
} wn_ms_file;

_Static_assert(sizeof(wn_ms_file) == WN_MS_FILE_SIZE, "MSVC FILE size ABI");

static wn_ms_file g_std_files[3] = {
    { WN_MS_FILE_MAGIC, 0, 0, 0, { 0 } },
    { WN_MS_FILE_MAGIC, 1, 0, 0, { 0 } },
    { WN_MS_FILE_MAGIC, 2, 0, 0, { 0 } },
};

/* Map a guest FILE* to our object (validates both std shells and fopen
 * results; returns NULL for foreign pointers). */
static wn_ms_file *ms_file_of(const void *p)
{
    if (!p)
        return NULL;
    uintptr_t off = (uintptr_t)p - (uintptr_t)g_std_files;
    if (off < 3 * sizeof(wn_ms_file) &&
        (off % sizeof(wn_ms_file)) == 0)
        return &g_std_files[off / sizeof(wn_ms_file)];
    const wn_ms_file *f = p;
    if (f->magic == WN_MS_FILE_MAGIC)
        return (wn_ms_file *)f;
    return NULL;
}

static WN_API wn_ms_file *ms___iob_func(void)
{
    return g_std_files;
}

/* --- errno bridge ---------------------------------------------------------------- */

static __thread int g_ms_errno;

static WN_API int *ms__errno(void)
{
    return &g_ms_errno;
}

/* --- alloc (map to host malloc; guest owns) ---------------------------------------- */

static WN_API void *ms_malloc(uint64_t n) { return malloc((size_t)n); }
static WN_API void *ms_calloc(uint64_t n, uint64_t sz) { return calloc((size_t)n, (size_t)sz); }
static WN_API void *ms_realloc(void *p, uint64_t n) { return realloc(p, (size_t)n); }
static WN_API void ms_free(void *p) { free(p); }

/* --- strings (forward to libc; ms_abi wrappers) ------------------------------------- */

static WN_API uint64_t ms_memcpy(void *d, const void *s, uint64_t n)
{
    return (uint64_t)(uintptr_t)memcpy(d, s, (size_t)n);
}
static WN_API uint64_t ms_memset(void *d, int32_t c, uint64_t n)
{
    return (uint64_t)(uintptr_t)memset(d, c, (size_t)n);
}
static WN_API int32_t ms_memcmp(const void *a, const void *b, uint64_t n)
{
    return memcmp(a, b, (size_t)n) > 0 ? 1 : memcmp(a, b, (size_t)n) < 0 ? -1 : 0;
}
static WN_API uint64_t ms_memmove(void *d, const void *s, uint64_t n)
{
    return (uint64_t)(uintptr_t)memmove(d, s, (size_t)n);
}
static WN_API int64_t ms_strlen(const char *s) { return (int64_t)strlen(s); }
static WN_API int32_t ms_strcmp(const char *a, const char *b) { return strcmp(a, b); }
static WN_API int32_t ms_strncmp(const char *a, const char *b, uint64_t n)
{
    int r = strncmp(a, b, (size_t)n);
    return (r > 0) - (r < 0);
}
static WN_API char *ms_strcpy(char *d, const char *s) { return strcpy(d, s); }
static WN_API char *ms_strncpy(char *d, const char *s, uint64_t n)
{
    return strncpy(d, s, (size_t)n);
}
static WN_API char *ms_strcat(char *d, const char *s) { return strcat(d, s); }
static WN_API char *ms_strchr(const char *s, int32_t c) { return strchr(s, c); }
static WN_API char *ms_strrchr(const char *s, int32_t c) { return strrchr(s, c); }
static WN_API char *ms_strstr(const char *h, const char *n) { return strstr(h, n); }
static WN_API char *ms_strupr(char *s)
{
    for (char *p = s; *p; p++)
        *p = (char)toupper((unsigned char)*p);
    return s;
}
static WN_API char *ms_strlwr(char *s)
{
    for (char *p = s; *p; p++)
        *p = (char)tolower((unsigned char)*p);
    return s;
}
static WN_API int32_t ms_stricmp(const char *a, const char *b)
{
    return strcasecmp(a, b) > 0 ? 1 : strcasecmp(a, b) < 0 ? -1 : 0;
}
static WN_API int32_t ms_strnicmp(const char *a, const char *b, uint64_t n)
{
    return strncasecmp(a, b, (size_t)n) > 0 ? 1 : strncasecmp(a, b, (size_t)n) < 0 ? -1 : 0;
}
static WN_API char *ms_strdup(const char *s) { return strdup(s); }
static WN_API int64_t ms_wcslen(const uint16_t *s)
{
    if (!s)
        return 0;
    int64_t n = 0;
    while (s[n])
        n++;
    return n;
}

static WN_API int32_t ms_setvbuf(wn_ms_file *f, char *buf, int32_t mode, uint64_t size)
{
    (void)buf;
    (void)mode;
    (void)size;
    f = ms_file_of(f);
    return f ? 0 : -1;   /* we are unbuffered at the FILE level already */
}

static WN_API int32_t ms_ferror(wn_ms_file *f)
{
    f = ms_file_of(f);
    return f ? 0 : 1;
}

static WN_API char *ms_strerror(int32_t e)
{
    switch (e) {
    case 0:  return "";
    case 2:  return "No such file or directory";
    case 12: return "Not enough space";
    case 13: return "Permission denied";
    case 22: return "Invalid argument";
    default: return "Unknown error";
    }
}

/* --- conversions -------------------------------------------------------------------- */

static WN_API int32_t ms_atoi(const char *s) { return (int32_t)atoi(s); }
static WN_API int64_t ms_atol(const char *s) { return atol(s); }
static WN_API int64_t ms_atoll(const char *s) { return atoll(s); }
static WN_API double ms_atof(const char *s) { return atof(s); }
static WN_API int64_t ms_strtol(const char *s, char **e, int32_t b)
{
    return strtol(s, e, b);
}
static WN_API uint64_t ms_strtoul(const char *s, char **e, int32_t b)
{
    return strtoul(s, e, b);
}
static WN_API double ms_strtod(const char *s, char **e) { return strtod(s, e); }
static WN_API int64_t ms_abs(int64_t v) { return v < 0 ? -v : v; }
static WN_API double ms_fabs(double v) { return fabs(v); }

/* Helper: resolve a to-be-created file (parent must exist). */
int wn_ms_fopen_create(const char *win, const char *mode, char *out, size_t cap)
{
    if (!strchr(mode, 'w') && !strchr(mode, 'a'))
        return -1;
    char fullhost[4200];
    if (wn_path_win_to_host(win, fullhost, sizeof fullhost) != 0)
        return -1;
    size_t dl;
    const char *base = wn_path_basename(fullhost, &dl);
    char dirpart[4100];
    if (dl >= sizeof dirpart)
        return -1;
    memcpy(dirpart, fullhost, dl);
    dirpart[dl] = '\0';
    snprintf(out, cap, "%s/%s", dl ? dirpart : ".", base);
    return 0;
}

/* --- exit / atexit ------------------------------------------------------------------- */

static WN_API void ms_exit(int32_t code)
{
    wn_process_exit(code);
}

static WN_API void ms__exit(int32_t code)
{
    _exit(code);
}

static WN_API void ms_abort(void)
{
    wn_log(WN_LOG_ERR, "msvcrt: abort() called by guest");
    exit(3);
}

static WN_API int32_t ms_atexit(void (*fn)(void))
{
    return wn_process_atexit(fn) ? 0 : -1;
}

static WN_API void ms__cexit(void)
{
    for (int i = g_proc.atexit_count - 1; i >= 0; i--)
        g_proc.atexit_fns[i]();
}

/* --- CRT startup hooks ----------------------------------------------------------------- */

static WN_API void ms___set_app_type(int32_t t)
{
    (void)t;
}

static WN_API void ms__amsg_exit(int32_t code)
{
    wn_log(WN_LOG_ERR, "msvcrt: _amsg_exit(%d) — CRT runtime error", code);
    exit(255);
}

typedef WN_API void (*wn_ms_voidfn)(void);
typedef WN_API int32_t (*wn_ms_intfn)(void);

static WN_API void ms__initterm(wn_ms_voidfn *start, wn_ms_voidfn *end)
{
    for (wn_ms_voidfn *p = start; p < end; p++)
        if (*p)
            (*p)();
}

static WN_API int32_t ms__initterm_e(wn_ms_intfn *start, wn_ms_intfn *end)
{
    for (wn_ms_intfn *p = start; p < end; p++)
        if (*p) {
            int32_t r = (*p)();
            if (r) {
                wn_log(WN_LOG_ERR, "msvcrt: _initterm_e initializer failed (%d)", r);
                return r;
            }
        }
    return 0;
}

static WN_API void ms__lock(int32_t n) { (void)n; }
static WN_API void ms__unlock(int32_t n) { (void)n; }

static WN_API void ms___setusermatherr(void *h) { (void)h; }

static WN_API uint32_t ms__controlfp(uint32_t a, uint32_t b)
{
    (void)a;
    (void)b;
    return 0x8001F;    /* default CW */
}

static WN_API uint32_t ms__control87(uint32_t a, uint32_t b)
{
    return ms__controlfp(a, b);
}

static WN_API void ms__fpreset(void) {}

static WN_API uint32_t ms___lc_codepage_func(void) { return 1252; }
static WN_API uint32_t ms___mb_cur_max_func(void) { return 1; }

/* localeconv: minimal C-locale lconv. */
struct ms_lconv {
    char *decimal_point, *thousands_sep, *grouping;
    char *int_curr_symbol, *currency_symbol, *mon_decimal_point,
         *mon_thousands_sep, *mon_grouping, *positive_sign, *negative_sign;
    char int_frac_digits, frac_digits, p_cs_precedes, p_sep_by_space,
         n_cs_precedes, n_sep_by_space, p_sign_posn, n_sign_posn;
    char *p_cs_precedes_2;
};
static struct ms_lconv g_lconv = {
    ".", ",", "", "", "", "", "", "", "", "",
    -1, -1, -1, -1, -1, -1, -1, -1, "",
};

static WN_API void *ms_localeconv(void)
{
    return &g_lconv;
}

static WN_API void *ms___C_specific_handler(void *rec, void *frame, void *ctx,
                                            void *disp)
{
    (void)rec; (void)frame; (void)ctx; (void)disp;
    wn_log(WN_LOG_WARN, "msvcrt: __C_specific_handler invoked (SEH scope "
           "search unsupported; passing on)");
    return 0;   /* ExceptionContinueSearch */
}

static WN_API void *ms_signal(int32_t sig, void *fn)
{
    wn_log(WN_LOG_DEBUG, "msvcrt: signal(%d) registered (no delivery yet)", sig);
    (void)fn;
    return 0;
}

/* --- __getmainargs ------------------------------------------------------------------------ */

static int g_argc;
static char **g_argv;
static char **g_envp;

static WN_API int32_t ms___getmainargs(int32_t *argc, char ***argv, char ***envp,
                                       int32_t wild, void *si)
{
    (void)wild;
    (void)si;
    *argc = g_argc;
    *argv = g_argv;
    *envp = g_envp;
    return 0;
}

void wn_ms_set_args(int argc, char **argv)
{
    g_argc = argc;
    g_argv = argv;
    g_envp = g_proc.env_utf8;
    g_initenv_ptr = g_proc.env_utf8;
}

/* --- printf engine ---------------------------------------------------------------------------- */

typedef void (*emit_fn)(void *ctx, const char *data, size_t n);

struct emit_buf {
    char *p;
    size_t left;
};

static void emit_to_buf(void *ctx, const char *data, size_t n)
{
    struct emit_buf *b = ctx;
    if (b->left == 0)
        return;
    size_t c = n < b->left ? n : b->left - 1;
    memcpy(b->p, data, c);
    b->p += c;
    *b->p = '\0';
    b->left -= c;
}

struct emit_fd {
    int fd;
    int is_console;
    size_t total;
};

/* Counting emitter (size measurement without storage). */
static void emit_count(void *ctx, const char *data, size_t n)
{
    (void)data;
    *(size_t *)ctx += n;
}

static void emit_to_fd(void *ctx, const char *data, size_t n)
{
    struct emit_fd *e = ctx;
    if (e->is_console) {
        /* \n -> \r\n */
        size_t start = 0;
        for (size_t i = 0; i < n; i++) {
            if (data[i] == '\n' && (i == 0 || data[i - 1] != '\r')) {
                (void)!write(e->fd, data + start, i - start);
                (void)!write(e->fd, "\r\n", 2);
                start = i + 1;
            }
        }
        if (start < n)
            (void)!write(e->fd, data + start, n - start);
    } else {
        size_t off = 0;
        while (off < n) {
            ssize_t w = write(e->fd, data + off, n - off);
            if (w <= 0)
                break;
            off += (size_t)w;
        }
    }
    e->total += n;
}

/* MS x64 varargs decode: every argument occupies one 8-byte slot in the
 * register save area (args 1-4, spilled by the ms_abi prologue) followed by
 * stack slots (args 5+). va_list in an ms_abi function is a plain char*
 * into that area - exactly like the MS CRT's va_list. */
static uint64_t ms_next(void **app)
{
    char *p = *(char **)app;
    uint64_t v;
    memcpy(&v, p, 8);
    *(char **)app = p + 8;
    return v;
}

static double ms_next_double(void **app)
{
    uint64_t b = ms_next(app);
    double d;
    memcpy(&d, &b, 8);
    return d;
}

/* Core formatter. Returns 0 on success (like vfprintf) or -1. */
static int vformat_core(emit_fn emit, void *ctx, const char *fmt, char **ap)
{
    const char *p = fmt;
    char tmp[512];

    while (*p) {
        if (*p != '%') {
            const char *start = p;
            while (*p && *p != '%')
                p++;
            emit(ctx, start, (size_t)(p - start));
            continue;
        }
        p++;
        /* flags */
        char flag = 0;
        int zero = 0, minus = 0, plus = 0, space = 0;
        for (;; p++) {
            if (*p == '0' && !minus && !zero) zero = 1;
            else if (*p == '-') { minus = 1; zero = 0; }
            else if (*p == '+') plus = 1;
            else if (*p == ' ') space = 1;
            else if (*p == '#') flag = '#';
            else break;
        }
        (void)flag;
        /* width */
        int width = 0;
        if (*p == '*') {
            width = (int)ms_next((void **)ap);
            if (width < 0) { minus = 1; width = -width; }
            p++;
        } else {
            while (isdigit((unsigned char)*p)) { width = width * 10 + (*p - '0'); p++; }
        }
        /* precision */
        int prec = -1;
        if (*p == '.') {
            p++;
            prec = 0;
            if (*p == '*') { prec = (int)ms_next((void **)ap); p++; }
            else while (isdigit((unsigned char)*p)) { prec = prec * 10 + (*p - '0'); p++; }
        }
        /* length modifier */
        int lng = 0;   /* 0 none, 1 l, 2 ll/I64, 3 z, 4 h */
        if (p[0] == 'I' && p[1] == '6' && p[2] == '4') { lng = 2; p += 3; }
        else if (p[0] == 'l' && p[1] == 'l') { lng = 2; p += 2; }
        else if (p[0] == 'z') { lng = 3; p += 1; }
        else if (p[0] == 'l') { lng = 1; p += 1; }
        else if (p[0] == 'h') { lng = 4; p += 1; }

        char conv = *p;
        if (!conv)
            break;
        p++;

        char *out = tmp;
        size_t outlen;

        switch (conv) {
        case '%':
            emit(ctx, "%", 1);
            continue;
        case 'c': {
            int c = (int)ms_next((void **)ap);
            char cc = (char)c;
            emit(ctx, &cc, 1);
            continue;
        }
        case 's': {
            const char *s = (const char *)(uintptr_t)ms_next((void **)ap);
            if (!s)
                s = "(null)";
            size_t l = strlen(s);
            if (prec >= 0 && (size_t)prec < l)
                l = (size_t)prec;
            /* width padding */
            if ((size_t)width > l) {
                size_t pad = (size_t)width - l;
                char *pb = wn_xmalloc(pad + 1);
                memset(pb, minus ? ' ' : ' ', pad);
                if (minus) { emit(ctx, s, l); emit(ctx, pb, pad); }
                else { emit(ctx, pb, pad); emit(ctx, s, l); }
                free(pb);
            } else {
                emit(ctx, s, l);
            }
            continue;
        }
        case 'd':
        case 'i': {
            long long v = (long long)ms_next((void **)ap);
            if (lng == 4)
                v = (short)v;
            char sign = 0;
            if (v < 0) sign = '-';
            else if (plus) sign = '+';
            else if (space) sign = ' ';
            unsigned long long uv = v < 0 ? (unsigned long long)(-(v + 1)) + 1 : (unsigned long long)v;
            char nb[32];
            snprintf(nb, sizeof nb, "%llu", uv);
            size_t nl = strlen(nb);
            size_t digits = nl;
            if (prec >= 0 && digits < (size_t)prec)
                digits = (size_t)prec;
            size_t total = digits + (sign ? 1 : 0);
            size_t pad = (size_t)width > total ? (size_t)width - total : 0;
            char *big = nb;
            if (digits > sizeof nb - 1)
                big = wn_xmalloc(digits + 1);
            /* build digit string with precision zero-fill */
            char *dp = big;
            for (size_t i = 0; i < digits - nl; i++)
                *dp++ = '0';
            memcpy(dp, nb, nl + 1);
            if (minus) {
                if (sign) { char s2[2] = { sign, 0 }; emit(ctx, s2, 1); }
                emit(ctx, big, digits);
                for (size_t i = 0; i < pad; i++) emit(ctx, " ", 1);
            } else {
                for (size_t i = 0; i < pad; i++) emit(ctx, zero && prec < 0 ? "0" : " ", 1);
                if (sign) { char s2[2] = { sign, 0 }; emit(ctx, s2, 1); }
                emit(ctx, big, digits);
            }
            if (big != nb)
                free(big);
            continue;
        }
        case 'u':
        case 'x':
        case 'X':
        case 'o': {
            unsigned long long v = ms_next((void **)ap);
            char spec[3] = { conv, 0 };
            char nb[40];
            snprintf(nb, sizeof nb, conv == 'u' ? "%llu" : conv == 'o' ? "%llo" : "%llX", v);
            size_t nl = strlen(nb);
            size_t digits = nl;
            if (prec >= 0 && digits < (size_t)prec)
                digits = (size_t)prec;
            size_t total = digits;
            size_t pad = (size_t)width > total ? (size_t)width - total : 0;
            (void)spec;
            if (minus) {
                for (size_t i = 0; i < digits - nl; i++) emit(ctx, "0", 1);
                emit(ctx, nb, nl);
                for (size_t i = 0; i < pad; i++) emit(ctx, " ", 1);
            } else {
                for (size_t i = 0; i < pad; i++) emit(ctx, zero && prec < 0 ? "0" : " ", 1);
                for (size_t i = 0; i < digits - nl; i++) emit(ctx, "0", 1);
                emit(ctx, nb, nl);
            }
            continue;
        }
        case 'p': {
            void *v = (void *)(uintptr_t)ms_next((void **)ap);
            snprintf(tmp, sizeof tmp, "0x%llx", (unsigned long long)(uintptr_t)v);
            out = tmp;
            outlen = strlen(tmp);
            break;
        }
        case 'f':
        case 'e':
        case 'E':
        case 'g':
        case 'G': {
            double v = ms_next_double((void **)ap);
            char spec[32];
            snprintf(spec, sizeof spec, "%%.%d%c", prec >= 0 ? prec : 6, conv);
            int n = snprintf(tmp, sizeof tmp, spec, v);
            outlen = n > 0 ? (size_t)n : 0;
            out = tmp;
            /* width padding */
            if ((size_t)width > outlen) {
                size_t pad = (size_t)width - outlen;
                char *pb = wn_xmalloc(pad + outlen + 1);
                if (minus) {
                    memcpy(pb, tmp, outlen);
                    memset(pb + outlen, ' ', pad);
                } else {
                    memset(pb, ' ', pad);
                    memcpy(pb + pad, tmp, outlen);
                }
                pb[pad + outlen] = '\0';
                emit(ctx, pb, pad + outlen);
                free(pb);
                continue;
            }
            break;
        }
        default:
            /* Unknown conversion: emit verbatim. */
            emit(ctx, "%", 1);
            emit(ctx, &conv, 1);
            continue;
        }
        /* 'p' and any buffered conversions land here. */
        emit(ctx, out, outlen);
    }
    return 0;
}

/* --- printf family ----------------------------------------------------------------------- */

static WN_API int64_t ms_vsprintf(char *dst, const char *fmt, va_list ap);
static WN_API int64_t ms_vsnprintf(char *dst, uint64_t cap, const char *fmt, va_list ap);

static WN_API int64_t ms_printf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    char *argp = (char *)ap;
    struct emit_fd e = { 1, isatty(1), 0 };
    vformat_core(emit_to_fd, &e, fmt, &argp);
    va_end(ap);
    return (int64_t)e.total;
}

static WN_API int64_t ms_vprintf(const char *fmt, va_list ap)
{
    char *argp = (char *)ap;
    struct emit_fd e = { 1, isatty(1), 0 };
    vformat_core(emit_to_fd, &e, fmt, &argp);
    return (int64_t)e.total;
}

static WN_API int64_t ms_fprintf(wn_ms_file *f, const char *fmt, ...)
{
    f = ms_file_of(f);
    if (!f) {
        wn_log(WN_LOG_ERR, "msvcrt: fprintf(bad FILE* %p)", (void *)f);
        return -1;
    }
    va_list ap;
    va_start(ap, fmt);
    char *argp = (char *)ap;
    struct emit_fd e = { f->fd, isatty(f->fd), 0 };
    vformat_core(emit_to_fd, &e, fmt, &argp);
    va_end(ap);
    return (int64_t)e.total;
}

static WN_API int64_t ms_vfprintf(wn_ms_file *f, const char *fmt, va_list ap)
{
    f = ms_file_of(f);
    if (!f) {
        wn_log(WN_LOG_ERR, "msvcrt: vfprintf(bad FILE*)");
        return -1;
    }
    char *argp = (char *)ap;
    struct emit_fd e = { f->fd, isatty(f->fd), 0 };
    vformat_core(emit_to_fd, &e, fmt, &argp);
    return (int64_t)e.total;
}

static WN_API int64_t ms_sprintf(char *dst, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int64_t r = ms_vsprintf(dst, fmt, ap);
    va_end(ap);
    return r;
}

static WN_API int64_t ms_vsprintf(char *dst, const char *fmt, va_list ap)
{
    char *argp = (char *)ap;
    struct emit_buf b = { dst, (size_t)-1 };
    vformat_core(emit_to_buf, &b, fmt, &argp);
    return (int64_t)strlen(dst);
}

static WN_API int64_t ms_snprintf(char *dst, uint64_t cap, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int64_t r = ms_vsnprintf(dst, cap, fmt, ap);
    va_end(ap);
    return r;
}

static WN_API int64_t ms_vsnprintf(char *dst, uint64_t cap, const char *fmt, va_list ap)
{
    if (!dst || cap == 0) {
        /* measure only: count bytes. */
        char *argp = (char *)ap;
        size_t total = 0;
        vformat_core(emit_count, &total, fmt, &argp);
        return (int64_t)total;
    }
    char *argp = (char *)ap;
    struct emit_buf b = { dst, (size_t)cap };
    vformat_core(emit_to_buf, &b, fmt, &argp);
    return (int64_t)strlen(dst);
}

static WN_API int64_t ms_puts(const char *s)
{
    struct emit_fd e = { 1, isatty(1), 0 };
    if (s)
        emit_to_fd(&e, s, strlen(s));
    emit_to_fd(&e, "\n", 1);
    return (s || 1) ? 0 : -1;
}

static WN_API int32_t ms_fputc(int32_t c, wn_ms_file *f)
{
    f = ms_file_of(f);
    if (!f)
        return -1;
    char cc = (char)c;
    ssize_t w = write(f->fd, &cc, 1);
    return w == 1 ? c : -1;
}

static WN_API int32_t ms_putchar(int32_t c)
{
    return ms_fputc(c, &g_std_files[1]);
}

static WN_API int64_t ms_fputs(const char *s, wn_ms_file *f)
{
    f = ms_file_of(f);
    if (!s || !f)
        return -1;
    ssize_t w = write(f->fd, s, strlen(s));
    return w >= 0 ? 0 : -1;
}

static WN_API int32_t ms_fflush(wn_ms_file *f)
{
    if (!f) {
        fflush(NULL);
        return 0;
    }
    return 0;
}

/* --- stdio file layer ------------------------------------------------------------------------ */

static WN_API wn_ms_file *ms_fopen(const char *path, const char *mode)
{
    if (!path || !mode)
        return NULL;
    char host[2100];
    if (wn_path_resolve_ci(path, host, sizeof host) != 0) {
        if (wn_ms_fopen_create(path, mode, host, sizeof host) != 0)
            return NULL;
    }
    int oflags = O_CLOEXEC;
    char m0 = mode[0];
    int plus = strchr(mode, '+') != NULL;
    if (m0 == 'r')      oflags |= plus ? O_RDWR : O_RDONLY;
    else if (m0 == 'w') oflags |= (plus ? O_RDWR : O_WRONLY) | O_CREAT | O_TRUNC;
    else if (m0 == 'a') oflags |= (plus ? O_RDWR : O_WRONLY) | O_CREAT | O_APPEND;
    else return NULL;
    int fd = open(host, oflags, 0666);
    if (fd < 0)
        return NULL;
    wn_ms_file *f = wn_xcalloc(1, sizeof *f);
    f->magic = WN_MS_FILE_MAGIC;
    f->fd = fd;
    f->owned = 1;
    return f;
}

static WN_API int32_t ms_fclose(wn_ms_file *f)
{
    f = ms_file_of(f);
    if (!f)
        return -1;
    if (f >= g_std_files && f < g_std_files + 3)
        return 0;                 /* std shells are never closed */
    if (f->owned)
        close(f->fd);
    free(f);
    return 0;
}

static WN_API int64_t ms_fread(void *buf, uint64_t sz, uint64_t n, wn_ms_file *f)
{
    if (!f)
        return 0;
    uint64_t total = sz * n;
    size_t got = 0;
    while (got < total) {
        ssize_t r = read(f->fd, (char *)buf + got, (size_t)(total - got));
        if (r <= 0) {
            if (r == 0)
                f->eof = 1;
            break;
        }
        got += (size_t)r;
    }
    return (int64_t)(sz ? got / (size_t)sz : 0);
}

static WN_API int64_t ms_fwrite(const void *buf, uint64_t sz, uint64_t n, wn_ms_file *f)
{
    if (!f)
        return 0;
    uint64_t total = sz * n;
    size_t put = 0;
    while (put < total) {
        ssize_t w = write(f->fd, (const char *)buf + put, (size_t)(total - put));
        if (w <= 0)
            break;
        put += (size_t)w;
    }
    return (int64_t)(sz ? put / (size_t)sz : 0);
}

static WN_API int32_t ms_fseek(wn_ms_file *f, int64_t off, int32_t whence)
{
    if (!f)
        return -1;
    return lseek(f->fd, off, whence == 0 ? SEEK_SET : whence == 1 ? SEEK_CUR : SEEK_END) < 0 ? -1 : 0;
}

static WN_API int64_t ms_ftell(wn_ms_file *f)
{
    if (!f)
        return -1;
    return lseek(f->fd, 0, SEEK_CUR);
}

static WN_API int32_t ms_feof(wn_ms_file *f)
{
    f = ms_file_of(f);
    return f ? f->eof : 0;
}

static WN_API int32_t ms_remove(const char *path)
{
    char host[2100];
    if (wn_path_resolve_ci(path, host, sizeof host) != 0)
        return -1;
    return unlink(host) == 0 ? 0 : -1;
}

/* --- misc -------------------------------------------------------------------------------------- */

static WN_API int64_t ms_time(int64_t *t)
{
    int64_t now = (int64_t)time(NULL);
    if (t)
        *t = now;
    return now;
}

static WN_API int64_t ms_clock(void)
{
    return (int64_t)(clock() * 1000000 / CLOCKS_PER_SEC);
}

static uint32_t g_seed = 1;

static WN_API void ms_srand(uint32_t s) { g_seed = s ? s : 1; }

static WN_API int32_t ms_rand(void)
{
    g_seed = g_seed * 1103515245 + 12345;
    return (int32_t)((g_seed >> 16) & 0x7FFF);
}

static WN_API char *ms_getenv(const char *name)
{
    for (char **e = g_proc.env_utf8; e && *e; e++) {
        const char *eq = strchr(*e, '=');
        if (eq && (size_t)(eq - *e) == strlen(name) &&
            !strncasecmp(*e, name, strlen(name)))
            return *e + strlen(name) + 1;
    }
    return NULL;
}

/* --- export table -------------------------------------------------------------------------------- */

const wn_export_entry wn_msvcrt_exports[] = {
    { "__initenv", &g_initenv_ptr },
    { "___lc_codepage_func", ms___lc_codepage_func },
    { "___mb_cur_max_func", ms___mb_cur_max_func },
    { "__C_specific_handler", ms___C_specific_handler },
    { "__getmainargs", ms___getmainargs },
    { "__iob_func", ms___iob_func },
    { "__set_app_type", ms___set_app_type },
    { "__setusermatherr", ms___setusermatherr },
    { "_amsg_exit", ms__amsg_exit },
    { "_cexit", ms__cexit },
    { "_commode", &g_commode },
    { "_control87", ms__control87 },
    { "_controlfp", ms__controlfp },
    { "_errno", ms__errno },
    { "_exit", ms__exit },
    { "_fmode", &g_fmode },
    { "_fpreset", ms__fpreset },
    { "_initenv", &g_initenv_ptr },
    { "_iob", g_std_files },
    { "_initterm", ms__initterm },
    { "_initterm_e", ms__initterm_e },
    { "_lock", ms__lock },
    { "_snprintf", ms_snprintf },
    { "_strdup", ms_strdup },
    { "_stricmp", ms_stricmp },
    { "_strnicmp", ms_strnicmp },
    { "_unlock", ms__unlock },
    { "_vsnprintf", ms_vsnprintf },
    { "abort", ms_abort },
    { "abs", (void *)ms_abs },
    { "atexit", ms_atexit },
    { "atof", ms_atof },
    { "atoi", ms_atoi },
    { "atol", ms_atol },
    { "atoll", ms_atoll },
    { "calloc", ms_calloc },
    { "clock", ms_clock },
    { "exit", ms_exit },
    { "fabs", ms_fabs },
    { "fclose", ms_fclose },
    { "feof", ms_feof },
    { "fflush", ms_fflush },
    { "fopen", ms_fopen },
    { "fprintf", ms_fprintf },
    { "fputc", ms_fputc },
    { "fputs", ms_fputs },
    { "fread", ms_fread },
    { "free", ms_free },
    { "fwrite", ms_fwrite },
    { "ferror", ms_ferror },
    { "fseek", ms_fseek },
    { "ftell", ms_ftell },
    { "getenv", ms_getenv },
    { "localeconv", ms_localeconv },
    { "malloc", ms_malloc },
    { "memcmp", ms_memcmp },
    { "memcpy", ms_memcpy },
    { "memmove", ms_memmove },
    { "memset", ms_memset },
    { "printf", ms_printf },
    { "putchar", ms_putchar },
    { "puts", ms_puts },
    { "rand", ms_rand },
    { "realloc", ms_realloc },
    { "remove", ms_remove },
    { "setvbuf", ms_setvbuf },
    { "signal", ms_signal },
    { "snprintf", ms_snprintf },
    { "sprintf", ms_sprintf },
    { "srand", ms_srand },
    { "strcat", ms_strcat },
    { "strchr", ms_strchr },
    { "strcmp", ms_strcmp },
    { "strcpy", ms_strcpy },
    { "strdup", ms_strdup },
    { "strerror", ms_strerror },
    { "stricmp", ms_stricmp },
    { "strlen", ms_strlen },
    { "strlwr", ms_strlwr },
    { "strncmp", ms_strncmp },
    { "strncpy", ms_strncpy },
    { "strnicmp", ms_strnicmp },
    { "strrchr", ms_strrchr },
    { "strstr", ms_strstr },
    { "strtod", ms_strtod },
    { "strtol", ms_strtol },
    { "strtoul", ms_strtoul },
    { "wcslen", ms_wcslen },
    { "strupr", ms_strupr },
    { "time", ms_time },
    { "vfprintf", ms_vfprintf },
    { "vprintf", ms_vprintf },
    { "vsnprintf", ms_vsnprintf },
    { "vsprintf", ms_vsprintf },
    { NULL, NULL },
};
