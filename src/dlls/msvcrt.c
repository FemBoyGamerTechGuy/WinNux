/* msvcrt.c — builtin msvcrt.dll / ucrtbase.dll subset.
 *
 * The printf engine is written in-tree (no libc varargs pass-through: the
 * MS-ABI va_list is decoded with __builtin_ms_va_list, each argument is
 * extracted, then formatted with host snprintf — allowed: libc).
 */
#include "wn_dll.h"
#include <execinfo.h>
#include <dlfcn.h>
#include "wn_types.h"
#include "wn_process.h"
#include "wn_log.h"
#include "wn_util.h"
#include "wn_path.h"
#include "wn_format.h"
#include <fcntl.h>

#include <ctype.h>
#include <wctype.h>
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
/* MSVC struct _iobuf: 48 bytes on x64, 32 on i386 (8 fields x 4). Guest
 * CRTs compute stdout as __iob_func() + N * sizeof(FILE) — a wrong stride
 * lands mid-entry, fails the magic check, and every fwrite silently
 * no-ops (32-bit printf output vanished this way). */
#if defined(__x86_64__)
#define WN_MS_FILE_SIZE  48
#else
#define WN_MS_FILE_SIZE  32
#endif

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

static WN_CRTAPI wn_ms_file *ms___iob_func(void)
{
    return g_std_files;
}

static WN_CRTAPI wn_ms_file *ms___p___iob(void)
{
    return g_std_files;   /* __p__iob returns the ARRAY address, like __iob_func */
}

/* --- errno bridge ---------------------------------------------------------------- */

static __thread int g_ms_errno;

static WN_CRTAPI int *ms__errno(void)
{
    return &g_ms_errno;
}

/* --- alloc (map to host malloc; guest owns) ---------------------------------------- */

static WN_CRTAPI void *ms_malloc(wn_abiword n) { return malloc((size_t)n); }
static WN_CRTAPI void *ms_calloc(wn_abiword n, wn_abiword sz) { return calloc((size_t)n, (size_t)sz); }
static WN_CRTAPI void *ms_realloc(void *p, wn_abiword n) { return realloc(p, (size_t)n); }
static WN_CRTAPI void ms_free(void *p) { free(p); }

/* --- strings (forward to libc; ms_abi wrappers) ------------------------------------- */

static WN_CRTAPI uint64_t ms_memcpy(void *d, const void *s, wn_abiword n)
{
    return (uint64_t)(uintptr_t)memcpy(d, s, (size_t)n);
}
static WN_CRTAPI uint64_t ms_memset(void *d, int32_t c, wn_abiword n)
{
    return (uint64_t)(uintptr_t)memset(d, c, (size_t)n);
}
static WN_CRTAPI int32_t ms_memcmp(const void *a, const void *b, wn_abiword n)
{
    return memcmp(a, b, (size_t)n) > 0 ? 1 : memcmp(a, b, (size_t)n) < 0 ? -1 : 0;
}
static WN_CRTAPI uint64_t ms_memmove(void *d, const void *s, wn_abiword n)
{
    return (uint64_t)(uintptr_t)memmove(d, s, (size_t)n);
}
static WN_CRTAPI int64_t ms_strlen(const char *s) { return (int64_t)strlen(s); }
static WN_CRTAPI int32_t ms_strcmp(const char *a, const char *b) { return strcmp(a, b); }
static WN_CRTAPI int32_t ms_strncmp(const char *a, const char *b, wn_abiword n)
{
    int r = strncmp(a, b, (size_t)n);
    return (r > 0) - (r < 0);
}
static WN_CRTAPI char *ms_strcpy(char *d, const char *s) { return strcpy(d, s); }
static WN_CRTAPI char *ms_strncpy(char *d, const char *s, wn_abiword n)
{
    return strncpy(d, s, (size_t)n);
}
static WN_CRTAPI char *ms_strcat(char *d, const char *s) { return strcat(d, s); }
/* CRT contract: const-in, mutable-out (mirrors MSVC declarations).
 * Explicit casts are deliberate: GCC 15's builtins const-propagate the first
 * argument's qualifier into the return type, tripping -Werror=discarded-qualifiers. */
static WN_CRTAPI char *ms_strchr(const char *s, int32_t c) { return (char *)strchr(s, c); }
static WN_CRTAPI char *ms_strrchr(const char *s, int32_t c) { return (char *)strrchr(s, c); }
static WN_CRTAPI char *ms_strstr(const char *h, const char *n) { return (char *)strstr(h, n); }
static WN_CRTAPI char *ms_strupr(char *s)
{
    for (char *p = s; *p; p++)
        *p = (char)toupper((unsigned char)*p);
    return s;
}
static WN_CRTAPI char *ms_strlwr(char *s)
{
    for (char *p = s; *p; p++)
        *p = (char)tolower((unsigned char)*p);
    return s;
}
static WN_CRTAPI int32_t ms_stricmp(const char *a, const char *b)
{
    return strcasecmp(a, b) > 0 ? 1 : strcasecmp(a, b) < 0 ? -1 : 0;
}
static WN_CRTAPI int32_t ms_strnicmp(const char *a, const char *b, wn_abiword n)
{
    return strncasecmp(a, b, (size_t)n) > 0 ? 1 : strncasecmp(a, b, (size_t)n) < 0 ? -1 : 0;
}
static WN_CRTAPI char *ms_strdup(const char *s) { return strdup(s); }
static WN_CRTAPI int64_t ms_wcslen(const uint16_t *s)
{
    if (!s)
        return 0;
    int64_t n = 0;
    while (s[n])
        n++;
    return n;
}

/* MSVC C++ exception throw: without full EH unwinding (scope tables,
 * catch matching — documented TODO), the honest behavior is a clean,
 * LOUD process abort instead of returning into a half-unwound guest. */
static WN_API void ms_CxxThrowException(const void *object, const void *info)
{
    (void)info;
    uint32_t first = 0;
    if (object) {
        memcpy(&first, object, 4);
        wn_log(WN_LOG_ERR, "msvcrt: _CxxThrowException: unhandled C++ "
               "exception (object %p, first dword 0x%x) — exiting",
               object, first);
    } else {
        wn_log(WN_LOG_ERR, "msvcrt: _CxxThrowException: unhandled C++ "
               "exception — exiting");
    }
    wn_process_exit(1);
}

/* --- wchar CRT family (cdecl; 7-Zip i386 and every unicode app needs these) */
static WN_CRTAPI int32_t ms_wcscmp(const uint16_t *a, const uint16_t *b)
{
    if (!a || !b)
        return (a ? 1 : 0) - (b ? 1 : 0);
    while (*a && *a == *b) { a++; b++; }
    return (int32_t)*a - (int32_t)*b;
}

static WN_CRTAPI int32_t ms_wcsncmp(const uint16_t *a, const uint16_t *b, wn_abiword n)
{
    if (!a || !b || n == 0)
        return (a ? 1 : 0) - (b ? 1 : 0);
    size_t i = 0;
    while (i + 1 < (size_t)n && a[i] && a[i] == b[i])
        i++;
    return (int32_t)a[i] - (int32_t)b[i];
}

static WN_CRTAPI int32_t ms_wcsicmp(const uint16_t *a, const uint16_t *b)
{
    if (!a || !b)
        return (a ? 1 : 0) - (b ? 1 : 0);
    while (*a && towlower(*a) == towlower(*b)) { a++; b++; }
    return (int32_t)towlower(*a) - (int32_t)towlower(*b);
}

static WN_CRTAPI int32_t ms_wcsnicmp(const uint16_t *a, const uint16_t *b, wn_abiword n)
{
    if (!a || !b || n == 0)
        return (a ? 1 : 0) - (b ? 1 : 0);
    size_t i = 0;
    while (i + 1 < (size_t)n && a[i] && towlower(a[i]) == towlower(b[i]))
        i++;
    return (int32_t)towlower(a[i]) - (int32_t)towlower(b[i]);
}

static WN_CRTAPI uint16_t *ms_wcschr(const uint16_t *s, uint16_t c)
{
    if (!s)
        return NULL;
    while (*s) {
        if (*s == c)
            return (uint16_t *)s;
        s++;
    }
    return c == 0 ? (uint16_t *)s : NULL;
}

static WN_CRTAPI uint16_t *ms_wcsrchr(const uint16_t *s, uint16_t c)
{
    if (!s)
        return NULL;
    const uint16_t *last = NULL;
    while (*s) {
        if (*s == c)
            last = s;
        s++;
    }
    if (c == 0)
        return (uint16_t *)s;
    return (uint16_t *)last;
}

static WN_CRTAPI uint16_t *ms_wcscpy(uint16_t *d, const uint16_t *s)
{
    if (!d || !s)
        return d;
    uint16_t *o = d;
    while ((*d++ = *s++) != 0)
        ;
    return o;
}

static WN_CRTAPI uint16_t *ms_wcsncpy(uint16_t *d, const uint16_t *s, wn_abiword n)
{
    if (!d || !s || n == 0)
        return d;
    size_t i = 0;
    while (i < (size_t)n && s[i]) {
        d[i] = s[i];
        i++;
    }
    while (i < (size_t)n)
        d[i++] = 0;
    return d;
}

static WN_CRTAPI uint16_t *ms_wcscat(uint16_t *d, const uint16_t *s)
{
    if (!d || !s)
        return d;
    uint16_t *o = d;
    while (*d)
        d++;
    while ((*d++ = *s++) != 0)
        ;
    return o;
}

static WN_CRTAPI uint16_t *ms_wcsncat(uint16_t *d, const uint16_t *s, wn_abiword n)
{
    if (!d || !s || n == 0)
        return d;
    uint16_t *o = d;
    while (*d)
        d++;
    size_t i = 0;
    while (i < (size_t)n && s[i])
        d[i] = s[i], i++, d++;
    *d = 0;
    return o;
}

static WN_CRTAPI uint16_t *ms_wcsstr(const uint16_t *h, const uint16_t *n)
{
    if (!h || !n)
        return NULL;
    if (!*n)
        return (uint16_t *)h;
    for (const uint16_t *p = h; *p; p++) {
        const uint16_t *a = p, *b = n;
        while (*a && *b && *a == *b) { a++; b++; }
        if (!*b)
            return (uint16_t *)p;
    }
    return NULL;
}

static WN_CRTAPI uint16_t *ms_wcspbrk(const uint16_t *s, const uint16_t *set)
{
    if (!s || !set)
        return NULL;
    for (const uint16_t *p = s; *p; p++)
        for (const uint16_t *q = set; *q; q++)
            if (*p == *q)
                return (uint16_t *)p;
    return NULL;
}

static WN_CRTAPI wn_abiword ms_wcsspn(const uint16_t *s, const uint16_t *set)
{
    if (!s || !set)
        return 0;
    wn_abiword n = 0;
    while (s[n]) {
        int found = 0;
        for (const uint16_t *q = set; *q; q++)
            if (s[n] == *q) { found = 1; break; }
        if (!found)
            break;
        n++;
    }
    return n;
}

static WN_CRTAPI wn_abiword ms_wcscspn(const uint16_t *s, const uint16_t *set)
{
    if (!s || !set)
        return s ? ms_wcslen(s) : 0;
    wn_abiword n = 0;
    while (s[n]) {
        for (const uint16_t *q = set; *q; q++)
            if (s[n] == *q)
                return n;
        n++;
    }
    return n;
}

static WN_CRTAPI uint16_t *ms_wcstok(uint16_t *s, const uint16_t *delim, uint16_t **ctx)
{
    if (ctx)
        *ctx = NULL;   /* simplified: no continuation state (rarely used) */
    if (!s || !delim)
        return NULL;
    /* skip leading delims */
    uint16_t *p = s;
    while (*p && ms_wcschr(delim, *p))
        p++;
    if (!*p)
        return NULL;
    uint16_t *tok = p;
    while (*p && !ms_wcschr(delim, *p))
        p++;
    if (*p)
        *p++ = 0;
    return tok;
}

static WN_CRTAPI uint16_t *ms_wmemcpy(uint16_t *d, const uint16_t *s, wn_abiword n)
{
    return (uint16_t *)memcpy(d, s, (size_t)n * 2);
}

static WN_CRTAPI uint16_t *ms_wmemset(uint16_t *d, uint16_t c, wn_abiword n)
{
    for (wn_abiword i = 0; i < n; i++)
        d[i] = c;
    return d;
}

static WN_CRTAPI int32_t ms_setvbuf(wn_ms_file *f, char *buf, int32_t mode, wn_abiword size)
{
    (void)buf;
    (void)mode;
    (void)size;
    f = ms_file_of(f);
    return f ? 0 : -1;   /* we are unbuffered at the FILE level already */
}

static WN_CRTAPI int32_t ms_ferror(wn_ms_file *f)
{
    f = ms_file_of(f);
    return f ? 0 : 1;
}

static WN_CRTAPI char *ms_strerror(int32_t e)
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

static WN_CRTAPI int32_t ms_atoi(const char *s) { return (int32_t)atoi(s); }
static WN_CRTAPI int64_t ms_atol(const char *s) { return atol(s); }
static WN_CRTAPI int64_t ms_atoll(const char *s) { return atoll(s); }
static WN_CRTAPI double ms_atof(const char *s) { return atof(s); }
static WN_CRTAPI int64_t ms_strtol(const char *s, char **e, int32_t b)
{
    return strtol(s, e, b);
}
static WN_CRTAPI uint64_t ms_strtoul(const char *s, char **e, int32_t b)
{
    return strtoul(s, e, b);
}
static WN_CRTAPI double ms_strtod(const char *s, char **e) { return strtod(s, e); }
static WN_CRTAPI int64_t ms_abs(wn_abiword_s v) { return v < 0 ? -v : v; }
static WN_CRTAPI double ms_fabs(double v) { return fabs(v); }

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

static WN_CRTAPI void ms_exit(int32_t code)
{
    wn_process_exit(code);
}

static WN_CRTAPI void ms__exit(int32_t code)
{
    _exit(code);
}

static WN_CRTAPI void ms_abort(void)
{
    wn_log(WN_LOG_ERR, "msvcrt: abort() called by guest");
    exit(3);
}

static WN_CRTAPI int32_t ms_atexit(void (*fn)(void))
{
    return wn_process_atexit(fn) ? 0 : -1;
}

/* CRT _onexit: returns the function pointer on success, NULL when the
 * table is full (MSVC contract); the function runs at process exit. */
static WN_CRTAPI void *ms__onexit(void (*fn)(void))
{
    if (!fn)
        return NULL;
    return wn_process_atexit(fn) ? (void *)(uintptr_t)fn : NULL;
}

static WN_CRTAPI void ms__cexit(void)
{
    for (int i = g_proc.atexit_count - 1; i >= 0; i--)
        g_proc.atexit_fns[i]();
}

/* --- CRT startup hooks ----------------------------------------------------------------- */

static WN_CRTAPI void ms___set_app_type(int32_t t)
{
    (void)t;
}

static WN_CRTAPI void ms__amsg_exit(int32_t code)
{
    wn_log(WN_LOG_ERR, "msvcrt: _amsg_exit(%d) — CRT runtime error", code);
    exit(255);
}

typedef WN_CRTAPI void (*wn_ms_voidfn)(void);
typedef WN_CRTAPI int32_t (*wn_ms_intfn)(void);

static WN_CRTAPI void ms__initterm(wn_ms_voidfn *start, wn_ms_voidfn *end)
{
    for (wn_ms_voidfn *p = start; p < end; p++)
        if (*p)
            (*p)();
}

static WN_CRTAPI int32_t ms__initterm_e(wn_ms_intfn *start, wn_ms_intfn *end)
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

static WN_CRTAPI void ms__lock(int32_t n) { (void)n; }
static WN_CRTAPI void ms__unlock(int32_t n) { (void)n; }

static WN_CRTAPI void ms___setusermatherr(void *h) { (void)h; }

static WN_CRTAPI uint32_t ms__controlfp(uint32_t a, uint32_t b)
{
    (void)a;
    (void)b;
    return 0x8001F;    /* default CW */
}

static WN_CRTAPI uint32_t ms__control87(uint32_t a, uint32_t b)
{
    return ms__controlfp(a, b);
}

static WN_CRTAPI void ms__fpreset(void) {}

static int g_mb_cur_max = 1;
static uint32_t g_lc_codepage = 1252;

static WN_CRTAPI uint32_t ms___lc_codepage_func(void) { return g_lc_codepage; }
static WN_CRTAPI uint32_t ms___mb_cur_max_func(void) { return (uint32_t)g_mb_cur_max; }

/* The __p__* family: mingw-built 32-bit CRT startup calls these to get the
 * ADDRESS of a CRT global (cdecl, return void*). Without them every i686
 * mingw exe dies on startup. */
static WN_CRTAPI int   *ms___p___mb_cur_max(void) { return &g_mb_cur_max; }
static WN_CRTAPI int   *ms___p__commode(void)     { return &g_commode; }
static WN_CRTAPI int   *ms___p__fmode(void)       { return &g_fmode; }
static WN_CRTAPI char ***ms___p___initenv(void)   { return &g_initenv_ptr; }
static WN_CRTAPI uint32_t *ms___lc_codepage(void) { return &g_lc_codepage; }

/* _acmdln/_wcmdln: the CRT's view of the command line. mingw's WinMain
 * startup reads *__p__acmdln() — a NULL deref there killed every
 * -mwindows i386 build (gui32 smoke test). Backed by g_proc cmdline. */
static char *g_acmdln;
static uint16_t *g_wcmdln;

static void ms_cmdln_init(void)
{
    if (!g_acmdln)
        g_acmdln = g_proc.cmdline_utf8 ? g_proc.cmdline_utf8 : (char *)"";
    if (!g_wcmdln)
        g_wcmdln = g_proc.cmdline_utf16 ? g_proc.cmdline_utf16
                                        : (uint16_t *)L"";
}

static WN_CRTAPI char **ms___p__acmdln(void)
{
    ms_cmdln_init();
    return &g_acmdln;
}

static WN_CRTAPI uint16_t **ms___p__wcmdln(void)
{
    ms_cmdln_init();
    return &g_wcmdln;
}

/* Multi-byte lead/trail tests: C locale (CP1252/ASCII) has no multi-byte
 * sequences — every byte is a single-byte character, so _ismbblead /
 * _ismbbtrail always return 0 (mingw CRT calls these while parsing the
 * command line). _ismbblead must NOT stay a stub: pre-WinMain code paths
 * call it with real chars. */
static WN_CRTAPI int32_t ms__ismbblead(uint32_t c) { (void)c; return 0; }
static WN_CRTAPI int32_t ms__ismbbtrail(uint32_t c) { (void)c; return 0; }
static WN_CRTAPI int32_t ms__ismbcspace(uint32_t c) { return (c == ' ') ? 1 : 0; }
static WN_CRTAPI int32_t ms__setmbcp(int32_t cp)
{
    return (cp == 0 || cp == 1252) ? 0 : -1;  /* _MB_CP_ANSI / SBCS ok */
}

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

static WN_CRTAPI void *ms_localeconv(void)
{
    return &g_lconv;
}

static WN_CRTAPI void *ms___C_specific_handler(void *rec, void *frame, void *ctx,
                                            void *disp)
{
    (void)rec; (void)frame; (void)ctx; (void)disp;
    wn_log(WN_LOG_WARN, "msvcrt: __C_specific_handler invoked (SEH scope "
           "search unsupported; passing on)");
    return 0;   /* ExceptionContinueSearch */
}

static WN_CRTAPI void *ms_signal(int32_t sig, void *fn)
{
    wn_log(WN_LOG_DEBUG, "msvcrt: signal(%d) registered (no delivery yet)", sig);
    (void)fn;
    return 0;
}

/* --- __getmainargs ------------------------------------------------------------------------ */

static int g_argc;
static char **g_argv;
static char **g_envp;

static WN_CRTAPI int32_t ms___getmainargs(int32_t *argc, char ***argv, char ***envp,
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

/* Public bounded-buffer emitter (declared in wn_format.h): writes at most
 * left-1 bytes, always NUL-terminates, stops consuming once full. */
void wn_emit_to_buf(void *ctx, const char *data, size_t n)
{
    struct wn_emit_buf *b = ctx;
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
 * into that area - exactly like the MS CRT's va_list.
 *
 * i386: MSVC cdecl varargs are 4-byte slots (ints/pointers) with doubles
 * 8-byte-aligned (4 bytes skipped when needed). Same walk, different slot
 * width - selected by pointer size at compile time. */
#if defined(__x86_64__)
#define MS_VA_SLOT 8
#else
#define MS_VA_SLOT 4
#endif

static uint64_t ms_next(void **app)
{
    char *p = *(char **)app;
    uint64_t v = 0;
    memcpy(&v, p, MS_VA_SLOT);
    *(char **)app = p + MS_VA_SLOT;
    return v;
}

static double ms_next_double(void **app)
{
#if defined(__x86_64__)
    uint64_t b = ms_next(app);
    double d;
    memcpy(&d, &b, 8);
    return d;
#else
    /* align to 8 first (i386 varargs leave doubles 8-byte aligned; a 4-only
     * aligned position means one 4-byte pad precedes) */
    char *p = *(char **)app;
    if ((uintptr_t)p & 4)
        p += 4;
    double d;
    memcpy(&d, p, 8);
    *(char **)app = p + 8;
    return d;
#endif
}

/* Core formatter (shared with user32 wsprintf — see wn_format.h).
 * Returns 0 on success (like vfprintf) or -1. */
int wn_vformat(wn_emit_fn emit, void *ctx, const char *fmt, char **ap,
               int wide)
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
        case 'c':
        case 'C': {
            int c = (int)ms_next((void **)ap);
            int this_wide = (conv == 'c') ? wide : !wide;
            if (lng == 1) this_wide = 1;        /* %lc always wide   */
            else if (lng == 4) this_wide = 0;   /* %hc always narrow */
            if (this_wide) {
                uint16_t wc[2] = { (uint16_t)c, 0 };
                char *u8 = wn_utf16_to_utf8(wc, 1);
                if (u8) {
                    emit(ctx, u8, strlen(u8));
                    free(u8);
                }
            } else {
                char cc = (char)c;
                emit(ctx, &cc, 1);
            }
            continue;
        }
        case 's':
        case 'S': {
            /* Direction: %s follows the wide flag, %S is flipped
             * (printf-A: %s narrow / %S wide; W-side: %s wide / %S narrow).
             * An explicit l/h prefix overrides either way. */
            int this_wide = (conv == 's') ? wide : !wide;
            if (lng == 1) this_wide = 1;        /* %ls always wide   */
            else if (lng == 4) this_wide = 0;   /* %hs always narrow */
            char *owned = NULL;
            const char *s;
            if (this_wide) {
                const uint16_t *w =
                    (const uint16_t *)(uintptr_t)ms_next((void **)ap);
                if (!w) {
                    s = "(null)";
                } else {
                    size_t l16 = 0;
                    while (w[l16]) l16++;
                    owned = wn_utf16_to_utf8(w, l16);
                    s = owned ? owned : "";
                }
            } else {
                s = (const char *)(uintptr_t)ms_next((void **)ap);
                if (!s)
                    s = "(null)";
            }
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
            free(owned);
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

/* MS-va_list note (2026-10, found via putty/t14 debugging):
 * SysV <stdarg.h> va_list is an ARRAY type: passing it to another function
 * passes its ADDRESS (by reference), so `ms_vsnprintf(..., va_list ap)` +
 * `(char*)ap` read the va_list POINTER ITSELF as the first argument - every
 * sprintf/snprintf with %s produced garbage. GCC lowers va_start correctly
 * only when the walk stays inside one function. The wn_ms_va/WN_VA_START
 * machinery for this model now lives in wn_format.h (shared with the
 * user32 wsprintf family). */
static int64_t vprintf_impl(const char *fmt, char *argp)
{
    struct emit_fd e = { 1, isatty(1), 0 };
    wn_vformat(emit_to_fd, &e, fmt, &argp, 0);
    return (int64_t)e.total;
}

static int64_t vfprintf_impl(int fd, const char *fmt, char *argp)
{
    struct emit_fd e = { fd, isatty(fd), 0 };
    wn_vformat(emit_to_fd, &e, fmt, &argp, 0);
    return (int64_t)e.total;
}

static int64_t vsprintf_impl(char *dst, const char *fmt, char *argp)
{
    struct wn_emit_buf b = { dst, (size_t)-1 };
    wn_vformat(wn_emit_to_buf, &b, fmt, &argp, 0);
    return (int64_t)strlen(dst);
}

static int64_t vsnprintf_impl(char *dst, uint64_t cap, const char *fmt,
                              char *argp)
{
    if (!dst || cap == 0) {
        /* measure only: count bytes. */
        size_t total = 0;
        wn_vformat(emit_count, &total, fmt, &argp, 0);
        return (int64_t)total;
    }
    struct wn_emit_buf b = { dst, (size_t)cap };
    wn_vformat(wn_emit_to_buf, &b, fmt, &argp, 0);
    return (int64_t)strlen(dst);
}

/* wsprintf-family convenience (user32): bounded, NUL-terminated. */
int64_t wn_wsprintf_buf(char *dst, size_t cap, const char *fmt, char *ap,
                        int wide)
{
    if (!dst || cap == 0 || !fmt)
        return -1;
    struct wn_emit_buf b = { dst, cap };
    char *cur = ap;
    wn_vformat(wn_emit_to_buf, &b, fmt, &cur, wide);
    return (int64_t)strlen(dst);
}

static WN_CRTAPI int64_t ms_printf(const char *fmt, ...)
{
    wn_ms_va ap;
    WN_VA_START(ap, fmt);
    int64_t r = vprintf_impl(fmt, (char *)ap);
    WN_VA_END(ap);
    return r;
}

/* v-family: Windows va_list is char* into the caller's spill area. */
static WN_CRTAPI int64_t ms_vprintf(const char *fmt, char *ap)
{
    return vprintf_impl(fmt, ap);
}

static WN_CRTAPI int64_t ms_fprintf(wn_ms_file *f, const char *fmt, ...)
{
    f = ms_file_of(f);
    if (!f) {
        wn_log(WN_LOG_ERR, "msvcrt: fprintf(bad FILE*) %p", (void *)f);
        return -1;
    }
    wn_ms_va ap;
    WN_VA_START(ap, fmt);
    int64_t r = vfprintf_impl(f->fd, fmt, (char *)ap);
    WN_VA_END(ap);
    return r;
}

static WN_CRTAPI int64_t ms_vfprintf(wn_ms_file *f, const char *fmt, char *ap)
{
    f = ms_file_of(f);
    if (!f) {
        wn_log(WN_LOG_ERR, "msvcrt: vfprintf(bad FILE*) %p", (void *)f);
        return -1;
    }
    return vfprintf_impl(f->fd, fmt, ap);
}

static WN_CRTAPI int64_t ms_sprintf(char *dst, const char *fmt, ...)
{
    wn_ms_va ap;
    WN_VA_START(ap, fmt);
    int64_t r = vsprintf_impl(dst, fmt, (char *)ap);
    WN_VA_END(ap);
    return r;
}

static WN_CRTAPI int64_t ms_vsprintf(char *dst, const char *fmt, char *ap)
{
    return vsprintf_impl(dst, fmt, ap);
}

static WN_CRTAPI int64_t ms_snprintf(char *dst, wn_abiword cap, const char *fmt, ...)
{
    wn_ms_va ap;
    WN_VA_START(ap, fmt);
    int64_t r = vsnprintf_impl(dst, cap, fmt, (char *)ap);
    WN_VA_END(ap);
    return r;
}

static WN_CRTAPI int64_t ms_vsnprintf(char *dst, wn_abiword cap, const char *fmt,
                                   char *ap)
{
    return vsnprintf_impl(dst, cap, fmt, ap);
}

static WN_CRTAPI int64_t ms_puts(const char *s)
{
    struct emit_fd e = { 1, isatty(1), 0 };
    if (s)
        emit_to_fd(&e, s, strlen(s));
    emit_to_fd(&e, "\n", 1);
    return (s || 1) ? 0 : -1;
}

static WN_CRTAPI int32_t ms_fputc(int32_t c, wn_ms_file *f)
{
    f = ms_file_of(f);
    if (!f)
        return -1;
    char cc = (char)c;
    ssize_t w = write(f->fd, &cc, 1);
    return w == 1 ? c : -1;
}

static WN_CRTAPI int32_t ms_putchar(int32_t c)
{
    return ms_fputc(c, &g_std_files[1]);
}

static WN_CRTAPI int64_t ms_fputs(const char *s, wn_ms_file *f)
{
    f = ms_file_of(f);
    if (!s || !f)
        return -1;
    ssize_t w = write(f->fd, s, strlen(s));
    return w >= 0 ? 0 : -1;
}

static WN_CRTAPI int32_t ms_fflush(wn_ms_file *f)
{
    if (!f) {
        fflush(NULL);
        return 0;
    }
    return 0;
}

/* --- stdio file layer ------------------------------------------------------------------------ */

static WN_CRTAPI wn_ms_file *ms_fopen(const char *path, const char *mode)
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

/* _wfopen: wide path -> same engine as fopen. */
static WN_CRTAPI wn_ms_file *ms__wfopen(const uint16_t *wpath, const char *mode)
{
    if (!wpath || !mode)
        return NULL;
    size_t l = 0;
    while (wpath[l])
        l++;
    char *path = wn_utf16_to_utf8(wpath, l);
    if (!path)
        return NULL;
    wn_ms_file *f = ms_fopen(path, mode);
    free(path);
    return f;
}

/* _fileno: FILE* -> host fd (std shells have fixed 0/1/2). */
static WN_CRTAPI int32_t ms__fileno(wn_ms_file *f)
{
    f = ms_file_of(f);
    if (!f)
        return -1;
    return f->fd;
}

/* _isatty: real. */
static WN_CRTAPI int32_t ms__isatty(int32_t fd)
{
    return isatty(fd);
}

/* _access / _waccess: existence + mode bits via the mapped path. */
static WN_CRTAPI int32_t ms__access(const char *path, int32_t mode)
{
    if (!path)
        return -1;
    char host[2100];
    if (wn_path_resolve_ci(path, host, sizeof host) != 0) {
        if (wn_path_win_to_host(path, host, sizeof host) != 0)
            return -1;
    }
    if (access(host, mode & 7) != 0)
        return -1;
    return 0;
}

static WN_CRTAPI int32_t ms__waccess(const uint16_t *wpath, int32_t mode)
{
    if (!wpath)
        return -1;
    size_t l = 0;
    while (wpath[l])
        l++;
    char *path = wn_utf16_to_utf8(wpath, l);
    if (!path)
        return -1;
    int32_t r = ms__access(path, mode);
    free(path);
    return r;
}


/* fgets: line read straight off the fd (FILE shells are unbuffered). */
static WN_CRTAPI char *ms_fgets(char *buf, int32_t n, wn_ms_file *f)
{
    f = ms_file_of(f);
    if (!f || !buf || n <= 0)
        return NULL;
    size_t got = 0;
    while (got + 1 < (size_t)n) {
        char c;
        ssize_t r = read(f->fd, &c, 1);
        if (r != 1) {
            if (r == 0)
                f->eof = 1;
            if (got == 0)
                return NULL;
            break;
        }
        buf[got++] = c;
        if (c == '\n')
            break;
    }
    buf[got] = 0;
    return buf;
}

/* _setmode: TEXT/BINARY accepted (no translation performed - documented);
 * UTF modes rejected honestly. Returns the previous mode. */
static WN_CRTAPI int32_t ms__setmode(int32_t fd, int32_t mode)
{
    if (fd < 0 || fd > 2)
        return -1;
    if (mode != 0x4000 /*_O_TEXT*/ && mode != 0x8000 /*_O_BINARY*/)
        return -1;
    (void)mode;
    return 0x8000;   /* we are always binary */
}

static WN_CRTAPI int32_t ms_fclose(wn_ms_file *f)
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

static WN_CRTAPI int64_t ms_fread(void *buf, wn_abiword sz, wn_abiword n, wn_ms_file *f)
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

static WN_CRTAPI int64_t ms_fwrite(const void *buf, wn_abiword sz, wn_abiword n, wn_ms_file *f)
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

static WN_CRTAPI int32_t ms_fseek(wn_ms_file *f, int64_t off, int32_t whence)
{
    if (!f)
        return -1;
    return lseek(f->fd, off, whence == 0 ? SEEK_SET : whence == 1 ? SEEK_CUR : SEEK_END) < 0 ? -1 : 0;
}

static WN_CRTAPI int64_t ms_ftell(wn_ms_file *f)
{
    if (!f)
        return -1;
    return lseek(f->fd, 0, SEEK_CUR);
}

static WN_CRTAPI int32_t ms_feof(wn_ms_file *f)
{
    f = ms_file_of(f);
    return f ? f->eof : 0;
}

static WN_CRTAPI int32_t ms_remove(const char *path)
{
    char host[2100];
    if (wn_path_resolve_ci(path, host, sizeof host) != 0)
        return -1;
    return unlink(host) == 0 ? 0 : -1;
}

/* --- misc -------------------------------------------------------------------------------------- */

static WN_CRTAPI int64_t ms_time(int64_t *t)
{
    int64_t now = (int64_t)time(NULL);
    if (t)
        *t = now;
    return now;
}

static WN_CRTAPI int64_t ms_clock(void)
{
    return (int64_t)(clock() * 1000000 / CLOCKS_PER_SEC);
}

/* --- guest-shaped struct tm -----------------------------------------------------
 * MSVC's struct tm is 9 ints = 36 bytes on BOTH arches (glibc's has
 * tm_gmtoff/tm_zone); localtime/gmtime must fill the MSVC layout, not the
 * host one. Classic msvcrt.dll `localtime` takes a time_t-sized pointer:
 * 4 bytes on i386, 8 on x64 — read the guest word. */
struct wn_ms_tm {
    int32_t sec, min, hour, mday, mon, year, wday, yday, isdst;
};
_Static_assert(sizeof(struct wn_ms_tm) == 36, "MSVC struct tm ABI");

static __thread struct wn_ms_tm g_ms_tm;

static struct wn_ms_tm *ms_tm_fill(const struct tm *ht)
{
    if (!ht)
        return NULL;
    g_ms_tm.sec = (int32_t)ht->tm_sec;
    g_ms_tm.min = (int32_t)ht->tm_min;
    g_ms_tm.hour = (int32_t)ht->tm_hour;
    g_ms_tm.mday = (int32_t)ht->tm_mday;
    g_ms_tm.mon = (int32_t)ht->tm_mon;
    g_ms_tm.year = (int32_t)ht->tm_year;
    g_ms_tm.wday = (int32_t)ht->tm_wday;
    g_ms_tm.yday = (int32_t)ht->tm_yday;
    g_ms_tm.isdst = (int32_t)ht->tm_isdst;
    return &g_ms_tm;
}

static WN_CRTAPI struct wn_ms_tm *ms_localtime(const wn_abiword *tp)
{
    if (!tp)
        return NULL;
    time_t t = (time_t)(intptr_t)(wn_abiword_s)*tp;
    return ms_tm_fill(localtime(&t));
}

static WN_CRTAPI struct wn_ms_tm *ms__localtime32(const int32_t *tp)
{
    if (!tp)
        return NULL;
    time_t t = (time_t)*tp;
    return ms_tm_fill(localtime(&t));
}

static WN_CRTAPI struct wn_ms_tm *ms__localtime64(const int64_t *tp)
{
    if (!tp)
        return NULL;
    time_t t = (time_t)*tp;
    return ms_tm_fill(localtime(&t));
}

static WN_CRTAPI struct wn_ms_tm *ms_gmtime(const wn_abiword *tp)
{
    if (!tp)
        return NULL;
    time_t t = (time_t)(intptr_t)(wn_abiword_s)*tp;
    return ms_tm_fill(gmtime(&t));
}

/* --- case ops (ASCII, locale-free like the C locale default) -------------------- */
static WN_CRTAPI char *ms__strupr(char *s)
{
    if (!s)
        return s;
    for (char *p = s; *p; p++)
        if (*p >= 'a' && *p <= 'z')
            *p = (char)(*p - 'a' + 'A');
    return s;
}

static WN_CRTAPI char *ms__strlwr(char *s)
{
    if (!s)
        return s;
    for (char *p = s; *p; p++)
        if (*p >= 'A' && *p <= 'Z')
            *p = (char)(*p - 'A' + 'a');
    return s;
}

/* --- qsort ------------------------------------------------------------------------
 * In-tree heapsort: the comparison callback is GUEST code, so it must be
 * called through a WN_CRTAPI function pointer (cdecl on i386, ms_abi on
 * x64) — host libc qsort would call it SysV and smash x64 guests. */
static WN_CRTAPI void ms_qsort(void *base, wn_abiword n, wn_abiword sz,
                               WN_CRTAPI int32_t (*cmp)(const void *,
                                                        const void *))
{
    if (!base || n < 2 || sz == 0 || !cmp)
        return;
    unsigned char *a = base;
    /* max heap: element i -> children 2i+1, 2i+2 */
    wn_abiword start = n / 2;   /* signed math below; n < 2^31 in practice */
    for (wn_abiword i = start; i-- > 0;) {
        wn_abiword root = i;
        for (;;) {
            wn_abiword c = 2 * root + 1;
            if (c >= n)
                break;
            if (c + 1 < n && cmp(a + (c + 1) * sz, a + c * sz) > 0)
                c++;
            if (cmp(a + root * sz, a + c * sz) >= 0)
                break;
            for (wn_abiword b = 0; b < sz; b++) {
                unsigned char t = a[root * sz + b];
                a[root * sz + b] = a[c * sz + b];
                a[c * sz + b] = t;
            }
            root = c;
        }
    }
    for (wn_abiword end = n - 1; end > 0; end--) {
        for (wn_abiword b = 0; b < sz; b++) {
            unsigned char t = a[end * sz + b];
            a[end * sz + b] = a[b];
            a[b] = t;
        }
        wn_abiword root = 0;
        for (;;) {
            wn_abiword c = 2 * root + 1;
            if (c >= end)
                break;
            if (c + 1 < end && cmp(a + (c + 1) * sz, a + c * sz) > 0)
                c++;
            if (cmp(a + root * sz, a + c * sz) >= 0)
                break;
            for (wn_abiword b = 0; b < sz; b++) {
                unsigned char t = a[root * sz + b];
                a[root * sz + b] = a[c * sz + b];
                a[c * sz + b] = t;
            }
            root = c;
        }
    }
}

static uint32_t g_seed = 1;

static WN_CRTAPI void ms_srand(uint32_t s) { g_seed = s ? s : 1; }

static WN_CRTAPI int32_t ms_rand(void)
{
    g_seed = g_seed * 1103515245 + 12345;
    return (int32_t)((g_seed >> 16) & 0x7FFF);
}

static WN_CRTAPI char *ms_getenv(const char *name)
{
    for (char **e = g_proc.env_utf8; e && *e; e++) {
        const char *eq = strchr(*e, '=');
        if (eq && (size_t)(eq - *e) == strlen(name) &&
            !strncasecmp(*e, name, strlen(name)))
            return *e + strlen(name) + 1;
    }
    return NULL;
}

/* --- ctype (real: forward to host with unsigned-char domain) ---------------- */

static WN_CRTAPI int32_t ms_toupper(int32_t c) { return toupper((unsigned char)(c & 0xFF)); }
static WN_CRTAPI int32_t ms_tolower(int32_t c) { return tolower((unsigned char)(c & 0xFF)); }
static WN_CRTAPI int32_t ms_isalpha(int32_t c) { return isalpha((unsigned char)(c & 0xFF)) != 0; }
static WN_CRTAPI int32_t ms_isalnum(int32_t c) { return isalnum((unsigned char)(c & 0xFF)) != 0; }
static WN_CRTAPI int32_t ms_iscntrl(int32_t c) { return iscntrl((unsigned char)(c & 0xFF)) != 0; }
static WN_CRTAPI int32_t ms_isdigit(int32_t c) { return isdigit((unsigned char)(c & 0xFF)) != 0; }
static WN_CRTAPI int32_t ms_isgraph(int32_t c) { return isgraph((unsigned char)(c & 0xFF)) != 0; }
static WN_CRTAPI int32_t ms_islower(int32_t c) { return islower((unsigned char)(c & 0xFF)) != 0; }
static WN_CRTAPI int32_t ms_isprint(int32_t c) { return isprint((unsigned char)(c & 0xFF)) != 0; }
static WN_CRTAPI int32_t ms_ispunct(int32_t c) { return ispunct((unsigned char)(c & 0xFF)) != 0; }
static WN_CRTAPI int32_t ms_isspace(int32_t c) { return isspace((unsigned char)(c & 0xFF)) != 0; }
static WN_CRTAPI int32_t ms_isupper(int32_t c) { return isupper((unsigned char)(c & 0xFF)) != 0; }
static WN_CRTAPI int32_t ms_isxdigit(int32_t c) { return isxdigit((unsigned char)(c & 0xFF)) != 0; }
static WN_CRTAPI int32_t ms___isascii(int32_t c) { return (c & ~0x7F) == 0; }
static WN_CRTAPI int32_t ms_toascii(int32_t c) { return c & 0x7F; }

/* --- _setjmp / _longjmp (MS x64 jmp_buf layout: uint64_t[16]) ------------------
 *
 * MSVC's plain _setjmp saves the 6 nonvolatile GPRs + r12-r15 + rsp + rip:
 *   [0]=RBX [1]=RSI [2]=RDI [3]=RBP [4..7]=R12-R15 [8]=RSP [9]=RIP
 * These are called BY GUEST CODE directly, so they follow the MS ABI
 * (rcx = jmp_buf). Implemented in raw asm like the stub trampoline.
 */
extern WN_CRTAPI int32_t ms__setjmp_impl(void *env);
extern WN_CRTAPI void ms__longjmp_impl(void *env, uint64_t val);

#if defined(__x86_64__)
__asm__(
    ".text\n"
    ".globl ms__setjmp_impl\n"
    ".type ms__setjmp_impl, @function\n"
    "ms__setjmp_impl:\n"
    "    movq %rbx,   0x00(%rcx)\n"
    "    movq %rsi,   0x08(%rcx)\n"
    "    movq %rdi,   0x10(%rcx)\n"
    "    movq %rbp,   0x18(%rcx)\n"
    "    movq %r12,   0x20(%rcx)\n"
    "    movq %r13,   0x28(%rcx)\n"
    "    movq %r14,   0x30(%rcx)\n"
    "    movq %r15,   0x38(%rcx)\n"
    "    leaq 8(%rsp), %rax\n"
    "    movq %rax,   0x40(%rcx)\n"   /* caller rsp  */
    "    movq (%rsp), %rax\n"
    "    movq %rax,   0x48(%rcx)\n"   /* return addr */
    "    xorl %eax, %eax\n"
    "    ret\n"
    ".size ms__setjmp_impl, .-ms__setjmp_impl\n"
    ".globl ms__longjmp_impl\n"
    ".type ms__longjmp_impl, @function\n"
    "ms__longjmp_impl:\n"            /* rcx = env, rdx = val */
    "    movq 0x00(%rcx), %rbx\n"
    "    movq 0x08(%rcx), %rsi\n"
    "    movq 0x10(%rcx), %rdi\n"
    "    movq 0x18(%rcx), %rbp\n"
    "    movq 0x20(%rcx), %r12\n"
    "    movq 0x28(%rcx), %r13\n"
    "    movq 0x30(%rcx), %r14\n"
    "    movq 0x38(%rcx), %r15\n"
    "    movq 0x40(%rcx), %rsp\n"
    "    movq 0x48(%rcx), %rax\n"
    "    xorl %ecx, %ecx\n"          /* clear retval's env for good measure */
    "    testq %rdx, %rdx\n"
    "    jne 2f\n"
    "    movl $1, %edx\n"
    "2:  movq %rdx, %rax\n"
    "    jmp *%rax\n"
    ".size ms__longjmp_impl, .-ms__longjmp_impl\n"
);
#else
/* i386: classic cdecl setjmp saves ebx,esi,edi,ebp,esp,eip — TODO */
__asm__(".globl ms__setjmp_impl\n.type ms__setjmp_impl,@function\nms__setjmp_impl:\n xor %eax,%eax\n ret\n"
".globl ms__longjmp_impl\n.type ms__longjmp_impl,@function\nms__longjmp_impl:\n xor %eax,%eax\n ret\n");
#endif


/* --- export table -------------------------------------------------------------------------------- */

const wn_export_entry wn_msvcrt_exports[] = {
    { "__initenv", &g_initenv_ptr },
    { "___lc_codepage_func", ms___lc_codepage_func },
    { "___mb_cur_max_func", ms___mb_cur_max_func },
    { "__C_specific_handler", ms___C_specific_handler },
    { "__getmainargs", ms___getmainargs },
    { "__iob_func", ms___iob_func },
    { "__p__iob", ms___p___iob },
    { "__p___mb_cur_max", ms___p___mb_cur_max },
    { "__p__commode", ms___p__commode },
    { "__p__fmode", ms___p__fmode },
    { "__p___initenv", ms___p___initenv },
    { "__p__acmdln", ms___p__acmdln },
    { "_ismbblead", ms__ismbblead },
    { "_ismbbtrail", ms__ismbbtrail },
    { "_ismbcspace", ms__ismbcspace },
    { "_setmbcp", ms__setmbcp },
    { "__p__wcmdln", ms___p__wcmdln },
    /* _acmdln/_wcmdln as DATA exports: address of our variable (the _iob
     * pattern; MSVC exports them as data). */
    { "_acmdln", (void *)&g_acmdln },
    { "_wcmdln", (void *)&g_wcmdln },
    { "__lc_codepage", ms___lc_codepage },
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
    { "_setjmp", ms__setjmp_impl },
    { "_longjmp", ms__longjmp_impl },
    { "longjmp", ms__longjmp_impl },
    { "_strdup", ms_strdup },
    { "_stricmp", ms_stricmp },
    { "_strnicmp", ms_strnicmp },
    { "_unlock", ms__unlock },
    { "_vsnprintf", ms_vsnprintf },
    { "abort", ms_abort },
    { "toupper", ms_toupper },
    { "tolower", ms_tolower },
    { "isalpha", ms_isalpha },
    { "isalnum", ms_isalnum },
    { "iscntrl", ms_iscntrl },
    { "isdigit", ms_isdigit },
    { "isgraph", ms_isgraph },
    { "islower", ms_islower },
    { "isprint", ms_isprint },
    { "ispunct", ms_ispunct },
    { "isspace", ms_isspace },
    { "isupper", ms_isupper },
    { "isxdigit", ms_isxdigit },
    { "__isascii", ms___isascii },
    { "toascii", ms_toascii },
    { "abs", (void *)ms_abs },
    { "atexit", ms_atexit },
    { "_onexit", ms__onexit },
    { "atof", ms_atof },
    { "atoi", ms_atoi },
    { "_time64", ms_time },
    { "atol", ms_atol },
    { "atoll", ms_atoll },
    { "calloc", ms_calloc },
    { "clock", ms_clock },
    { "gmtime", ms_gmtime },
    { "localtime", ms_localtime },
    { "_localtime32", ms__localtime32 },
    { "_localtime64", ms__localtime64 },
    { "qsort", ms_qsort },
    { "strlwr", ms__strlwr },
    { "strupr", ms__strupr },
    { "_strlwr", ms__strlwr },
    { "_strupr", ms__strupr },
    { "exit", ms_exit },
    { "fabs", ms_fabs },
    { "fclose", ms_fclose },
    { "feof", ms_feof },
    { "fflush", ms_fflush },
    { "fopen", ms_fopen },
    { "_wfopen", ms__wfopen },
    { "_fileno", ms__fileno },
    { "_isatty", ms__isatty },
    { "_access", ms__access },
    { "_waccess", ms__waccess },
    { "fgets", ms_fgets },
    { "_setmode", ms__setmode },
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
    { "_CxxThrowException", ms_CxxThrowException },
    { "wcscmp", ms_wcscmp },
    { "wcsncmp", ms_wcsncmp },
    { "_wcsicmp", ms_wcsicmp },
    { "wcsicmp", ms_wcsicmp },
    { "_wcsnicmp", ms_wcsnicmp },
    { "wcsnicmp", ms_wcsnicmp },
    { "wcschr", ms_wcschr },
    { "wcsrchr", ms_wcsrchr },
    { "wcscpy", ms_wcscpy },
    { "wcsncpy", ms_wcsncpy },
    { "wcscat", ms_wcscat },
    { "wcsncat", ms_wcsncat },
    { "wcsstr", ms_wcsstr },
    { "wcspbrk", ms_wcspbrk },
    { "wcsspn", ms_wcsspn },
    { "wcscspn", ms_wcscspn },
    { "wcstok", ms_wcstok },
    { "wmemcpy", ms_wmemcpy },
    { "wmemset", ms_wmemset },
    { "strupr", ms_strupr },
    { "time", ms_time },
    { "vfprintf", ms_vfprintf },
    { "vprintf", ms_vprintf },
    { "vsnprintf", ms_vsnprintf },
    { "vsprintf", ms_vsprintf },
    { NULL, NULL },
};
