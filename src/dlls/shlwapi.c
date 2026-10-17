/* shlwapi.c — light-weight path/string helpers.
 *
 * The pure string/path manipulation functions are REAL (full Windows
 * semantics, path separators are '\\' or '/'). Existence checks resolve
 * through the prefix mapping so they see the same world the app does.
 */
#include "wn_dll.h"
#include "wn_log.h"
#include "wn_process.h"
#include "wn_util.h"
#include "wn_path.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <sys/stat.h>

static size_t wlen(const uint16_t *w)
{
    size_t l = 0;
    while (w[l])
        l++;
    return l;
}

/* --- A variants ----------------------------------------------------------- */

static char *sl_find_last_sep(const char *path)
{
    char *bs = (char *)strrchr(path, '\\');   /* cast: see msvcrt.c note */
    char *fs = (char *)strrchr(path, '/');
    if (!bs)
        return fs;
    if (!fs)
        return bs;
    return bs > fs ? bs : fs;
}

static WN_API char *sl_PathFindFileNameA(char *path)
{
    if (!path)
        return NULL;
    char *sep = sl_find_last_sep(path);
    return sep ? sep + 1 : path;
}

static WN_API uint64_t sl_PathFindFileNameW(uint16_t *path)
{
    if (!path)
        return 0;
    size_t last = 0;
    for (size_t i = 0; path[i]; i++)
        if (path[i] == L'\\' || path[i] == L'/')
            last = i + 1;
    return (uint64_t)(uintptr_t)(path + last);
}

static WN_API char *sl_PathFindExtensionA(char *path)
{
    if (!path)
        return NULL;
    char *name = sl_PathFindFileNameA(path);
    char *dot = strrchr(name, '.');
    return dot && dot != name ? dot : name + strlen(name);
}

static WN_API uint64_t sl_PathFindExtensionW(uint16_t *path)
{
    if (!path)
        return 0;
    /* find file name start */
    size_t start = 0;
    for (size_t i = 0; path[i]; i++)
        if (path[i] == L'\\' || path[i] == L'/')
            start = i + 1;
    size_t dotpos = 0;
    for (size_t i = start; path[i]; i++)
        if (path[i] == L'.' && i != start)
            dotpos = i + 1;   /* mark last dot (1-based); 0 = none */
    if (!dotpos)
        return (uint64_t)(uintptr_t)(path + wlen(path));
    return (uint64_t)(uintptr_t)(path + dotpos - 1);
}

static WN_API int32_t sl_PathIsRelativeA(const char *path)
{
    if (!path || !*path)
        return 1;
    return path[0] != '\\' && path[0] != '/' &&
           !(isalpha((unsigned char)path[0]) && path[1] == ':');
}

static WN_API int32_t sl_PathIsRelativeW(const uint16_t *path)
{
    if (!path || !path[0])
        return 1;
    if (path[0] == L'\\' || path[0] == L'/')
        return 0;
    if (path[1] == L':' && path[0] >= L'A' && path[0] <= L'z')
        return 0;
    return 1;
}

static WN_API char *sl_PathRemoveFileSpecA(char *path)
{
    if (!path)
        return NULL;
    char *sep = sl_find_last_sep(path);
    if (sep && sep != path) {
        *sep = 0;
        return path;
    }
    if (sep == path) {
        /* root: becomes empty per Windows? "\x" -> "\" stays. We keep "\". */
        sep[1] = 0;
        return path;
    }
    /* "C:x" — drive-relative: strip after colon. */
    if (path[0] && path[1] == ':') {
        path[2] = 0;
        return path;
    }
    path[0] = 0;
    return path;
}

static WN_API int32_t sl_PathRemoveFileSpecW(uint16_t *path)
{
    if (!path)
        return 0;
    size_t cut = (size_t)-1;
    for (size_t i = 0; path[i]; i++)
        if (path[i] == L'\\' || path[i] == L'/')
            cut = i;
    if (cut == (size_t)-1)
        return 0;
    path[cut ? cut : 1] = 0;
    return 1;
}

static WN_API int32_t sl_PathFileExistsA(const char *path)
{
    if (!path)
        return 0;
    char host[1100];
    if (wn_path_win_to_host(path, host, sizeof host) != 0)
        return 0;
    struct stat st;
    return stat(host, &st) == 0;
}

static WN_API int32_t sl_PathFileExistsW(const uint16_t *path)
{
    if (!path)
        return 0;
    char *u = wn_utf16_to_utf8(path, wlen(path));
    if (!u)
        return 0;
    char host[1100];
    int rc = wn_path_win_to_host(u, host, sizeof host);
    free(u);
    if (rc != 0)
        return 0;
    struct stat st;
    return stat(host, &st) == 0;
}

static WN_API int32_t sl_PathIsDirectoryA(const char *path)
{
    if (!path)
        return 0;
    char host[1100];
    if (wn_path_win_to_host(path, host, sizeof host) != 0)
        return 0;
    struct stat st;
    return stat(host, &st) == 0 && S_ISDIR(st.st_mode)
           ? 0x10 /* FILE_ATTRIBUTE_DIRECTORY */
           : 0;
}

/* PathMatchSpec: '*' any run, '?' any one char. */
static int match_spec(const char *spec, const char *name)
{
    if (!spec || !name)
        return 0;
    if (!*spec)
        return !*name;
    if (*spec == '*') {
        for (const char *n = name;; n++) {
            if (match_spec(spec + 1, n))
                return 1;
            if (!*n)
                break;
        }
        return 0;
    }
    if (!*name)
        return 0;
    if (*spec == '?' || tolower((unsigned char)*spec) == tolower((unsigned char)*name))
        return match_spec(spec + 1, name + 1);
    return 0;
}

static WN_API int32_t sl_PathMatchSpecA(const char *name, const char *spec)
{
    return match_spec(spec ? spec : "", name ? name : "");
}

static WN_API int32_t sl_PathMatchSpecW(const uint16_t *name,
                                        const uint16_t *spec)
{
    if (!name || !spec)
        return 0;
    char *n = wn_utf16_to_utf8(name, wlen(name));
    char *s = wn_utf16_to_utf8(spec, wlen(spec));
    int r = 0;
    if (n && s)
        r = match_spec(s, n);
    free(n);
    free(s);
    return r;
}

/* wnsprintf: bounded sprintf with the common format specifiers. */
static WN_API int32_t sl_wnsprintfA(char *buf, uint32_t cap,
                                    const char *fmt, uint64_t a1, uint64_t a2,
                                    uint64_t a3, uint64_t a4, uint64_t a5,
                                    uint64_t a6)
{
    /* Hand-rolled: host snprintf with up to 6 positional int/str args is
     * unknowable without varargs info; we support the overwhelmingly common
     * usages by treating every argument as 8 bytes and decoding %s/%d/%x/%u
     * ourselves. */
    const uint64_t args[6] = { a1, a2, a3, a4, a5, a6 };
    int ai = 0;
    char *out = buf;
    const char *end = buf + (cap ? cap - 1 : 0);
    const char *p = fmt;
    while (*p && out < end) {
        if (*p != '%') {
            *out++ = *p++;
            continue;
        }
        p++;
        if (*p == '%') {
            *out++ = '%';
            p++;
            continue;
        }
        char tmp[32];
        const char *ins = NULL;
        if (*p == 's') {
            ins = ai < 6 ? (const char *)(uintptr_t)args[ai++] : "";
            if (!ins)
                ins = "(null)";
        } else if (*p == 'd' || *p == 'i') {
            snprintf(tmp, sizeof tmp, "%lld",
                     (long long)(ai < 6 ? (int64_t)args[ai++] : 0));
            ins = tmp;
        } else if (*p == 'u') {
            snprintf(tmp, sizeof tmp, "%llu",
                     (unsigned long long)(ai < 6 ? args[ai++] : 0));
            ins = tmp;
        } else if (*p == 'x') {
            snprintf(tmp, sizeof tmp, "%llx",
                     (unsigned long long)(ai < 6 ? args[ai++] : 0));
            ins = tmp;
        } else if (*p == 'X') {
            snprintf(tmp, sizeof tmp, "%llX",
                     (unsigned long long)(ai < 6 ? args[ai++] : 0));
            ins = tmp;
        } else if (*p == 'c') {
            tmp[0] = (char)(ai < 6 ? args[ai++] : 0);
            tmp[1] = 0;
            ins = tmp;
        } else {
            /* unknown specifier: copy verbatim */
            tmp[0] = '%';
            tmp[1] = *p ? *p : 0;
            tmp[2] = 0;
            ins = tmp;
            if (*p)
                p++;
            continue;
        }
        p++;
        while (*ins && out < end)
            *out++ = *ins++;
    }
    *out = 0;
    return (int32_t)(out - buf);
}

const wn_export_entry wn_shlwapi_exports[] = {
    { "PathFindFileNameA",     sl_PathFindFileNameA },
    { "PathFindFileNameW",     sl_PathFindFileNameW },
    { "PathFindExtensionA",    sl_PathFindExtensionA },
    { "PathFindExtensionW",    sl_PathFindExtensionW },
    { "PathIsRelativeA",       sl_PathIsRelativeA },
    { "PathIsRelativeW",       sl_PathIsRelativeW },
    { "PathRemoveFileSpecA",   sl_PathRemoveFileSpecA },
    { "PathRemoveFileSpecW",   sl_PathRemoveFileSpecW },
    { "PathFileExistsA",       sl_PathFileExistsA },
    { "PathFileExistsW",       sl_PathFileExistsW },
    { "PathIsDirectoryA",      sl_PathIsDirectoryA },
    { "PathMatchSpecA",        sl_PathMatchSpecA },
    { "PathMatchSpecW",        sl_PathMatchSpecW },
    { "wnsprintfA",            sl_wnsprintfA },
    { NULL, NULL },
};
