/* path.c — drive mapping, case-insensitive resolution, cwd tracking. */
#include "wn_path.h"
#include "wn_module.h"
#include "wn_log.h"
#include "wn_util.h"
#include "wn_process.h"

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <execinfo.h>
#include <unistd.h>

/* Documented global: Windows CWD in Windows form. */
static char g_cwd_win[1024] = "C:\\";

const char *wn_path_prefix(void) { return g_proc.prefix; }

/* mkdir -p semantics for the prefix root. */
static int mkdir_p(const char *path)
{
    char tmp[2100];
    snprintf(tmp, sizeof tmp, "%s", path);
    size_t l = strlen(tmp);
    if (l == 0)
        return -1;
    if (tmp[l - 1] == '/')
        tmp[l - 1] = '\0';
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0777) != 0 && errno != EEXIST)
                return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, 0777) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

/* Current user name for the profile tree (Windows-style, no spaces). */
static void prefix_user(char *out, size_t cap)
{
    const char *u = getenv("USER");
    if (!u || !*u) {
        struct passwd *pw = getpwuid(getuid());
        u = pw ? pw->pw_name : "user";
    }
    /* Windows profile dirs munge spaces etc.; keep it simple + safe. */
    size_t o = 0;
    for (size_t i = 0; u[i] && o + 1 < cap; i++)
        if (u[i] != ' ')
            out[o++] = (u[i] >= 'A' && u[i] <= 'Z') ? (char)(u[i] + 32) : u[i];
    out[o] = '\0';
}

int wn_path_prefix_init(const char *prefix)
{
    if (mkdir_p(prefix) != 0) {
        wn_log(WN_LOG_ERR, "prefix: cannot create %s: %s", prefix, strerror(errno));
        return -1;
    }
    char user[64];
    prefix_user(user, sizeof user);
    char p[2100];
    char userdir[2100];
    snprintf(userdir, sizeof userdir, "%s/drive_c/users/%s", prefix, user);
    const char *dirs[] = {
        "drive_c",
        "drive_c/windows",
        "drive_c/windows/system32",
        "drive_c/windows/syswow64",      /* populated when 32-bit lands */
        "drive_c/windows/temp",
        "drive_c/Program Files",
        "drive_c/Program Files (x86)",
        "drive_c/users",
        userdir,                         /* C:\Users\<name> */
        "drive_c/users/Public",
        NULL };
    for (int i = 0; dirs[i]; i++) {
        if (dirs[i][0] == '/')
            snprintf(p, sizeof p, "%s", dirs[i]);
        else
            snprintf(p, sizeof p, "%s/%s", prefix, dirs[i]);
        if (mkdir(p, 0777) != 0 && errno != EEXIST) {
            wn_log(WN_LOG_WARN, "prefix: cannot create %s: %s", p, strerror(errno));
            return -1;
        }
    }
    /* Registry files exist (possibly empty) so tools can stat them. */
    const char *regfiles[] = { "system.reg", "user.reg", "userdiff.reg", NULL };
    for (int i = 0; regfiles[i]; i++) {
        snprintf(p, sizeof p, "%s/%s", prefix, regfiles[i]);
        if (access(p, F_OK) != 0) {
            FILE *f = fopen(p, "w");
            if (f)
                fclose(f);
        }
    }
    return 0;
}

/* Is the char a Windows path separator? */
static int is_sep(char c) { return c == '\\' || c == '/'; }

/* Normalize: strip \\?\ or \\.\ prefixes, forward slashes -> backslashes in
 * place within a copy. Returns a malloc'd lowercase-insensitive form? No:
 * returns malloc'd cleaned UTF-8 path with backslashes. */
static char *clean_win_path(const char *win)
{
    const char *p = win;
    if (!p || !*p)
        return NULL;
    /* NT path prefixes. */
    if (!strncmp(p, "\\\\?\\", 4) || !strncmp(p, "\\\\.\\", 4))
        p += 4;
    /* UNC: unsupported (loud). */
    if (!strncmp(p, "\\\\", 2) && strncmp(p, "\\\\?\\", 4)) {
        wn_log(WN_LOG_ERR, "path: UNC paths unsupported: '%s'", win);
        return NULL;
    }
    char *out = wn_xmalloc(strlen(p) + 1);
    size_t o = 0;
    for (size_t i = 0; p[i]; i++)
        out[o++] = is_sep(p[i]) ? '\\' : p[i];
    out[o] = '\0';
    /* Collapse duplicate backslashes. */
    size_t w = 0;
    for (size_t i = 0; i < o; i++) {
        if (out[i] == '\\' && w && out[w - 1] == '\\')
            continue;
        out[w++] = out[i];
    }
    out[w] = '\0';
    return out;
}

int wn_path_win_to_host(const char *win, char *out, size_t cap)
{
    /* Apps pass garbage pointers on failure paths (putty does; on Windows
     * that AVs inside the app and its SEH catches it). The layer must fail
     * cleanly instead of dying: probe under the sigsetjmp guard first. */
    if (win && !wn_ptr_readable(win, 4)) {
        /* Guest bug survived: log caller chain + guest frame for triage
         * (putty taught us these happen; the layer must fail cleanly). */
        void *bt[10];
        int n = backtrace(bt, 10);
        char frames[192] = "";
        size_t o = 0;
        for (int i = 0; i < n && o + 24 < sizeof frames; i++) {
            Dl_info di;
            if (dladdr(bt[i], &di) && di.dli_fbase)
                o += (size_t)snprintf(frames + o, sizeof frames - o,
                                      " +%llx", (unsigned long long)
                                      ((char *)bt[i] - (char *)di.dli_fbase));
            else {
                wn_module *gm = wn_module_from_addr(bt[i], NULL);
                if (gm)
                    o += (size_t)snprintf(frames + o, sizeof frames - o,
                                          " %s+0x%llx", gm->name,
                                          (unsigned long long)((char *)bt[i] -
                                                               (char *)gm->base));
            }
        }
        wn_log(WN_LOG_WARN, "path: unreadable win-path pointer %p -> "
               "ERROR_INVALID_NAME (guest bug survived; bt:%s)",
               (void *)win, frames);
        wn_last_error_set(WN_ERR_INVALID_NAME);
        return -1;
    }
    char *p = clean_win_path(win);
    if (!p) {
        wn_last_error_set(WN_ERR_INVALID_NAME);
        return -1;
    }
    if (p[0] && p[1] == ':') {                 /* drive-absolute */
        char drive = p[0];
        char *rest = p[2] == '\\' ? p + 3 : p + 2;
        /* Host paths need forward slashes: convert the rest in place. */
        for (char *q = rest; *q; q++)
            if (*q == '\\')
                *q = '/';
        if (drive == 'Z' || drive == 'z') {
            snprintf(out, cap, "/%s", rest);
        } else if (drive == 'C' || drive == 'c') {
            snprintf(out, cap, "%s/drive_c/%s", g_proc.prefix, rest);
        } else {
            wn_log(WN_LOG_WARN, "path: unmapped drive %c: in '%s' (mapped to C:)",
                   drive, win);
            snprintf(out, cap, "%s/drive_c/%s", g_proc.prefix, rest);
        }
        free(p);
        return 0;
    }
    if (p[0] == '\\' && p[1] != '\\') {        /* rooted, no drive: C:\ */
        char *rest = p + 1;
        for (char *q = rest; *q; q++)
            if (*q == '\\')
                *q = '/';
        snprintf(out, cap, "%s/drive_c/%s", g_proc.prefix, rest);
        free(p);
        return 0;
    }
    /* Relative: join with CWD. */
    char cwd[1024];
    wn_path_get_cwd_win(cwd, sizeof cwd);
    char joined[2048];
    if (cwd[strlen(cwd) - 1] == '\\')
        snprintf(joined, sizeof joined, "%s%s", cwd, p);
    else
        snprintf(joined, sizeof joined, "%s\\%s", cwd, p);
    free(p);
    return wn_path_win_to_host(joined, out, cap);
}

void wn_path_host_to_win(const char *host, char *out, size_t cap)
{
    char pl[2100];
    snprintf(pl, sizeof pl, "%s/drive_c", g_proc.prefix);
    size_t n = strlen(pl);
    if (!strncmp(host, pl, n) && (host[n] == '/' || host[n] == '\0')) {
        const char *rest = host[n] ? host + n + 1 : "";
        snprintf(out, cap, "C:%s%s", *rest ? "\\" : "", rest);
    } else {
        /* Host filesystem: expose through Z:. */
        snprintf(out, cap, "Z:%s%s", host[0] == '/' ? "" : "/", host);
    }
    /* Windows paths use backslashes. */
    for (char *q = out; *q; q++)
        if (*q == '/')
            *q = '\\';
}

/* Case-insensitive file lookup inside one host directory. Fills out with
 * "<dir>/<actual-name>" when found (exact case first, then readdir scan).
 * Returns 1 on hit, 0 on miss. Exported for the loader's DLL search. */
int wn_path_lookup_ci(const char *dir, const char *name, char *out, size_t cap)
{
    if (strlen(dir) + strlen(name) + 2 > cap)
        return 0;
    /* Fast path first (exact case). */
    snprintf(out, cap, "%s/%s", dir, name);
    struct stat st;
    if (lstat(out, &st) == 0)
        return 1;
    DIR *d = opendir(dir);
    if (!d)
        return 0;
    struct dirent64 *e;   /* LFS: 32-bit readdir EOVERFLOWs on 64-bit inodes */
    int found = 0;
    while ((e = readdir64(d))) {
        if (wn_strcaseeq(e->d_name, name)) {
            snprintf(out, cap, "%s/%s", dir, e->d_name);
            found = 1;
            break;
        }
    }
    closedir(d);
    return found;
}

/* Case-insensitive component resolution.
 * (The length guard below makes the snprintfs safe; GCC cannot prove it,
 * so the warning is locally disabled with a comment trail.) */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
static int ci_lookup(const char *dir, const char *name, char *out, size_t cap)
{
    return wn_path_lookup_ci(dir, name, out, cap);
}
#pragma GCC diagnostic pop

int wn_path_resolve_ci(const char *win, char *out, size_t cap)
{
    char host[1024];
    if (wn_path_win_to_host(win, host, sizeof host) != 0)
        return -1;

    struct stat st;
    if (lstat(host, &st) == 0) {   /* exact exists */
        snprintf(out, cap, "%s", host);
        return 0;
    }
    if (strchr(host, '*') || strchr(host, '?'))
        return -1;                 /* wildcards: caller enumerates */

    /* Walk components, resolving case-insensitively. */
    char resolved[PATH_MAX];
    resolved[0] = '\0';
    const char *p = host;
    if (p[0] == '/') {
        snprintf(resolved, sizeof resolved, "/");
        p++;
    }
    char comp[NAME_MAX + 1];
    while (*p) {
        size_t cl = 0;
        while (p[cl] && p[cl] != '/')
            cl++;
        if (cl >= sizeof comp) {
            return -1;
        }
        memcpy(comp, p, cl);
        comp[cl] = '\0';
        p += cl;
        while (*p == '/')
            p++;
        char next[PATH_MAX];
        if (!ci_lookup(resolved[0] ? resolved : ".", comp, next, sizeof next)) {
            return -1;             /* component missing */
        }
        /* Keep the directory separators canonical. */
        snprintf(resolved, sizeof resolved, "%s", next);
    }
    if (!resolved[0])
        return -1;
    snprintf(out, cap, "%s", resolved);
    return 0;
}

void wn_path_get_cwd_win(char *out, size_t cap)
{
    snprintf(out, cap, "%s", g_cwd_win);
}

int wn_path_set_cwd_win(const char *windir)
{
    char host[1024];
    if (wn_path_win_to_host(windir, host, sizeof host) != 0)
        return -1;
    if (chdir(host) != 0) {
        wn_log(WN_LOG_DEBUG, "path: chdir %s: %s", host, strerror(errno));
        return -1;
    }
    char clean[1024];
    char *p = wn_xstrdup(windir);
    for (char *q = p; *q; q++)
        if (*q == '/')
            *q = '\\';
    /* Normalize trailing separator. */
    snprintf(clean, sizeof clean, "%s%s", p,
             (p[strlen(p) - 1] == '\\') ? "" : "\\");
    free(p);
    snprintf(g_cwd_win, sizeof g_cwd_win, "%s", clean);
    return 0;
}

/* Initialize CWD from host cwd at startup. */
void wn_path_init_cwd_from_host(void)
{
    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof cwd)) {
        snprintf(g_cwd_win, sizeof g_cwd_win, "C:\\");
        return;
    }
    wn_path_host_to_win(cwd, g_cwd_win, sizeof g_cwd_win);
}

const char *wn_path_is_device(const char *win)
{
    static const char *devs[] = { "CON", "PRN", "AUX", "NUL",
                                  "COM1", "LPT1", NULL };
    const char *base = win;
    const char *bs = strrchr(win, '\\');
    if (bs)
        base = bs + 1;
    for (int i = 0; devs[i]; i++)
        if (wn_strcaseeq(base, devs[i]))
            return devs[i];
    return NULL;
}
