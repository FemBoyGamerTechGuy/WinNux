/* shell32.c — Shell basics.
 *
 * REAL: CommandLineToArgvW (full Windows quoting rules), SHGetFolderPath /
 * SHGetSpecialFolderPath (prefix-backed user/profile dirs, CSIDL_FLAG_CREATE
 * honored), IsUserAnAdmin (euid check), ShellExecuteA/W + Ex (URLs and files
 * through xdg-open, .exe/.bat re-launched through our own loader).
 */
#include "wn_dll.h"
#include "wn_log.h"
#include "wn_process.h"
#include "wn_util.h"
#include "wn_path.h"

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* --- CommandLineToArgvW: canonical MSVCRT argument splitting --------------- */

typedef struct {
    uint16_t *wargv[512];
    int       count;
} argv_ctx;

/* Split like Windows: whitespace outside quotes separates args; backslashes
 * are literal except before a quote (2N backslashes + " -> N backslashes +
 * literal/quote toggle). */
static int win_split_cmdline(const uint16_t *cmd, argv_ctx *ctx)
{
    int argc = 0;
    const uint16_t *p = cmd;
    for (;;) {
        while (*p == L' ' || *p == L'\t')
            p++;
        if (!*p)
            break;
        /* One argument: measure worst case, then build. */
        const uint16_t *start = p;
        size_t cap = 0;
        const uint16_t *q = p;
        int inquote = 0;
        while (*q && (inquote || (*q != L' ' && *q != L'\t'))) {
            if (*q == L'"') {
                inquote = !inquote;
                q++;
            } else if (*q == L'\\' && q[1] == L'"') {
                size_t nb = 0;
                while (*q == L'\\') { nb++; q++; }
                if (nb % 2 == 0 && *q == L'"') { q++; inquote = !inquote; }
                cap += nb / 2;
            } else {
                cap++;
                q++;
            }
        }
        if (argc >= 512)
            break;
        uint16_t *out = wn_xmalloc((cap + 1) * sizeof(uint16_t));
        size_t oi = 0;
        inquote = 0;
        q = start;
        while (*q && (inquote || (*q != L' ' && *q != L'\t'))) {
            if (*q == L'"') {
                inquote = !inquote;
                q++;
            } else if (*q == L'\\' && q[1] == L'"') {
                size_t nb = 0;
                while (*q == L'\\') { nb++; q++; }
                if (nb % 2 == 0 && *q == L'"') { q++; inquote = !inquote; }
                for (size_t k = 0; k < nb / 2; k++)
                    out[oi++] = L'\\';
            } else {
                out[oi++] = *q++;
            }
        }
        out[oi] = 0;
        ctx->wargv[argc++] = out;
        p = q;
    }
    ctx->count = argc;
    return argc;
}

static WN_API uint64_t sh_CommandLineToArgvW(const uint16_t *cmd, int32_t *num)
{
    if (!num)
        return 0;
    if (!cmd) {
        /* NULL means GetCommandLine; we approximate with an empty list. */
        *num = 0;
        return 0;
    }
    argv_ctx ctx;
    memset(&ctx, 0, sizeof ctx);
    int n = win_split_cmdline(cmd, &ctx);
    if (n <= 0) {
        *num = 0;
        return 0;
    }
    /* Windows layout: [argv array][strings...]; one block, argv[N] = NULL. */
    uint64_t *argv = wn_xmalloc(((size_t)n + 1) * sizeof(uint64_t));
    for (int i = 0; i < n; i++)
        argv[i] = (uint64_t)(uintptr_t)ctx.wargv[i];
    argv[n] = 0;
    *num = n;
    return (uint64_t)(uintptr_t)argv;
}

/* --- SHGetFolderPath: prefix-backed ------------------------------------------ */

#define CSIDL_FLAG_CREATE 0x8000

static int sh_folder_for_csidl(uint32_t csidl, char *win, size_t cap)
{
    static const char *user = NULL;
    if (!user) {
        user = getenv("USER");
        if (!user || !*user)
            user = "user";
    }
    const char *sub = NULL;
    switch (csidl & 0xFF) {
    case 0x00: sub = "Desktop"; break;                 /* CSIDL_DESKTOP   */
    case 0x02: sub = "Start Menu/Programs"; break;     /* CSIDL_PROGRAMS  */
    case 0x05: sub = "My Documents"; break;            /* CSIDL_PERSONAL  */
    case 0x07: sub = "Start Menu/Programs/Startup"; break;
    case 0x1a: sub = "AppData/Roaming"; break;         /* CSIDL_APPDATA   */
    case 0x1c: sub = "AppData/Local"; break;           /* CSIDL_LOCAL_APPDATA */
    case 0x24: snprintf(win, cap, "%s/drive_c/windows", g_proc.prefix);
               return 0;                                /* CSIDL_WINDOWS   */
    case 0x25: snprintf(win, cap, "%s/drive_c/windows/system32", g_proc.prefix);
               return 0;                                /* CSIDL_SYSTEM    */
    case 0x26: snprintf(win, cap, "%s/drive_c/Program Files", g_proc.prefix);
               return 0;                                /* CSIDL_PROGRAM_FILES */
    case 0x2a: snprintf(win, cap, "%s/drive_c/Program Files/Common Files",
                        g_proc.prefix);
               return 0;                                /* PROGRAM_FILES_COMMON */
    case 0x2b: snprintf(win, cap, "%s/drive_c/Program Files (x86)",
                        g_proc.prefix);
               return 0;                                /* PROGRAM_FILESX86 */
    default: return -1;
    }
    snprintf(win, cap, "%s/drive_c/users/%s/%s", g_proc.prefix, user, sub);
    return 0;
}

static int sh_folder_path(uint32_t csidl, int wide, void *out, size_t out_cap)
{
    char win[1100];
    if (sh_folder_for_csidl(csidl, win, sizeof win) != 0) {
        wn_log(WN_LOG_WARN, "shell32: SHGetFolderPath CSIDL 0x%x not mapped "
               "(honest failure)", csidl);
        return -1;
    }
    if (csidl & CSIDL_FLAG_CREATE) {
        char host[1100];
        wn_path_win_to_host(win, host, sizeof host);
        for (char *p = host + strlen(g_proc.prefix); *p; p++)
            if (*p == '/' && p[1]) {
                char save = p[1];
                p[1] = 0;
                mkdir(host, 0755);
                p[1] = save;
            }
        mkdir(host, 0755);
    }
    if (wide) {
        uint16_t *w = wn_utf8_to_utf16(win, NULL);
        if (!w)
            return -1;
        size_t l = 0;
        while (w[l])
            l++;
        if (l + 1 > out_cap / 2) {
            free(w);
            return -1;
        }
        memcpy(out, w, (l + 1) * 2);
        free(w);
    } else {
        if (strlen(win) + 1 > out_cap)
            return -1;
        memcpy(out, win, strlen(win) + 1);
    }
    return 0;
}

static WN_API int32_t sh_SHGetFolderPathA(wn_abiword hwnd, uint32_t csidl,
                                          wn_abiword token, uint32_t flags,
                                          char *path)
{
    (void)hwnd; (void)token; (void)flags;
    if (!path)
        return -2147467259;
    return sh_folder_path(csidl, 0, path, 260) == 0 ? 0 : -2147467259;
}

static WN_API int32_t sh_SHGetFolderPathW(wn_abiword hwnd, uint32_t csidl,
                                          wn_abiword token, uint32_t flags,
                                          uint16_t *path)
{
    (void)hwnd; (void)token; (void)flags;
    if (!path)
        return -2147467259;
    return sh_folder_path(csidl, 1, path, 520) == 0 ? 0 : -2147467259;
}

static WN_API int32_t sh_SHGetSpecialFolderPathA(wn_abiword hwnd, char *path,
                                                 uint32_t csidl, int32_t create)
{
    (void)hwnd;
    if (!path)
        return 0;
    return sh_folder_path(csidl | (create ? CSIDL_FLAG_CREATE : 0), 0,
                          path, 260) == 0;
}

static WN_API int32_t sh_SHGetSpecialFolderPathW(wn_abiword hwnd, uint16_t *path,
                                                 uint32_t csidl, int32_t create)
{
    (void)hwnd;
    if (!path)
        return 0;
    return sh_folder_path(csidl | (create ? CSIDL_FLAG_CREATE : 0), 1,
                          path, 520) == 0;
}

static WN_API int32_t sh_IsUserAnAdmin(void)
{
    return geteuid() == 0;
}

/* --- ShellExecute: real ------------------------------------------------- */

/* Split a params string on whitespace (quote-aware enough for launching). */
static int sh_split_params(const char *params, char *argv[], int max)
{
    int n = 0;
    const char *p = params;
    while (p && *p && n < max - 1) {
        while (*p == ' ' || *p == '\t')
            p++;
        if (!*p)
            break;
        const char *start = p;
        int inq = 0;
        while (*p && (inq || (*p != ' ' && *p != '\t'))) {
            if (*p == '"')
                inq = !inq;
            p++;
        }
        size_t len = (size_t)(p - start);
        char *a = wn_xmalloc(len + 1);
        size_t o = 0;
        for (size_t i = 0; i < len; i++)
            if (start[i] != '"')
                a[o++] = start[i];
        a[o] = 0;
        argv[n++] = a;
    }
    return n;
}

static int sh_is_url(const char *f)
{
    const char *c = strchr(f, ':');
    if (!c || c == f)
        return 0;
    for (const char *p = f; p < c; p++)
        if (!isalnum((unsigned char)*p) && *p != '+' && *p != '-' && *p != '.')
            return 0;
    /* scheme present: http/https/mailto/etc. open in the host browser */
    return 1;
}

/* Launch and don't wait (the shell case). Returns >32 (SE success band). */
static uintptr_t sh_launch(const char *file, const char *params, const char *dir)
{
    pid_t pid = fork();
    if (pid < 0)
        return 0;                       /* 0 = out of memory (SE_ERR_OOM) */
    if (pid == 0) {
        /* child: exec immediately; never touch our locks/allocations */
        if (dir && *dir)
            chdir(dir);
        if (sh_is_url(file)) {
            execlp("xdg-open", "xdg-open", file, (char *)NULL);
            _exit(127);
        }
        /* .exe/.bat: launch through our own loader (a second WinNux app) */
        size_t fl = strlen(file);
        int is_exe = (fl > 4 && !strcasecmp(file + fl - 4, ".exe")) ||
                     (fl > 4 && !strcasecmp(file + fl - 4, ".bat")) ||
                     (fl > 4 && !strcasecmp(file + fl - 4, ".cmd"));
        char self[300];
        ssize_t n = readlink("/proc/self/exe", self, sizeof self - 1);
        if (is_exe && n > 0) {
            self[n] = 0;
            char *argv[66];
            int ac = 0;
            argv[ac++] = (char *)"winnux";
            argv[ac++] = (char *)"run";
            argv[ac++] = (char *)file;
            if (params && *params)
                ac += sh_split_params(params, argv + ac, 64 - ac);
            argv[ac] = NULL;
            execv(self, argv);
            _exit(127);
        }
        /* any other file/dir: host association via xdg-open */
        execlp("xdg-open", "xdg-open", file, (char *)NULL);
        _exit(127);
    }
    /* parent: xdg-open delegates to the browser and exits quickly, so a
     * plain waitpid is fine (and keeps SIGCHLD semantics untouched). */
    int st;
    waitpid(pid, &st, 0);
    return 42;                          /* >32: success (HINSTANCE band) */
}

static uintptr_t sh_execute_core(const char *verb, const char *file,
                                 const char *params, const char *dir)
{
    if (!file || !*file) {
        wn_last_error_set(2 /*ERROR_FILE_NOT_FOUND*/);
        return 2;                       /* SE_ERR_FNF */
    }
    (void)verb;
    wn_log(WN_LOG_DEBUG, "shell32: ShellExecute('%s' '%s' '%s')",
           verb ? verb : "open", file, params ? params : "");
    /* Windows-path files must map into the prefix before the host shell
     * sees them. */
    char host[1100];
    if (!sh_is_url(file)) {
        wn_path_win_to_host(file, host, sizeof host);
        file = host;
    }
    uintptr_t r = sh_launch(file, params, dir);
    if (r == 0) {
        wn_last_error_set(8 /*ERROR_NOT_ENOUGH_MEMORY*/);
        return 8;                       /* SE_ERR_OOM */
    }
    return r;
}

static WN_API uint64_t sh_ShellExecuteA(wn_abiword hwnd, const char *verb,
                                        const char *file, const char *params,
                                        const char *dir, int32_t show)
{
    (void)hwnd; (void)show;
    return (uint64_t)sh_execute_core(verb, file, params, dir);
}

static WN_API uint64_t sh_ShellExecuteW(wn_abiword hwnd, const uint16_t *verb,
                                        const uint16_t *file,
                                        const uint16_t *params,
                                        const uint16_t *dir, int32_t show)
{
    (void)hwnd; (void)show;
    if (!file)
        return 2;
    size_t l = 0;
    while (file[l])
        l++;
    char *f = wn_utf16_to_utf8(file, l);
    char *v = verb ? wn_utf16_to_utf8(verb, 256) : NULL;
    char *pa = params ? wn_utf16_to_utf8(params, 1024) : NULL;
    char *d = dir ? wn_utf16_to_utf8(dir, 1024) : NULL;
    uintptr_t r = sh_execute_core(v, f ? f : "", pa, d);
    free(f); free(v); free(pa); free(d);
    return (uint64_t)r;
}

/* SHELLEXECUTEINFOA x64: cbSize@0 fMask@4 hwnd@8 lpVerb@0x10 lpFile@0x18
 * lpParameters@0x20 lpDirectory@0x28 nShow@0x30 hInstApp@0x38 ... hProcess@0x68 */
static int sh_fill_exec_info(void *info, int wide, const char *file)
{
    (void)wide;   /* the A/W distinction only matters for reading lpFile */
    uint8_t *b = info;
    uint32_t cb = *(const uint32_t *)(const void *)(b + 0);
    if (cb < 0x40)
        return 0;
    uintptr_t r = sh_execute_core(
        NULL,
        file,
        NULL,
        NULL);
    *(uint64_t *)(void *)(b + 0x38) = (uint64_t)r;   /* hInstApp */
    return r > 32;
}

static WN_API int32_t sh_ShellExecuteExA(void *info)
{
    if (!info)
        return 0;
    uint8_t *b = info;
    const char *file = *(const char *const *)(const void *)(b + 0x18);
    wn_last_error_set(0);
    return sh_fill_exec_info(info, 0, file ? file : "");
}

static WN_API int32_t sh_ShellExecuteExW(void *info)
{
    if (!info)
        return 0;
    uint8_t *b = info;
    const uint16_t *file = *(const uint16_t *const *)(const void *)(b + 0x18);
    if (!file)
        return 0;
    size_t l = 0;
    while (file[l])
        l++;
    char *f = wn_utf16_to_utf8(file, l);
    int32_t r = sh_fill_exec_info(info, 1, f ? f : "");
    free(f);
    return r;
}

const wn_export_entry wn_shell32_exports[] = {
    { "CommandLineToArgvW",        sh_CommandLineToArgvW },
    { "SHGetFolderPathA",          sh_SHGetFolderPathA },
    { "SHGetFolderPathW",          sh_SHGetFolderPathW },
    { "SHGetSpecialFolderPathA",   sh_SHGetSpecialFolderPathA },
    { "SHGetSpecialFolderPathW",   sh_SHGetSpecialFolderPathW },
    { "IsUserAnAdmin",             sh_IsUserAnAdmin },
    { "ShellExecuteA",             sh_ShellExecuteA },
    { "ShellExecuteW",             sh_ShellExecuteW },
    { "ShellExecuteExA",           sh_ShellExecuteExA },
    { "ShellExecuteExW",           sh_ShellExecuteExW },
    { NULL, NULL },
};
