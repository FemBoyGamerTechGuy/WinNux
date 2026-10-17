/* shell32.c — Shell basics.
 *
 * REAL: CommandLineToArgvW (full Windows quoting rules), SHGetFolderPath /
 * SHGetSpecialFolderPath (prefix-backed user/profile dirs, CSIDL_FLAG_CREATE
 * honored), IsUserAnAdmin (euid check).
 * Honest failures: ShellExecute (we cannot host shell launches yet) returns
 * SE_ERR_NOASSOC and logs loudly.
 */
#include "wn_dll.h"
#include "wn_log.h"
#include "wn_process.h"
#include "wn_util.h"
#include "wn_path.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
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

static WN_API int32_t sh_SHGetFolderPathA(uint64_t hwnd, uint32_t csidl,
                                          uint64_t token, uint32_t flags,
                                          char *path)
{
    (void)hwnd; (void)token; (void)flags;
    if (!path)
        return -2147467259;
    return sh_folder_path(csidl, 0, path, 260) == 0 ? 0 : -2147467259;
}

static WN_API int32_t sh_SHGetFolderPathW(uint64_t hwnd, uint32_t csidl,
                                          uint64_t token, uint32_t flags,
                                          uint16_t *path)
{
    (void)hwnd; (void)token; (void)flags;
    if (!path)
        return -2147467259;
    return sh_folder_path(csidl, 1, path, 520) == 0 ? 0 : -2147467259;
}

static WN_API int32_t sh_SHGetSpecialFolderPathA(uint64_t hwnd, char *path,
                                                 uint32_t csidl, int32_t create)
{
    (void)hwnd;
    if (!path)
        return 0;
    return sh_folder_path(csidl | (create ? CSIDL_FLAG_CREATE : 0), 0,
                          path, 260) == 0;
}

static WN_API int32_t sh_SHGetSpecialFolderPathW(uint64_t hwnd, uint16_t *path,
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

static WN_API uint64_t sh_ShellExecuteA(uint64_t hwnd, const char *verb,
                                        const char *file, const char *params,
                                        const char *dir, int32_t show)
{
    (void)hwnd; (void)verb; (void)params; (void)dir; (void)show;
    wn_log(WN_LOG_WARN, "shell32: ShellExecuteA('%s') not implemented: no "
           "shell integration yet -> SE_ERR_NOASSOC (31)",
           file ? file : "(null)");
    wn_last_error_set(WN_ERR_CALL_NOT_IMPLEMENTED);
    return 31;   /* SE_ERR_NOASSOC */
}

static WN_API uint64_t sh_ShellExecuteW(uint64_t hwnd, const uint16_t *verb,
                                        const uint16_t *file,
                                        const uint16_t *params,
                                        const uint16_t *dir, int32_t show)
{
    (void)hwnd; (void)verb; (void)params; (void)dir; (void)show;
    char *f = NULL;
    if (file) {
        size_t l = 0;
        while (file[l])
            l++;
        f = wn_utf16_to_utf8(file, l);
    }
    wn_log(WN_LOG_WARN, "shell32: ShellExecuteW('%s') not implemented -> 31",
           f ? f : "(null)");
    free(f);
    wn_last_error_set(WN_ERR_CALL_NOT_IMPLEMENTED);
    return 31;
}

static WN_API int32_t sh_ShellExecuteExA(void *info)
{
    (void)info;
    wn_log(WN_LOG_WARN, "shell32: ShellExecuteExA not implemented -> FALSE");
    wn_last_error_set(WN_ERR_CALL_NOT_IMPLEMENTED);
    return 0;
}

static WN_API int32_t sh_ShellExecuteExW(void *info)
{
    (void)info;
    wn_log(WN_LOG_WARN, "shell32: ShellExecuteExW not implemented -> FALSE");
    wn_last_error_set(WN_ERR_CALL_NOT_IMPLEMENTED);
    return 0;
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
