/* userenv.c — profile directory + environment blocks.
 *
 * REAL: GetUserProfileDirectory (prefix-backed), CreateEnvironmentBlock
 * (host env + the Windows-style variables WinNux actually models),
 * DestroyEnvironmentBlock.
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
#include <unistd.h>

extern char **environ;

static void profile_win_path(char *out, size_t cap)
{
    const char *user = getenv("USER");
    if (!user || !*user)
        user = "user";
    snprintf(out, cap, "%s/drive_c/users/%s", g_proc.prefix, user);
}

static WN_API int32_t ue_GetUserProfileDirectoryA(uint64_t token, char *buf,
                                                  uint32_t *need)
{
    (void)token;
    char win[1100];
    profile_win_path(win, sizeof win);
    size_t l = strlen(win);
    if (need)
        *need = (uint32_t)(l + 1);
    if (!buf || !need || *need < l + 1) {
        if (need)
            wn_last_error_set(WN_ERR_INSUFFICIENT_BUFFER);
        return 0;
    }
    memcpy(buf, win, l + 1);
    return 1;
}

static WN_API int32_t ue_GetUserProfileDirectoryW(uint64_t token, uint16_t *buf,
                                                  uint32_t *need)
{
    (void)token;
    char win[1100];
    profile_win_path(win, sizeof win);
    uint16_t *w = wn_utf8_to_utf16(win, NULL);
    if (!w)
        return 0;
    size_t l = 0;
    while (w[l])
        l++;
    if (need)
        *need = (uint32_t)(l + 1);
    int32_t ok = 0;
    if (buf && need && *need >= l + 1) {
        memcpy(buf, w, (l + 1) * 2);
        ok = 1;
    } else if (need) {
        wn_last_error_set(WN_ERR_INSUFFICIENT_BUFFER);
    }
    free(w);
    return ok;
}

/* Environment block: UTF-16 "NAME=value\0" entries, terminated by an extra
 * \0. We pass the host environment through (minus our own knobs) plus the
 * standard Windows paths. */
static WN_API int32_t ue_CreateEnvironmentBlock(void **out, uint64_t token,
                                                int32_t inherit)
{
    (void)token;
    (void)inherit;
    if (!out)
        return 0;
    wn_buf b;
    wn_buf_init(&b);
    char prof[1100];
    profile_win_path(prof, sizeof prof);
    char sysroot[1100];
    snprintf(sysroot, sizeof sysroot, "%s/drive_c/windows", g_proc.prefix);
    const char *user = getenv("USER");
    if (!user || !*user)
        user = "user";

    for (char **e = environ; e && *e; e++) {
        if (wn_strcaseprefix(*e, "WINNUX_"))
            continue;
        uint16_t *w = wn_utf8_to_utf16_n(*e, strlen(*e) + 1);
        if (w) {
            wn_buf_append(&b, w, (strlen(*e) + 1) * 2);
            free(w);
        }
    }
    const char *extra[] = {
        NULL,
    };
    (void)extra;
    char kv[1200];
    snprintf(kv, sizeof kv, "USERNAME=%s", user);
    uint16_t *w = wn_utf8_to_utf16(kv, NULL);
    if (w) { wn_buf_append(&b, w, (strlen(kv) + 1) * 2); free(w); }
    char windir[1300];
    snprintf(windir, sizeof windir, "SystemRoot=%s", sysroot);
    w = wn_utf8_to_utf16(windir, NULL);
    if (w) { wn_buf_append(&b, w, (strlen(windir) + 1) * 2); free(w); }
    snprintf(windir, sizeof windir, "USERPROFILE=%s", prof);
    w = wn_utf8_to_utf16(windir, NULL);
    if (w) { wn_buf_append(&b, w, (strlen(windir) + 1) * 2); free(w); }
    snprintf(windir, sizeof windir, "ProgramFiles=%s/drive_c/Program Files",
             g_proc.prefix);
    w = wn_utf8_to_utf16(windir, NULL);
    if (w) { wn_buf_append(&b, w, (strlen(windir) + 1) * 2); free(w); }
    uint16_t term = 0;
    wn_buf_append(&b, &term, 2);
    *out = b.data;
    return 1;
}

static WN_API void ue_DestroyEnvironmentBlock(void *env)
{
    free(env);
}

static WN_API int32_t ue_LoadUserProfileA(uint64_t token, void *lpi, void *out)
{
    (void)token; (void)lpi; (void)out;
    wn_log(WN_LOG_WARN, "userenv: LoadUserProfileA not implemented -> FALSE");
    wn_last_error_set(WN_ERR_CALL_NOT_IMPLEMENTED);
    return 0;
}

const wn_export_entry wn_userenv_exports[] = {
    { "GetUserProfileDirectoryA",  ue_GetUserProfileDirectoryA },
    { "GetUserProfileDirectoryW",  ue_GetUserProfileDirectoryW },
    { "CreateEnvironmentBlock",    ue_CreateEnvironmentBlock },
    { "DestroyEnvironmentBlock",   ue_DestroyEnvironmentBlock },
    { "LoadUserProfileA",          ue_LoadUserProfileA },
    { NULL, NULL },
};
