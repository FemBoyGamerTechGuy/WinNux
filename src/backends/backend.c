/* backend.c — backend selection: WINNUX_BACKEND env, Wayland-first auto. */
#include "wn_backend.h"
#include "wn_log.h"

#include <stdlib.h>
#include <string.h>

extern const wn_backend wn_x11_backend;
extern const wn_backend wn_wayland_backend;

static const wn_backend *g_backend;

const char *wn_backend_pick_name(void)
{
    const char *want = getenv("WINNUX_BACKEND");
    if (want && *want) {
        if (!strcmp(want, "x11"))
            return "x11";
        if (!strcmp(want, "wayland"))
            return "wayland";
    }
    if (getenv("WAYLAND_DISPLAY") && wn_wayland_backend.init)
        return "wayland";
    return "x11";
}

int wn_backend_init(void)
{
    const char *want = getenv("WINNUX_BACKEND");
    const wn_backend *candidates[2];
    int n = 0;

    if (g_backend)
        return 0;

    if (want && !strcmp(want, "x11")) {
        candidates[n++] = &wn_x11_backend;
    } else if (want && !strcmp(want, "wayland")) {
        candidates[n++] = &wn_wayland_backend;
    } else {
        /* auto: prefer Wayland when a display exists, else X11. */
        if (getenv("WAYLAND_DISPLAY"))
            candidates[n++] = &wn_wayland_backend;
        candidates[n++] = &wn_x11_backend;
    }

    for (int i = 0; i < n; i++) {
        if (candidates[i]->init && candidates[i]->init() == 0) {
            g_backend = candidates[i];
            wn_log(WN_LOG_INFO, "backend: %s active", g_backend->name);
            return 0;
        }
        wn_log(WN_LOG_INFO, "backend: %s unavailable, trying next",
               candidates[i]->name);
    }
    wn_log(WN_LOG_ERR, "backend: no windowing backend available (GUI disabled)");
    return -1;
}

const wn_backend *wn_backend_get(void)
{
    return g_backend;
}
