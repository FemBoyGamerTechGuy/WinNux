/* user32.c — builtin user32.dll: window classes, windows, message queues,
 * timers, input translation. Window pixels live in per-window BGRA buffers
 * presented through the backend abstraction (never X11/Wayland directly).
 *
 * Threading model v1 (documented): one GUI thread; the message queue is
 * process-global. Cross-thread PostMessage wakes the queue via eventfd.
 */
#include "wn_dll.h"
#include "wn_backend.h"
#include "wn_process.h"
#include "wn_handle.h"
#include "wn_log.h"
#include "wn_util.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <time.h>
#include <unistd.h>

/* --- structures -------------------------------------------------------------- */

#define WN_USER32_MAX_WINDOWS 64
#define WN_MSG_QUEUE_DEPTH   128

typedef struct wn_msg {
    uint64_t hwnd;
    uint32_t message;
    uint64_t wparam;
    int64_t  lparam;
    uint32_t time;
    int32_t  pt_x, pt_y;
} wn_msg;

typedef struct wn_wndclass {
    char name[64];
    WN_API uint64_t (*proc)(uint64_t, uint32_t, uint64_t, int64_t);
    uint32_t style;
    int used;
} wn_wndclass;

typedef struct wn_timer {
    uint64_t hwnd;
    uintptr_t id;
    uint64_t period_ms;
    uint64_t next_fire;
    WN_API void (*proc)(uint64_t, uint32_t, uintptr_t, uint32_t);
    int active;
} wn_timer;

typedef struct wn_window {
    wn_bwin *bwin;            /* backend window */
    wn_wndclass *cls;
    uint64_t hinstance;
    uint64_t userdata;
    char title[128];
    int visible;
    int in_destroy;
    int paint_pending;
    struct { int l, t, r, b; } dirty;    /* damage rect; l<0 = clean */
} wn_window;

/* Documented globals: GUI state (single-GUI-thread model for v1). */
static wn_wndclass g_classes[32];
static wn_timer g_timers[32];
static wn_msg g_queue[WN_MSG_QUEUE_DEPTH];
static int g_q_head, g_q_count;
static int g_msg_fd = -1;
static int g_backend_up;
static int g_quit_posted;
static uint32_t g_quit_code;
static uint64_t g_paint_counter;

/* hwnd registry (parallel to the handle table, for reverse lookup). */
static struct { wn_window *win; wn_handle h; } g_hwnds[WN_USER32_MAX_WINDOWS];
static int g_hwnd_count;
/* bwin->(backend private window) registry for backend event dispatch. */
static struct { wn_bwin *bwin; void *backend_priv; } g_bwins[WN_USER32_MAX_WINDOWS];
static int g_bwin_count;

/* --- queue -------------------------------------------------------------------- */

static void queue_push(const wn_msg *m)
{
    if (g_q_count >= WN_MSG_QUEUE_DEPTH) {
        wn_log(WN_LOG_WARN, "user32: message queue overflow (dropped 0x%x)",
               m->message);
        return;
    }
    g_queue[(g_q_head + g_q_count) % WN_MSG_QUEUE_DEPTH] = *m;
    g_q_count++;
    if (g_msg_fd >= 0) {
        uint64_t one = 1;
        (void)!write(g_msg_fd, &one, 8);
    }
}

static int queue_pop(wn_msg *out)
{
    if (g_q_count == 0)
        return 0;
    *out = g_queue[g_q_head];
    g_q_head = (g_q_head + 1) % WN_MSG_QUEUE_DEPTH;
    g_q_count--;
    return 1;
}

static void post_msg(uint64_t hwnd, uint32_t msg, uint64_t wp, int64_t lp)
{
    wn_msg m = { .hwnd = hwnd, .message = msg, .wparam = wp, .lparam = lp,
                 .time = (uint32_t)(wn_monotonic_ns() / 1000000) };
    queue_push(&m);
}

static wn_window *win_from_hwnd(uint64_t hwnd)
{
    if (!hwnd)
        return NULL;
    wn_object *o = wn_handle_get((wn_handle)(uintptr_t)hwnd, WN_HTYPE_GFX);
    return o ? o->ptr : NULL;
}

static wn_handle hwnd_of_window(wn_window *w)
{
    for (int i = 0; i < g_hwnd_count; i++)
        if (g_hwnds[i].win == w)
            return g_hwnds[i].h;
    return (wn_handle)0;
}

static wn_handle register_hwnd(wn_window *win)
{
    wn_handle h = wn_handle_alloc(WN_HTYPE_GFX, win);
    if (g_hwnd_count < WN_USER32_MAX_WINDOWS) {
        g_hwnds[g_hwnd_count].win = win;
        g_hwnds[g_hwnd_count].h = h;
        g_hwnd_count++;
    }
    return h;
}

/* Called from the X11 backend: map backend-private window -> wn_bwin. */
wn_bwin *wn_user32_bwin_for(void *backend_priv)
{
    for (int i = 0; i < g_bwin_count; i++)
        if (g_bwins[i].backend_priv == backend_priv)
            return g_bwins[i].bwin;
    return NULL;
}

/* --- input translation --------------------------------------------------------- */

uint32_t wn_user32_vk_from_keysym(uint32_t ks)
{
    if (ks >= 0x20 && ks < 0x7F)
        return ks;                        /* ASCII == VK for printable keys */
    if (ks >= 0xFFBE && ks <= 0xFFC9)
        return 0x70 + (ks - 0xFFBE);      /* F1..F12 */
    switch (ks) {
    case 0xFF08: return 0x08;             /* BackSpace */
    case 0xFF09: return 0x09;             /* Tab */
    case 0xFF0D: return 0x0D;             /* Return */
    case 0xFF1B: return 0x1B;             /* Escape */
    case 0xFF50: return 0x24;             /* Home */
    case 0xFF51: return 0x25;             /* Left */
    case 0xFF52: return 0x26;             /* Up */
    case 0xFF53: return 0x27;             /* Right */
    case 0xFF54: return 0x28;             /* Down */
    case 0xFF55: return 0x21;             /* PgUp */
    case 0xFF56: return 0x22;             /* PgDn */
    case 0xFF57: return 0x23;             /* End */
    case 0xFF63: return 0x2D;             /* Insert */
    case 0xFFFF: return 0x2E;             /* Delete */
    case 0xFFE1: case 0xFFE2: return 0x10;
    case 0xFFE3: case 0xFFE4: return 0x11;
    case 0xFFE9: case 0xFFEA: return 0x12;
    default: return 0;
    }
}

/* Backend event callback: raw events -> Win32 messages. */
void wn_backend_event_cb(const wn_backend_event *ev)
{
    wn_bwin *b = ev->win;
    if (!b)
        return;
    wn_window *w = b->userdata;
    if (!w || w->in_destroy)
        return;
    wn_handle hwnd = hwnd_of_window(w);
    if (!hwnd)
        return;
    uint64_t h = (uint64_t)(uintptr_t)hwnd;

    switch (ev->type) {
    case WN_BEV_EXPOSE:
        if (w->dirty.l < 0) {
            w->dirty.l = ev->x; w->dirty.t = ev->y;
            w->dirty.r = ev->x + ev->val; w->dirty.b = ev->y + ev->val2;
        } else {
            if (ev->x < w->dirty.l) w->dirty.l = ev->x;
            if (ev->y < w->dirty.t) w->dirty.t = ev->y;
            if (ev->x + ev->val > w->dirty.r) w->dirty.r = ev->x + ev->val;
            if (ev->y + ev->val2 > w->dirty.b) w->dirty.b = ev->y + ev->val2;
        }
        post_msg(h, WN_WM_PAINT, 0, 0);
        break;
    case WN_BEV_RESIZE:
        if (b->pixels) {
            b->width = ev->x;
            b->height = ev->y;
            b->stride = ev->x * 4;
            free(b->pixels);
            b->pixels = wn_xmalloc((size_t)ev->x * ev->y * 4 + 64);
            memset(b->pixels, 0xFF, (size_t)ev->x * ev->y * 4);
        }
        post_msg(h, WN_WM_SIZE, 0,
                 (int64_t)(((uint64_t)(uint16_t)ev->x) |
                           ((uint64_t)(uint16_t)ev->y << 16)));
        break;
    case WN_BEV_CLOSE:
        post_msg(h, WN_WM_CLOSE, 0, 0);
        break;
    case WN_BEV_KEY: {
        uint32_t vk = wn_user32_vk_from_keysym((uint32_t)ev->val);
        if (vk)
            post_msg(h, WN_WM_KEYDOWN, vk, 0);
        break;
    }
    case WN_BEV_TEXT:
        post_msg(h, WN_WM_CHAR, (uint64_t)(uint32_t)ev->val, 0);
        break;
    case WN_BEV_MOUSE_MOVE:
        post_msg(h, WN_WM_MOUSEMOVE, 0,
                 (int64_t)(((uint64_t)(uint16_t)ev->x) |
                           ((uint64_t)(uint16_t)ev->y << 16)));
        break;
    case WN_BEV_MOUSE_BUTTON: {
        uint32_t msg = 0;
        uint64_t wp = 1 /* MK_LBUTTON */;
        if (ev->val2 == 1)      msg = ev->val ? WN_WM_LBUTTONDOWN : WN_WM_LBUTTONUP;
        else if (ev->val2 == 3) { msg = ev->val ? WN_WM_RBUTTONDOWN : WN_WM_RBUTTONUP; wp = 2; }
        if (msg)
            post_msg(h, msg, wp,
                     (int64_t)(((uint64_t)(uint16_t)ev->x) |
                               ((uint64_t)(uint16_t)ev->y << 16)));
        break;
    }
    default:
        break;
    }
}

/* --- window management ------------------------------------------------------------ */

static int ensure_gui(void)
{
    static int state = 0;
    if (state == 1)
        return 0;
    if (state == -1)
        return -1;
    if (wn_backend_init() != 0) {
        state = -1;
        return -1;
    }
    g_backend_up = 1;
    g_msg_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    return 0;
}

static WN_API int32_t u32_ShowWindow(uint64_t hwnd, int32_t cmd)
{
    wn_window *w = win_from_hwnd(hwnd);
    if (!w || !w->bwin)
        return 0;
    const wn_backend *be = wn_backend_get();
    int was_visible = w->visible;
    if (be && be->win_show)
        be->win_show(w->bwin);
    if (cmd != 0 /* SW_HIDE */)
        w->visible = 1;
    else
        w->visible = 0;
    return was_visible;
}

static WN_API uint64_t u32_RegisterClassA(const void *wc)
{
    /* WNDCLASSA x64: style@0(4), lpfnWndProc@8(8), cbClsExtra@0x10,
     * cbWndExtra@0x14, hInstance@0x18, ..., lpszClassName@0x40. */
    const uint8_t *p = wc;
    const char *name = *(const char **)(const void *)(p + 0x40);
    WN_API uint64_t (*proc)(uint64_t, uint32_t, uint64_t, int64_t) =
        (WN_API uint64_t (*)(uint64_t, uint32_t, uint64_t, int64_t))
        *(const void **)(const void *)(p + 8);
    if (!name || !proc) {
        wn_last_error_set(WN_ERR_INVALID_PARAMETER);
        return 0;
    }
    for (int i = 0; i < 32; i++) {
        if (g_classes[i].used && wn_strcaseeq(g_classes[i].name, name)) {
            wn_last_error_set(1410 /* ERROR_CLASS_ALREADY_EXISTS */);
            return 0;
        }
    }
    for (int i = 0; i < 32; i++) {
        if (!g_classes[i].used) {
            snprintf(g_classes[i].name, sizeof g_classes[i].name, "%s", name);
            g_classes[i].proc = proc;
            g_classes[i].style = *(const uint32_t *)(const void *)p;
            g_classes[i].used = 1;
            wn_log(WN_LOG_DEBUG, "user32: class '%s' registered (proc %p)",
                   name, (void *)proc);
            return 0xC000 + (uint64_t)i;
        }
    }
    wn_last_error_set(WN_ERR_NOT_ENOUGH_MEMORY);
    return 0;
}

static WN_API uint64_t u32_RegisterClassW(const void *wc)
{
    const uint8_t *p = wc;
    const uint16_t *wname = *(const uint16_t **)(const void *)(p + 0x40);
    char name[128] = "";
    if (wname) {
        char *a = wn_utf16_to_utf8(wname, 256);
        if (a) {
            snprintf(name, sizeof name, "%s", a);
            free(a);
        }
    }
    /* ANSI struct with the same proc pointer: wide/ANSI split is not yet
     * done (documented); the window proc is called either way. */
    struct {
        uint32_t style; uint32_t pad;
        void *proc; uint32_t cbCls, cbWnd; uint32_t pad2;
        uint64_t hinst;
        void *icon, *cursor, *brush;
        const char *menu;
        const char *name;
    } wcA = { 0 };
    wcA.style = *(const uint32_t *)(const void *)p;
    wcA.proc = *(void **)(const void *)(p + 8);
    wcA.hinst = *(const uint64_t *)(const void *)(p + 0x18);
    wcA.name = name;
    return u32_RegisterClassA(&wcA);
}

static WN_API uint64_t u32_CreateWindowExA(uint32_t ex_style, const char *cls_name,
                                           const char *title, uint32_t style,
                                           int x, int y, int w, int h,
                                           uint64_t parent, uint64_t menu,
                                           uint64_t hinst, void *param)
{
    (void)ex_style; (void)parent; (void)menu; (void)x; (void)y;
    if (ensure_gui() != 0) {
        wn_last_error_set(WN_ERR_NOT_SUPPORTED);
        return 0;
    }
    wn_wndclass *cls = NULL;
    for (int i = 0; i < 32; i++)
        if (g_classes[i].used && wn_strcaseeq(g_classes[i].name, cls_name))
            cls = &g_classes[i];
    if (!cls) {
        wn_last_error_set(1407 /* ERROR_CLASS_DOES_NOT_EXIST */);
        return 0;
    }
    const wn_backend *be = wn_backend_get();
    if (!be || !be->win_create) {
        wn_last_error_set(WN_ERR_NOT_SUPPORTED);
        return 0;
    }
    wn_window *win = wn_xcalloc(1, sizeof *win);
    win->cls = cls;
    win->hinstance = hinst;
    win->userdata = (uint64_t)(uintptr_t)param;
    win->dirty.l = -1;
    snprintf(win->title, sizeof win->title, "%s", title ? title : "");
    if (w <= 0) w = 640;
    if (h <= 0) h = 480;
    win->bwin = be->win_create(w, h, win->title, win);
    if (!win->bwin) {
        free(win);
        wn_last_error_set(WN_ERR_NOT_ENOUGH_MEMORY);
        return 0;
    }
    win->bwin->pixels = wn_xmalloc((size_t)w * h * 4 + 64);
    memset(win->bwin->pixels, 0xFF, (size_t)w * h * 4);
    win->bwin->stride = w * 4;

    wn_handle hwnd = register_hwnd(win);
    if (g_bwin_count < WN_USER32_MAX_WINDOWS) {
        g_bwins[g_bwin_count].bwin = win->bwin;
        g_bwins[g_bwin_count].backend_priv = win->bwin->priv;
        g_bwin_count++;
    }

    if (style & 0x10000000 /* WS_VISIBLE */)
        u32_ShowWindow((uint64_t)(uintptr_t)hwnd, 5);

    post_msg((uint64_t)(uintptr_t)hwnd, WN_WM_CREATE, 0, 0);
    wn_log(WN_LOG_DEBUG, "user32: CreateWindow('%s') hwnd=0x%llx %dx%d",
           cls_name, (unsigned long long)(uintptr_t)hwnd, w, h);
    return (uint64_t)(uintptr_t)hwnd;
}

static WN_API uint64_t u32_CreateWindowExW(uint32_t ex, const uint16_t *cls,
                                           const uint16_t *title, uint32_t style,
                                           int x, int y, int w, int h,
                                           uint64_t parent, uint64_t menu,
                                           uint64_t hinst, void *param)
{
    char *c = cls ? wn_utf16_to_utf8(cls, 256) : NULL;
    char *t = title ? wn_utf16_to_utf8(title, 256) : NULL;
    uint64_t r = u32_CreateWindowExA(ex, c ? c : "", t ? t : "", style, x, y,
                                     w, h, parent, menu, hinst, param);
    free(c);
    free(t);
    return r;
}

static WN_API int32_t u32_DestroyWindow(uint64_t hwnd)
{
    wn_window *w = win_from_hwnd(hwnd);
    if (!w)
        return 0;
    if (w->in_destroy)
        return 1;
    w->in_destroy = 1;
    /* WM_DESTROY goes through the proc directly (in-order with calls). */
    if (w->cls && w->cls->proc)
        w->cls->proc(hwnd, WN_WM_DESTROY, 0, 0);
    const wn_backend *be = wn_backend_get();
    if (be && be->win_destroy && w->bwin) {
        for (int i = 0; i < g_bwin_count; i++) {
            if (g_bwins[i].bwin == w->bwin) {
                g_bwins[i] = g_bwins[g_bwin_count - 1];
                g_bwin_count--;
                break;
            }
        }
        be->win_destroy(w->bwin);
    }
    for (int i = 0; i < g_hwnd_count; i++) {
        if (g_hwnds[i].win == w) {
            g_hwnds[i] = g_hwnds[g_hwnd_count - 1];
            g_hwnd_count--;
            break;
        }
    }
    /* The handle table owns the wn_window object (single ref). */
    wn_handle_close((wn_handle)(uintptr_t)hwnd);
    return 1;
}

static WN_API void u32_PostQuitMessage(int32_t code)
{
    g_quit_posted = 1;
    g_quit_code = (uint32_t)code;
    if (g_msg_fd >= 0) {
        uint64_t one = 1;
        (void)!write(g_msg_fd, &one, 8);
    }
}

/* Generate WM_TIMER for expired timers. */
static void fire_timers(void)
{
    uint64_t now = wn_monotonic_ns() / 1000000;
    for (int i = 0; i < 32; i++) {
        if (!g_timers[i].active || g_timers[i].next_fire > now)
            continue;
        g_timers[i].next_fire = now + g_timers[i].period_ms;
        if (g_timers[i].proc) {
            g_timers[i].proc(g_timers[i].hwnd, WN_WM_TIMER,
                             g_timers[i].id, 0);
        } else {
            post_msg(g_timers[i].hwnd, WN_WM_TIMER, g_timers[i].id, 0);
        }
    }
}

/* Generate WM_PAINT for dirty visible windows. */
static void generate_paints(void)
{
    for (int i = 0; i < g_hwnd_count; i++) {
        wn_window *w = g_hwnds[i].win;
        if (w->visible && w->dirty.l >= 0 && !w->in_destroy &&
            !w->paint_pending) {
            post_msg((uint64_t)(uintptr_t)g_hwnds[i].h, WN_WM_PAINT, 0, 0);
            w->paint_pending = 1;
            g_paint_counter++;
        }
    }
}

/* --- helpers used by gdi32 ------------------------------------------------------- */

void wn_user32_validate_paint(uint64_t hwnd)
{
    wn_window *w = win_from_hwnd(hwnd);
    if (w) {
        w->dirty.l = -1;
        w->paint_pending = 0;
    }
}

wn_bwin *wn_user32_bwin_of(uint64_t hwnd)
{
    wn_window *w = win_from_hwnd(hwnd);
    return w ? w->bwin : NULL;
}

void wn_user32_paint_rect(uint64_t hwnd, int *l, int *t, int *r, int *b)
{
    wn_window *w = win_from_hwnd(hwnd);
    if (!w || w->dirty.l < 0 || !w->bwin) {
        *l = 0; *t = 0;
        *r = w && w->bwin ? w->bwin->width : 0;
        *b = w && w->bwin ? w->bwin->height : 0;
        return;
    }
    *l = w->dirty.l; *t = w->dirty.t;
    *r = w->dirty.r; *b = w->dirty.b;
}

static WN_API int32_t u32_GetMessageA(void *msg_out, uint64_t hwnd,
                                      uint32_t min, uint32_t max)
{
    (void)hwnd; (void)min; (void)max;
    if (ensure_gui() != 0)
        return -1;
    const wn_backend *be = wn_backend_get();
    for (;;) {
        wn_msg m;
        while (queue_pop(&m)) {
            if (g_quit_posted)
                break;
            /* Fill MSG: hwnd@0, message@8, wParam@0x10, lParam@0x18,
             * time@0x20, pt@0x24. */
            uint8_t *o = msg_out;
            memset(o, 0, 0x30);
            *(uint64_t *)(void *)(o + 0) = m.hwnd;
            *(uint32_t *)(void *)(o + 8) = m.message;
            *(uint64_t *)(void *)(o + 0x10) = m.wparam;
            *(int64_t *)(void *)(o + 0x18) = m.lparam;
            *(uint32_t *)(void *)(o + 0x20) = m.time;
            return 1;
        }
        if (g_quit_posted) {
            uint8_t *o = msg_out;
            memset(o, 0, 0x30);
            *(uint32_t *)(void *)(o + 8) = WN_WM_QUIT;
            *(uint64_t *)(void *)(o + 0x10) = g_quit_code;
            return 0;                   /* WM_QUIT */
        }
        fire_timers();
        generate_paints();
        wn_msg m2;
        if (queue_pop(&m2) && m2.message) {
            uint8_t *o = msg_out;
            memset(o, 0, 0x30);
            *(uint64_t *)(void *)(o + 0) = m2.hwnd;
            *(uint32_t *)(void *)(o + 8) = m2.message;
            *(uint64_t *)(void *)(o + 0x10) = m2.wparam;
            *(int64_t *)(void *)(o + 0x18) = m2.lparam;
            *(uint32_t *)(void *)(o + 0x20) = m2.time;
            return 1;
        }
        /* Block until a posted message, a timer deadline, or a backend
         * event. Waiting happens on the wake eventfd with the timer
         * deadline (capped), then backend events are drained without
         * blocking — a pure pump(-1) would starve timers forever. */
        uint64_t now = wn_monotonic_ns() / 1000000;
        int wait = 100;
        for (int i = 0; i < 32; i++) {
            if (g_timers[i].active && g_timers[i].next_fire > now) {
                int ms = (int)(g_timers[i].next_fire - now);
                if (ms < wait)
                    wait = ms;
            }
        }
        if (g_msg_fd >= 0) {
            struct pollfd pfd = { .fd = g_msg_fd, .events = POLLIN };
            poll(&pfd, 1, wait);
            uint64_t v;
            (void)!read(g_msg_fd, &v, 8);
        } else {
            struct timespec ts = { .tv_sec = 0,
                                   .tv_nsec = (long)wait * 1000000L };
            nanosleep(&ts, NULL);
        }
        if (be && be->pump)
            be->pump(0);
    }
}

static WN_API int32_t u32_PeekMessageA(void *msg_out, uint64_t hwnd,
                                       uint32_t min, uint32_t max,
                                       uint32_t remove)
{
    (void)hwnd; (void)min; (void)max;   /* filters unsupported yet */
    wn_msg m;
    if (queue_pop(&m) && m.message) {
        uint8_t *o = msg_out;
        memset(o, 0, 0x30);
        *(uint64_t *)(void *)(o + 0) = m.hwnd;
        *(uint32_t *)(void *)(o + 8) = m.message;
        *(uint64_t *)(void *)(o + 0x10) = m.wparam;
        *(int64_t *)(void *)(o + 0x18) = m.lparam;
        *(uint32_t *)(void *)(o + 0x20) = m.time;
        (void)remove;
        return 1;
    }
    if (g_quit_posted) {
        uint8_t *o = msg_out;
        memset(o, 0, 0x30);
        *(uint32_t *)(void *)(o + 8) = WN_WM_QUIT;
        *(uint64_t *)(void *)(o + 0x10) = g_quit_code;
        return 0;
    }
    return 0;
}

static WN_API uint64_t u32_DispatchMessageA(const void *msg)
{
    const uint8_t *p = msg;
    uint64_t hwnd = *(const uint64_t *)(const void *)(p + 0);
    uint32_t message = *(const uint32_t *)(const void *)(p + 8);
    uint64_t wp = *(const uint64_t *)(const void *)(p + 0x10);
    int64_t lp = *(const int64_t *)(const void *)(p + 0x18);
    wn_window *w = win_from_hwnd(hwnd);
    if (w && w->cls && w->cls->proc)
        return w->cls->proc(hwnd, message, wp, lp);
    return 0;
}

static WN_API uint64_t u32_DefWindowProcA(uint64_t hwnd, uint32_t msg,
                                          uint64_t wp, int64_t lp)
{
    switch (msg) {
    case WN_WM_CLOSE:
        u32_DestroyWindow(hwnd);
        return 0;
    case WN_WM_PAINT: {
        /* Validate the update region by clearing the dirty rect. */
        wn_window *w = win_from_hwnd(hwnd);
        if (w)
            w->dirty.l = -1;
        return 0;
    }
    default:
        return 0;
    }
    (void)wp; (void)lp;
}

static WN_API int32_t u32_PostMessageA(uint64_t hwnd, uint32_t msg,
                                       uint64_t wp, int64_t lp)
{
    post_msg(hwnd, msg, wp, lp);
    return 1;
}

static WN_API uint64_t u32_SendMessageA(uint64_t hwnd, uint32_t msg,
                                        uint64_t wp, int64_t lp)
{
    wn_window *w = win_from_hwnd(hwnd);
    if (w && w->cls && w->cls->proc)
        return w->cls->proc(hwnd, msg, wp, lp);
    return u32_DefWindowProcA(hwnd, msg, wp, lp);
}

static WN_API uintptr_t u32_SetTimer(uint64_t hwnd, uintptr_t id,
                                     uint32_t ms,
                                     WN_API void (*proc)(uint64_t, uint32_t,
                                                         uintptr_t, uint32_t))
{
    for (int i = 0; i < 32; i++) {
        if (!g_timers[i].active ||
            (g_timers[i].hwnd == hwnd && g_timers[i].id == id)) {
            g_timers[i].hwnd = hwnd;
            g_timers[i].id = id;
            g_timers[i].period_ms = ms ? ms : 10;
            g_timers[i].next_fire = wn_monotonic_ns() / 1000000 + ms;
            g_timers[i].proc = proc;
            g_timers[i].active = 1;
            return id;
        }
    }
    return 0;
}

static WN_API int32_t u32_KillTimer(uint64_t hwnd, uintptr_t id)
{
    for (int i = 0; i < 32; i++) {
        if (g_timers[i].active && g_timers[i].hwnd == hwnd &&
            g_timers[i].id == id) {
            g_timers[i].active = 0;
            return 1;
        }
    }
    return 0;
}

static WN_API int32_t u32_TranslateMessage(const void *msg)
{
    (void)msg;
    return 0;   /* WM_CHAR is generated directly by the backend */
}

/* RECT: left, top, right, bottom (4 LONGs). */
static WN_API int32_t u32_GetClientRect(uint64_t hwnd, void *rect)
{
    wn_window *w = win_from_hwnd(hwnd);
    if (!w || !rect)
        return 0;
    int32_t *r = rect;
    r[0] = 0;
    r[1] = 0;
    r[2] = w->bwin ? w->bwin->width : 0;
    r[3] = w->bwin ? w->bwin->height : 0;
    return 1;
}

static WN_API int32_t u32_GetWindowRect(uint64_t hwnd, void *rect)
{
    wn_window *w = win_from_hwnd(hwnd);
    if (!w || !rect)
        return 0;
    int32_t *r = rect;
    r[0] = 0; r[1] = 0;
    r[2] = w->bwin ? w->bwin->width : 0;
    r[3] = w->bwin ? w->bwin->height : 0;
    return 1;
}

static WN_API int32_t u32_SetWindowTextA(uint64_t hwnd, const char *text)
{
    wn_window *w = win_from_hwnd(hwnd);
    if (!w)
        return 0;
    snprintf(w->title, sizeof w->title, "%s", text ? text : "");
    const wn_backend *be = wn_backend_get();
    if (be && be->win_set_title && w->bwin)
        be->win_set_title(w->bwin, w->title);
    return 1;
}

static WN_API int32_t u32_IsWindow(uint64_t hwnd)
{
    return win_from_hwnd(hwnd) != NULL;
}

static WN_API int32_t u32_UpdateWindow(uint64_t hwnd)
{
    wn_window *w = win_from_hwnd(hwnd);
    if (!w || !w->bwin || !w->visible)
        return 0;
    u32_SendMessageA(hwnd, WN_WM_PAINT, 0, 0);
    return 1;
}

/* Paint counter (used by tests to verify WM_PAINT delivery). */
uint64_t wn_user32_paint_count(void)
{
    return g_paint_counter;
}

/* DC lifetime functions live in gdi32.c implementation-wise but are
 * exported from user32.dll, exactly like real Windows. */
extern WN_API wn_handle g32_BeginPaint(uint64_t hwnd, void *ps);
extern WN_API int32_t g32_EndPaint(uint64_t hwnd, const void *ps);
extern WN_API wn_handle g32_GetDC(uint64_t hwnd);
extern WN_API int32_t g32_ReleaseDC(uint64_t hwnd, wn_handle hdc);
extern WN_API int32_t g32_FillRect(wn_handle hdc, const void *rect, wn_handle brush);

/* --- export table ----------------------------------------------------------------- */


/* MessageBox: no dialog engine yet, so the box is PRINTED (loudly) and we
 * answer IDOK. This keeps apps running and makes their complaints visible
 * in the log - a deliberate diagnostic aid, not a fake window. */
static WN_API int32_t u32_MessageBoxA(uint64_t hwnd, const char *text,
                                      const char *caption, uint32_t type)
{
    (void)hwnd;
    (void)type;
    wn_log(WN_LOG_ERR, "MSGBOX '%s': %s",
           caption ? caption : "", text ? text : "");
    return 1;   /* IDOK */
}

static WN_API int32_t u32_MessageBoxW(uint64_t hwnd, const uint16_t *text,
                                      const uint16_t *caption, uint32_t type)
{
    (void)hwnd;
    (void)type;
    char *t = NULL, *c = NULL;
    if (text) {
        size_t l = 0;
        while (text[l]) l++;
        t = wn_utf16_to_utf8(text, l);
    }
    if (caption) {
        size_t l = 0;
        while (caption[l]) l++;
        c = wn_utf16_to_utf8(caption, l);
    }
    wn_log(WN_LOG_ERR, "MSGBOX '%s': %s", c ? c : "", t ? t : "");
    free(t);
    free(c);
    return 1;   /* IDOK */
}

const wn_export_entry wn_user32_exports[] = {
    { "BeginPaint", g32_BeginPaint },
    { "CreateWindowExA", u32_CreateWindowExA },
    { "CreateWindowExW", u32_CreateWindowExW },
    { "DefWindowProcA", u32_DefWindowProcA },
    { "DestroyWindow", u32_DestroyWindow },
    { "DispatchMessageA", u32_DispatchMessageA },
    { "EndPaint", g32_EndPaint },
    { "GetClientRect", u32_GetClientRect },
    { "FillRect", g32_FillRect },
    { "GetDC", g32_GetDC },
    { "GetMessageA", u32_GetMessageA },
    { "GetWindowRect", u32_GetWindowRect },
    { "IsWindow", u32_IsWindow },
    { "KillTimer", u32_KillTimer },
    { "PeekMessageA", u32_PeekMessageA },
    { "PostMessageA", u32_PostMessageA },
    { "PostQuitMessage", u32_PostQuitMessage },
    { "RegisterClassA", u32_RegisterClassA },
    { "ReleaseDC", g32_ReleaseDC },
    { "RegisterClassW", u32_RegisterClassW },
    { "SendMessageA", u32_SendMessageA },
    { "SetTimer", u32_SetTimer },
    { "SetWindowTextA", u32_SetWindowTextA },
    { "ShowWindow", u32_ShowWindow },
    { "TranslateMessage", u32_TranslateMessage },
    { "UpdateWindow", u32_UpdateWindow },
    { "MessageBoxA", u32_MessageBoxA },
    { "MessageBoxW", u32_MessageBoxW },
    { NULL, NULL },
};
