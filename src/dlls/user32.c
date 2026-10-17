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
    wn_bwin *bwin;            /* backend window (top-level) or child surface */
    wn_wndclass *cls;
    uint64_t hinstance;
    uint64_t userdata;
    char title[128];
    int visible;
    int in_destroy;
    int paint_pending;
    struct { int l, t, r, b; } dirty;    /* damage rect; l<0 = clean */
    /* child window support */
    uint64_t parent;          /* 0 = top level */
    int wx, wy;               /* position in parent (pixels) */
    int cw, ch;               /* size (pixels) */
    uint64_t id;              /* control id (HMENU slot) */
    int is_child;
    /* dialog support */
    int is_dialog;
    int dlg_done;
    int64_t dlg_result;
    uint64_t dlgproc;
    uint64_t dlg_param;
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

static wn_wndclass *builtin_control_class(const char *name);
static void compose_child(wn_window *child);

static WN_API uint64_t u32_CreateWindowExA(uint32_t ex_style, const char *cls_name,
                                           const char *title, uint32_t style,
                                           int x, int y, int w, int h,
                                           uint64_t parent, uint64_t menu,
                                           uint64_t hinst, void *param)
{
    if (ensure_gui() != 0 && !parent) {
        wn_last_error_set(WN_ERR_NOT_SUPPORTED);
        return 0;
    }
    wn_wndclass *cls = NULL;
    for (int i = 0; i < 32; i++)
        if (g_classes[i].used && wn_strcaseeq(g_classes[i].name, cls_name))
            cls = &g_classes[i];
    if (!cls) {
        cls = builtin_control_class(cls_name);
        if (!cls) {
            wn_last_error_set(1407 /* ERROR_CLASS_DOES_NOT_EXIST */);
            return 0;
        }
    }
    if (parent) {
        wn_window *pw = win_from_hwnd(parent);
        if (!pw) {
            wn_last_error_set(WN_ERR_INVALID_HANDLE);
            return 0;
        }
        /* Child window: own offscreen surface, composed onto the parent. */
        wn_window *win = wn_xcalloc(1, sizeof *win);
        win->cls = cls;
        win->hinstance = hinst;
        win->userdata = (uint64_t)(uintptr_t)param;
        win->parent = parent;
        win->is_child = 1;
        win->id = menu;
        win->wx = x;
        win->wy = y;
        win->cw = w > 0 ? w : 64;
        win->ch = h > 0 ? h : 20;
        snprintf(win->title, sizeof win->title, "%s", title ? title : "");
        win->bwin = wn_xcalloc(1, sizeof(wn_bwin));
        win->bwin->width = win->cw;
        win->bwin->height = win->ch;
        win->bwin->stride = win->cw * 4;
        win->bwin->pixels = wn_xmalloc((size_t)win->cw * win->ch * 4 + 64);
        memset(win->bwin->pixels, 0xFF, (size_t)win->cw * win->ch * 4);
        wn_handle hwnd = register_hwnd(win);
        (void)ex_style;
        post_msg((uint64_t)(uintptr_t)hwnd, WN_WM_CREATE, 0, 0);
        wn_log(WN_LOG_DEBUG, "user32: CreateWindow child '%s' id=%llu "
               "hwnd=0x%llx %dx%d at %d,%d", cls_name,
               (unsigned long long)menu, (unsigned long long)(uintptr_t)hwnd,
               win->cw, win->ch, x, y);
        return (uint64_t)(uintptr_t)hwnd;
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
    /* Destroy children first (Windows order). */
    for (int i = 0; i < g_hwnd_count; i++) {
        wn_window *c = g_hwnds[i].win;
        if (c && c->parent == hwnd && !c->in_destroy)
            u32_DestroyWindow((uint64_t)(uintptr_t)g_hwnds[i].h);
    }
    /* WM_DESTROY goes through the proc directly (in-order with calls). */
    if (w->cls && w->cls->proc)
        w->cls->proc(hwnd, WN_WM_DESTROY, 0, 0);
    if (w->is_child) {
        /* Child surfaces are ours; the backend never saw them. */
        free(w->bwin->pixels);
        free(w->bwin);
        w->bwin = NULL;
    }
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


/* ========================================================================== */
/* Builtin control classes + dialog engine                                     */
/* ========================================================================== */

extern WN_API int32_t g32_TextOutA(wn_handle hdc, int x, int y,
                                   const char *s, int32_t count);
extern WN_API uint32_t g32_SetTextColor(wn_handle hdc, uint32_t color);
extern WN_API int32_t g32_SetBkMode(wn_handle hdc, int32_t mode);
extern WN_API wn_handle g32_CreateSolidBrush(uint32_t color);
extern WN_API wn_handle g32_SelectObject(wn_handle hdc, wn_handle obj);

#define WN_WM_PAINT      0x000F
#define WN_WM_COMMAND    0x0111
#define WN_WM_INITDIALOG 0x0110
#define WN_WM_SETTEXT    0x000C
#define WN_WM_GETTEXT    0x000D
#define WN_BS_DEFPUSHBUTTON 0x0001
#define WN_WS_CHILD      0x40000000

/* Blit a child surface onto its parent (same 32bpp BGRA layout). */
static void compose_child(wn_window *child)
{
    if (!child || !child->parent || !child->bwin)
        return;
    wn_window *pw = win_from_hwnd(child->parent);
    if (!pw || !pw->bwin || !pw->bwin->pixels || !child->bwin->pixels)
        return;
    int cw = child->bwin->width, ch = child->bwin->height;
    int pw_w = pw->bwin->width, pw_h = pw->bwin->height;
    for (int row = 0; row < ch; row++) {
        int py = child->wy + row;
        if (py < 0 || py >= pw_h)
            continue;
        int x0 = child->wx < 0 ? -child->wx : 0;
        int x1 = cw;   /* clamp to parent width */
        if (child->wx + cw > pw_w)
            x1 = pw_w - child->wx;
        if (x1 <= x0)
            continue;
        memcpy(pw->bwin->pixels + (size_t)py * pw->bwin->stride
                 + (size_t)(child->wx + x0) * 4,
               child->bwin->pixels + (size_t)row * child->bwin->stride
                 + (size_t)x0 * 4,
               (size_t)(x1 - x0) * 4);
    }
    if (pw->dirty.l < 0) {
        pw->dirty.l = child->wx;
        pw->dirty.t = child->wy;
        pw->dirty.r = child->wx + cw;
        pw->dirty.b = child->wy + ch;
    } else {
        if (child->wx < pw->dirty.l) pw->dirty.l = child->wx;
        if (child->wy < pw->dirty.t) pw->dirty.t = child->wy;
        if (child->wx + cw > pw->dirty.r) pw->dirty.r = child->wx + cw;
        if (child->wy + ch > pw->dirty.b) pw->dirty.b = child->wy + ch;
    }
}

static void compose_children_of(uint64_t parent)
{
    for (int i = 0; i < g_hwnd_count; i++) {
        wn_window *c = g_hwnds[i].win;
        if (c && c->parent == parent)
            compose_child(c);
    }
}

/* --- builtin control proc ------------------------------------------------- */

typedef enum { CTL_BUTTON, CTL_STATIC, CTL_EDIT, CTL_LISTBOX, CTL_COMBO,
               CTL_SCROLLBAR } ctl_kind;

static ctl_kind ctl_kind_of(const char *cls)
{
    if (wn_strcaseeq(cls, "Button"))    return CTL_BUTTON;
    if (wn_strcaseeq(cls, "Static"))    return CTL_STATIC;
    if (wn_strcaseeq(cls, "Edit"))      return CTL_EDIT;
    if (wn_strcaseeq(cls, "ListBox"))   return CTL_LISTBOX;
    if (wn_strcaseeq(cls, "ComboBox"))  return CTL_COMBO;
    return CTL_SCROLLBAR;
}

static WN_API uint64_t ctl_proc(uint64_t hwnd, uint32_t msg, uint64_t wp,
                                int64_t lp)
{
    (void)wp;
    wn_window *w = win_from_hwnd(hwnd);
    if (!w)
        return 0;
    switch (msg) {
    case WN_WM_PAINT: {
        wn_handle hdc = g32_GetDC(hwnd);
        if (!hdc)
            return 0;
        ctl_kind k = ctl_kind_of(w->cls->name);
        uint32_t face = k == CTL_EDIT || k == CTL_LISTBOX ? 0x00FFFFFF
                                                          : 0x00C8D0D4;
        int32_t rect[4] = { 0, 0, w->bwin->width, w->bwin->height };
        wn_handle bg = g32_CreateSolidBrush(face);
        g32_FillRect(hdc, rect, bg);
        wn_handle_close(bg);
        /* flat 3D-ish border */
        wn_handle dark = g32_CreateSolidBrush(0x00606060);
        wn_handle lite = g32_CreateSolidBrush(0x00FFFFFF);
        int32_t top[4]  = { 0, 0, w->bwin->width, 1 };
        int32_t lef[4]  = { 0, 0, 1, w->bwin->height };
        int32_t bot[4]  = { 0, w->bwin->height - 1, w->bwin->width,
                            w->bwin->height };
        int32_t rig[4]  = { w->bwin->width - 1, 0, w->bwin->width,
                            w->bwin->height };
        g32_FillRect(hdc, top, k == CTL_STATIC ? lite : dark);
        g32_FillRect(hdc, lef, k == CTL_STATIC ? lite : dark);
        g32_FillRect(hdc, bot, lite);
        g32_FillRect(hdc, rig, lite);
        wn_handle_close(dark);
        wn_handle_close(lite);
        if (w->title[0]) {
            g32_SetTextColor(hdc, 0);
            g32_SetBkMode(hdc, 1 /* TRANSPARENT */);
            g32_TextOutA(hdc, 6, (w->bwin->height - 12) / 2, w->title, -1);
        }
        g32_ReleaseDC(hwnd, hdc);
        compose_child(w);
        return 0;
    }
    case 0x0201 /* WM_LBUTTONDOWN */:
        if (ctl_kind_of(w->cls->name) == CTL_BUTTON && w->parent) {
            post_msg(w->parent, WN_WM_COMMAND,
                     (w->id & 0xFFFF) | (0 /*BN_CLICKED*/ << 16),
                     (int64_t)hwnd);
        }
        return 0;
    case WN_WM_SETTEXT:
        snprintf(w->title, sizeof w->title, "%s",
                 lp ? (const char *)(uintptr_t)lp : "");
        compose_child(w);
        return 1;
    default:
        return 0;
    }
}

/* Register a builtin control class on first use. */
static wn_wndclass *builtin_control_class(const char *name)
{
    static const char *known[] = { "Button", "Edit", "Static", "ListBox",
                                   "ComboBox", "ScrollBar", "#32770", NULL };
    for (int i = 0; known[i]; i++) {
        if (!wn_strcaseeq(name, known[i]))
            continue;
        for (int c = 0; c < 32; c++) {
            if (!g_classes[c].used) {
                snprintf(g_classes[c].name, sizeof g_classes[c].name, "%s",
                         known[i]);
                g_classes[c].proc = ctl_proc;
                g_classes[c].used = 1;
                wn_log(WN_LOG_DEBUG, "user32: builtin control class '%s'",
                       known[i]);
                return &g_classes[c];
            }
        }
    }
    return NULL;
}

/* --- dialog template parsing ---------------------------------------------- */

/* sz_Or_Ord: 0xFFFF + WORD id, or a NUL-terminated UTF-16 string. */
static const uint16_t *dlg_read_szorord(const uint16_t *p, const uint16_t *end,
                                        uint16_t *id_out, char *out, size_t cap)
{
    if (p >= end)
        return p;
    if (*p == 0xFFFF) {
        if (id_out)
            *id_out = p[1];
        if (out && cap)
            out[0] = 0;
        return p + 2;
    }
    const uint16_t *q = p;
    size_t n = 0;
    while (q < end && *q) {
        if (out && n + 1 < cap)
            out[n] = (char)*q;   /* ASCII fold (dialog text is ANSI in templates) */
        q++;
        n++;
    }
    if (out && cap)
        out[n < cap ? n : cap - 1] = 0;
    if (id_out)
        *id_out = 0xFFFF;
    return q + 1;
}

static const uint32_t *dlg_dword_align(const void *p)
{
    uintptr_t a = (uintptr_t)p;
    a = (a + 3) & ~(uintptr_t)3;
    return (const uint32_t *)a;
}

/* Dialog class atom -> class name. */
static const char *dlg_atom_class(uint16_t atom)
{
    switch (atom) {
    case 0x0080: return "Button";
    case 0x0081: return "Edit";
    case 0x0082: return "Static";
    case 0x0083: return "ListBox";
    case 0x0084: return "ScrollBar";
    case 0x0085: return "ComboBox";
    default: return NULL;
    }
}

/* Approx dialog-base-unit conversion (font metrics come with real fonts). */
#define DLG_X(n) ((int)((n) * 4 / 2 + ((n) & 1)))
#define DLG_Y(n) ((int)((n) * 8 / 2))

static uint64_t create_dialog_from_template(uint64_t hinst,
                                            const void *tmpl, uint64_t parent,
                                            uint64_t dlgproc, uint64_t param,
                                            int32_t force_visible)
{
    /* Template argument may be a MAKEINTRESOURCE id -> resolve RT_DIALOG
     * from the module's resources first (this is what PuTTY does). */
    if (((uintptr_t)tmpl >> 16) == 0) {
        extern WN_API uint64_t k32_FindResourceA(uint64_t, const char *,
                                                 const char *);
        extern WN_API void *k32_LockResource(uint64_t);
        char rid[16];
        snprintf(rid, sizeof rid, "%u", (unsigned)(uintptr_t)tmpl);
        uint64_t hres = k32_FindResourceA(hinst, rid,
                                          (const char *)(uintptr_t)5 /*RT_DIALOG*/);
        if (!hres) {
            wn_log(WN_LOG_ERR, "user32: dialog resource %u not found", 
                   (unsigned)(uintptr_t)tmpl);
            wn_last_error_set(1814);
            return 0;
        }
        const void *locked = k32_LockResource(hres);
        if (!locked)
            return 0;
        wn_log(WN_LOG_DEBUG, "user32: dialog template from resource #%u",
               (unsigned)(uintptr_t)tmpl);
        tmpl = locked;
    }
    const uint16_t *p = tmpl;
    const uint16_t *end = p + 4096 * 64;   /* generous bound; templates are small */
    uint32_t style, ex_style;
    int nitems;
    int32_t x, y, cx, cy;
    char title[128];
    const uint16_t *menu, *cls, *tit;

    int is_ex = (p[0] == 1 && p[1] == 0xFFFF);
    if (is_ex) {
        /* DLGTEMPLATEEX */
        const uint8_t *b = tmpl;
        p = (const uint16_t *)(b + 4 + 4);   /* skip ver+sig, helpID */
        style = *(const uint32_t *)(const void *)p; p += 2;
        ex_style = *(const uint32_t *)(const void *)p; p += 2;
        nitems = *p++;
        x = (int16_t)*p++; y = (int16_t)*p++;
        cx = (int16_t)*p++; cy = (int16_t)*p++;
        menu = p; p = dlg_read_szorord(p, end, NULL, NULL, 0);
        cls = p;  p = dlg_read_szorord(p, end, NULL, NULL, 0);
        tit = p;  p = dlg_read_szorord(p, end, NULL, title, sizeof title);
    } else {
        /* DLGTEMPLATE */
        style = *(const uint32_t *)(const void *)p; p += 2;
        ex_style = *(const uint32_t *)(const void *)p; p += 2;
        nitems = *p++;
        x = (int16_t)*p++; y = (int16_t)*p++;
        cx = (int16_t)*p++; cy = (int16_t)*p++;
        menu = p; p = dlg_read_szorord(p, end, NULL, NULL, 0);
        cls = p;  p = dlg_read_szorord(p, end, NULL, NULL, 0);
        tit = p;  p = dlg_read_szorord(p, end, NULL, title, sizeof title);
    }
    (void)menu;
    (void)cls;
    (void)tit;

    /* dialog window itself (class #32770 -> our trampoline) */
    uint64_t hwnd = u32_CreateWindowExA(ex_style, "#32770", title,
                                        style | (force_visible ? 0x10000000u : 0),
                                        DLG_X(x), DLG_Y(y),
                                        DLG_X(cx), DLG_Y(cy),
                                        parent, 0, hinst, 0);
    if (!hwnd)
        return 0;
    wn_window *dw = win_from_hwnd(hwnd);
    dw->is_dialog = 1;
    dw->dlgproc = dlgproc;
    dw->dlg_param = param;

    /* items */
    for (int i = 0; i < nitems; i++) {
        p = (const uint16_t *)dlg_dword_align(p);
        if (p >= end)
            break;
        uint32_t istyle, iex;
        int32_t ix, iy, icx, icy;
        uint64_t iid;
        if (is_ex) {
            /* DLGITEMTEMPLATEEX: helpID(4) exStyle(4) style(4) x,y,cx,cy(2x4)
             * id(4!) class title extra(2) */
            p += 2;                                   /* helpID */
            iex = *(const uint32_t *)(const void *)p; p += 2;
            istyle = *(const uint32_t *)(const void *)p; p += 2;
            ix = (int16_t)*p++; iy = (int16_t)*p++;
            icx = (int16_t)*p++; icy = (int16_t)*p++;
            iid = *(const uint32_t *)(const void *)p; p += 2;
        } else {
            /* DLGITEMTEMPLATE: style(4) exStyle(4) x,y,cx,cy id(2!) */
            istyle = *(const uint32_t *)(const void *)p; p += 2;
            iex = *(const uint32_t *)(const void *)p; p += 2;
            ix = (int16_t)*p++; iy = (int16_t)*p++;
            icx = (int16_t)*p++; icy = (int16_t)*p++;
            iid = *p++;
        }
        char icls[64], ititle[160];
        uint16_t cls_id = 0xFFFF;
        p = dlg_read_szorord(p, end, &cls_id, icls, sizeof icls);
        p = dlg_read_szorord(p, end, NULL, ititle, sizeof ititle);
        uint16_t extra = *p++;
        p += extra / 2;
        const char *class_name = NULL;
        if (cls_id != 0xFFFF) {
            class_name = dlg_atom_class(cls_id);
            if (!class_name) {
                wn_log(WN_LOG_WARN, "user32: dialog item class atom 0x%x "
                       "unknown", cls_id);
                continue;
            }
        } else if (icls[0]) {
            class_name = icls;
        }
        if (!class_name) {
            wn_log(WN_LOG_WARN, "user32: dialog item without class");
            continue;
        }
        u32_CreateWindowExA(iex, class_name, ititle,
                            istyle | WN_WS_CHILD | 0x10000000u /*WS_VISIBLE*/,
                            DLG_X(ix), DLG_Y(iy), DLG_X(icx), DLG_Y(icy),
                            hwnd, iid, hinst, 0);
    }

    /* WM_INITDIALOG -> guest dlgproc */
    if (dlgproc) {
        typedef WN_API int64_t (*dlgproc_fn)(uint64_t, uint32_t, uint64_t,
                                             int64_t);
        ((dlgproc_fn)(uintptr_t)dlgproc)(hwnd, WN_WM_INITDIALOG, 0,
                                         (int64_t)param);
    }
    compose_children_of(hwnd);
    if (dw->visible)
        u32_ShowWindow(hwnd, 5);
    return hwnd;
}

/* DialogBox: modal-ish loop until EndDialog. */
static WN_API int64_t u32_DialogBoxParamA(uint64_t hinst, const void *tmpl,
                                          uint64_t parent, uint64_t dlgproc,
                                          uint64_t param)
{
    uint64_t hwnd = create_dialog_from_template(hinst, tmpl, parent, dlgproc,
                                                param, 1);
    if (!hwnd)
        return -1;
    wn_window *dw = win_from_hwnd(hwnd);
    wn_msg m;
    while (!dw->dlg_done) {
        int32_t r = u32_GetMessageA(&m, 0, 0, 0);
        if (r <= 0)
            break;
        u32_DispatchMessageA(&m);
    }
    int64_t result = dw->dlg_result;
    u32_DestroyWindow(hwnd);
    return result;
}

static WN_API uint64_t u32_CreateDialogParamA(uint64_t hinst, const void *tmpl,
                                              uint64_t parent, uint64_t dlgproc,
                                              uint64_t param)
{
    return create_dialog_from_template(hinst, tmpl, parent, dlgproc, param, 0);
}

static WN_API void u32_EndDialog(uint64_t hwnd, int64_t result)
{
    wn_window *w = win_from_hwnd(hwnd);
    if (!w || !w->is_dialog) {
        wn_log(WN_LOG_WARN, "user32: EndDialog on non-dialog hwnd 0x%llx",
               (unsigned long long)hwnd);
        return;
    }
    w->dlg_result = result;
    w->dlg_done = 1;
    post_msg(hwnd, 0, 0, 0);   /* wake the modal loop */
}

static WN_API uint64_t u32_GetDlgItem(uint64_t hwnd, int32_t id)
{
    for (int i = 0; i < g_hwnd_count; i++) {
        wn_window *c = g_hwnds[i].win;
        if (c && c->parent == hwnd && (int64_t)c->id == id)
            return (uint64_t)(uintptr_t)g_hwnds[i].h;
    }
    wn_last_error_set(WN_ERR_INVALID_PARAMETER);
    return 0;
}

static WN_API int32_t u32_IsDialogMessageA(void *msg)
{
    (void)msg;
    return 0;   /* no tab navigation yet (documented) */
}

static WN_API int32_t u32_SetDlgItemTextA(uint64_t hwnd, int32_t id,
                                          const char *text)
{
    uint64_t c = u32_GetDlgItem(hwnd, id);
    if (!c)
        return 0;
    wn_window *w = win_from_hwnd(c);
    if (w && w->cls && w->cls->proc)
        return (int32_t)w->cls->proc(c, WN_WM_SETTEXT, 0,
                                     (int64_t)(uintptr_t)text);
    return 0;
}

/* --- window text + longs --------------------------------------------------- */

static WN_API int32_t u32_SetWindowTextA(uint64_t hwnd, const char *text)
{
    wn_window *w = win_from_hwnd(hwnd);
    if (!w)
        return 0;
    snprintf(w->title, sizeof w->title, "%s", text ? text : "");
    if (w->is_child) {
        compose_child(w);
    }
    return 1;
}

static WN_API int32_t u32_GetWindowTextA(uint64_t hwnd, char *buf, int32_t max)
{
    wn_window *w = win_from_hwnd(hwnd);
    if (!w || !buf || max <= 0)
        return 0;
    snprintf(buf, (size_t)max, "%s", w->title);
    return (int32_t)strlen(buf);
}

static WN_API int64_t u32_GetWindowLongPtrA(uint64_t hwnd, int32_t idx)
{
    wn_window *w = win_from_hwnd(hwnd);
    if (!w)
        return 0;
    if (idx == -21 /* GWL_USERDATA */)
        return (int64_t)w->userdata;
    if (idx == -16 /* GWL_STYLE */)
        return 0;
    return 0;
}

static WN_API int64_t u32_SetWindowLongPtrA(uint64_t hwnd, int32_t idx,
                                            int64_t val)
{
    wn_window *w = win_from_hwnd(hwnd);
    if (!w)
        return 0;
    if (idx == -21) {
        int64_t old = (int64_t)w->userdata;
        w->userdata = (uint64_t)val;
        return old;
    }
    wn_log(WN_LOG_WARN, "user32: SetWindowLongPtr index %d unsupported",
           idx);
    return 0;
}

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
    { "DialogBoxParamA", u32_DialogBoxParamA },
    { "CreateDialogParamA", u32_CreateDialogParamA },
    { "EndDialog", u32_EndDialog },
    { "GetDlgItem", u32_GetDlgItem },
    { "IsDialogMessageA", u32_IsDialogMessageA },
    { "SetDlgItemTextA", u32_SetDlgItemTextA },
    { "SetWindowTextA", u32_SetWindowTextA },
    { "GetWindowTextA", u32_GetWindowTextA },
    { "GetWindowLongPtrA", u32_GetWindowLongPtrA },
    { "SetWindowLongPtrA", u32_SetWindowLongPtrA },
    { "MessageBoxA", u32_MessageBoxA },
    { "MessageBoxW", u32_MessageBoxW },
    { NULL, NULL },
};
