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
    uint32_t cb_wnd_extra;      /* bytes of GWLP storage past the fixed area */
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
    char title[128];          /* UTF-8 mirror of the window text */
    uint16_t wtext[512];      /* canonical text (UTF-16) for WM_GETTEXTW */
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
    uint32_t style, ex_style; /* style / ex_style capture */
    int is_desktop;           /* the GetDesktopWindow pseudo-window */
    int is_uni;               /* created via the W entry point */
    /* GWLP storage: 0..cbWndExtra bytes (fixed slots first, see docs) */
    uint64_t extra[16];
    /* control state (Button/Edit/ListBox/ComboBox/ScrollBar + comctl32) */
    uint32_t check;           /* BST_ state */
    int caret;                /* edit: caret position (chars) */
    int sel;                  /* list/combo/tree: selected index/item */
    int top_item;             /* list: first visible row */
    char **items;             /* list/combo: strings (malloc'd) */
    int n_items, items_cap;
    void *ctl_priv;           /* comctl32 private data (tree nodes etc.) */
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
/* focus + activation (single-GUI-thread model). */
static uint64_t g_focus_hwnd;       /* 0 = unset */
static uint64_t g_active_hwnd;      /* 0 = unset */
static uint64_t g_desktop_hwnd;     /* 0 = not created yet */

/* hwnd registry (parallel to the handle table, for reverse lookup). */
static struct { wn_window *win; wn_handle h; } g_hwnds[WN_USER32_MAX_WINDOWS];
static int g_hwnd_count;
/* bwin->(backend private window) registry for backend event dispatch. */
static struct { wn_bwin *bwin; void *backend_priv; } g_bwins[WN_USER32_MAX_WINDOWS];
static int g_bwin_count;

/* Forward decls (defined later in this file). */
static void compose_child(wn_window *child);
static void present_root(wn_window *w);
#define DLG_X(n) ((int)((n) * 4 / 2 + ((n) & 1)))
#define DLG_Y(n) ((int)((n) * 8 / 2))

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
        if (vk) {
            /* keyboard goes to the FOCUS window, not the event window */
            uint64_t target = g_focus_hwnd ? g_focus_hwnd : h;
            wn_window *tw = win_from_hwnd(target);
            if (!tw)
                target = h;
            post_msg(target, WN_WM_KEYDOWN, vk, 0);
        }
        break;
    }
    case WN_BEV_TEXT:
        post_msg(g_focus_hwnd ? g_focus_hwnd : h, WN_WM_CHAR,
                 (uint64_t)(uint32_t)ev->val, 0);
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
        if (msg) {
            /* hit-test: deliver to the deepest visible child under the
             * cursor, with coordinates translated to its origin. */
            uint64_t target = h;
            int mx = (int)(int16_t)ev->x, my = (int)(int16_t)ev->y;
            for (int depth = 0; depth < 8; depth++) {
                uint64_t next = 0;
                int nx = 0, ny = 0;
                for (int i = 0; i < g_hwnd_count; i++) {
                    wn_window *c = g_hwnds[i].win;
                    if (!c || c->parent != target || !c->visible ||
                        c->in_destroy)
                        continue;
                    if (mx >= c->wx && my >= c->wy &&
                        mx < c->wx + c->cw && my < c->wy + c->ch) {
                        next = (uint64_t)(uintptr_t)g_hwnds[i].h;
                        nx = mx - c->wx;
                        ny = my - c->wy;
                        break;
                    }
                }
                if (!next)
                    break;
                target = next;
                mx = nx;
                my = ny;
            }
            if (msg == WN_WM_LBUTTONDOWN && target != g_focus_hwnd) {
                /* click focuses: WM_KILLFOCUS/WM_SETFOCUS */
                extern int user32_set_focus_internal(uint64_t hwnd);
                user32_set_focus_internal(target);
            }
            post_msg(target, msg, wp,
                     (int64_t)(((uint64_t)(uint16_t)mx) |
                               ((uint64_t)(uint16_t)my << 16)));
        }
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

/* --- focus, activation, desktop --------------------------------------------- */

/* Canonical UTF-16 text storage for every window (controls round-trip it). */
static void user32_set_wtext_utf8(wn_window *w, const char *s)
{
    uint16_t *t = wn_utf8_to_utf16_n(s ? s : "", s ? strlen(s) : 0);
    if (!t) {
        w->wtext[0] = 0;
        return;
    }
    size_t i = 0;
    while (t[i] && i < 511) {
        w->wtext[i] = t[i];
        i++;
    }
    w->wtext[i] = 0;
    free(t);
}

/* internal SetFocus: posts kill/set notifications, updates g_focus_hwnd */
int user32_set_focus_internal(uint64_t hwnd)
{
    if (hwnd == g_focus_hwnd)
        return 1;
    wn_window *w = hwnd ? win_from_hwnd(hwnd) : NULL;
    if (hwnd && !w)
        return 0;
    if (g_focus_hwnd)
        post_msg(g_focus_hwnd, 8 /* WM_KILLFOCUS */, 0, 0);
    g_focus_hwnd = hwnd;
    if (hwnd)
        post_msg(hwnd, 7 /* WM_SETFOCUS */, 0, 0);
    return 1;
}

static WN_API uint64_t u32_SetFocus(uint64_t hwnd)
{
    uint64_t old = g_focus_hwnd;
    user32_set_focus_internal(hwnd);
    return old;
}

static WN_API uint64_t u32_GetFocus(void)
{
    return g_focus_hwnd;
}

static WN_API uint64_t u32_SetActiveWindow(uint64_t hwnd)
{
    uint64_t old = g_active_hwnd;
    if (hwnd == g_active_hwnd)
        return old;
    if (hwnd && !win_from_hwnd(hwnd))
        return old;
    if (g_active_hwnd)
        post_msg(g_active_hwnd, 0x0006 /* WM_ACTIVATE */,
                 0 /* WA_INACTIVE */ | 0, (int64_t)g_active_hwnd);
    g_active_hwnd = hwnd;
    if (hwnd)
        post_msg(hwnd, 0x0006 /* WM_ACTIVATE */,
                 1 /* WA_ACTIVE */ | 0, (int64_t)old);
    return old;
}

static WN_API uint64_t u32_GetActiveWindow(void)
{
    return g_active_hwnd;
}

static WN_API uint64_t u32_GetForegroundWindow(void)
{
    return g_active_hwnd;
}

/* Desktop pseudo-window: offscreen surface, no backend window, never shown.
 * GetDC(NULL) draws into it (screen-size scratch). */
uint64_t user32_desktop(void)
{
    if (g_desktop_hwnd)
        return g_desktop_hwnd;
    wn_window *win = wn_xcalloc(1, sizeof *win);
    win->cls = NULL;
    win->is_desktop = 1;
    win->style = 0;
    win->cw = 1280;
    win->ch = 800;
    win->bwin = wn_xcalloc(1, sizeof(wn_bwin));
    win->bwin->width = 1280;
    win->bwin->height = 800;
    win->bwin->stride = 1280 * 4;
    win->bwin->pixels = wn_xmalloc((size_t)1280 * 800 * 4 + 64);
    memset(win->bwin->pixels, 0xFF, (size_t)1280 * 800 * 4);
    wn_handle h = register_hwnd(win);
    g_desktop_hwnd = (uint64_t)(uintptr_t)h;
    return g_desktop_hwnd;
}

static WN_API uint64_t u32_GetDesktopWindow(void)
{
    return user32_desktop();
}

/* --- Get/SetWindowLong(Ptr): the full documented index space ----------------
 * Negative: system slots. 0..cbWndExtra-4: class extra bytes (uint64 slots in
 * our storage). Dialogs: DWL_MSGRESULT=0, DWL_DLGPROC=4, DWL_USER=8 map onto
 * the same extra storage. */
#define GWL_STYLE     (-16)
#define GWL_EXSTYLE   (-20)
#define GWL_USERDATA  (-21)
#define GWL_ID        (-12)
#define GWLP_WNDPROC  (-4)
#define GWLP_HINSTANCE (-6)
#define GWLP_HWNDPARENT (-8)
#define GWLP_ID       (-12)
#define GWLP_USERDATA (-21)

static int64_t winlong_get(wn_window *w, int32_t idx)
{
    if (!w)
        return 0;
    switch (idx) {
    case GWL_STYLE:     return (int64_t)(uint32_t)w->style;
    case GWL_EXSTYLE:   return (int64_t)(uint32_t)w->ex_style;
    case GWLP_USERDATA: return (int64_t)w->userdata;
    case GWLP_ID:       return (int64_t)w->id;
    case GWLP_HINSTANCE: return (int64_t)w->hinstance;
    case GWLP_HWNDPARENT: return (int64_t)w->parent;
    default:
        break;
    }
    if (idx >= 0) {
        /* class extra bytes / dialog DWL_* */
        uint32_t avail = w->cls ? w->cls->cb_wnd_extra : (w->is_dialog ? 40 : 0);
        if (w->is_dialog && idx < 40)
            return (int64_t)w->extra[idx / 8];
        if ((uint32_t)idx + 8 <= avail && idx / 8 < 16)
            return (int64_t)w->extra[idx / 8];
        wn_log(WN_LOG_WARN, "user32: GetWindowLong index %d beyond "
               "cbWndExtra (%u) hwnd=0x%llx class=%s", idx, avail,
               (unsigned long long)(uintptr_t)hwnd_of_window(w),
               w->cls ? w->cls->name : "#desktop");
        return 0;
    }
    if (idx == GWLP_WNDPROC) {
        wn_log(WN_LOG_WARN, "user32: GetWindowLong(GWLP_WNDPROC) -> class "
               "proc (subclassing unsupported)");
        return w->cls ? (int64_t)(uintptr_t)w->cls->proc : 0;
    }
    wn_log(WN_LOG_WARN, "user32: GetWindowLong unknown index %d", idx);
    return 0;
}

static int64_t winlong_set(wn_window *w, int32_t idx, int64_t v)
{
    if (!w)
        return 0;
    int64_t old = winlong_get(w, idx);
    switch (idx) {
    case GWL_STYLE:     w->style = (uint32_t)v; return old;
    case GWL_EXSTYLE:   w->ex_style = (uint32_t)v; return old;
    case GWLP_USERDATA: w->userdata = (uint64_t)v; return old;
    case GWLP_ID:       w->id = (uint64_t)v; return old;
    case GWLP_HINSTANCE: w->hinstance = (uint64_t)v; return old;
    default:
        break;
    }
    if (idx >= 0) {
        uint32_t avail = w->cls ? w->cls->cb_wnd_extra : (w->is_dialog ? 40 : 0);
        if ((w->is_dialog && idx < 40) ||
            ((uint32_t)idx + 8 <= avail && idx / 8 < 16)) {
            w->extra[idx / 8] = (uint64_t)v;
            return old;
        }
        wn_log(WN_LOG_WARN, "user32: SetWindowLong index %d beyond "
               "cbWndExtra (%u) - NOT stored", idx, avail);
        return old;
    }
    wn_log(WN_LOG_WARN, "user32: SetWindowLong unknown index %d (ignored)",
           idx);
    return old;
}

static WN_API int64_t u32_GetWindowLongA(uint64_t hwnd, int32_t idx)
{
    return winlong_get(win_from_hwnd(hwnd), idx);
}

static WN_API int64_t u32_GetWindowLongW(uint64_t hwnd, int32_t idx)
{
    return winlong_get(win_from_hwnd(hwnd), idx);
}

static WN_API int64_t u32_GetWindowLongPtrA(uint64_t hwnd, int32_t idx)
{
    return winlong_get(win_from_hwnd(hwnd), idx);
}

static WN_API int64_t u32_GetWindowLongPtrW(uint64_t hwnd, int32_t idx)
{
    return winlong_get(win_from_hwnd(hwnd), idx);
}

static WN_API int64_t u32_SetWindowLongA(uint64_t hwnd, int32_t idx, int64_t v)
{
    return winlong_set(win_from_hwnd(hwnd), idx, v);
}

static WN_API int64_t u32_SetWindowLongW(uint64_t hwnd, int32_t idx, int64_t v)
{
    return winlong_set(win_from_hwnd(hwnd), idx, v);
}

static WN_API int64_t u32_SetWindowLongPtrA(uint64_t hwnd, int32_t idx, int64_t v)
{
    return winlong_set(win_from_hwnd(hwnd), idx, v);
}

static WN_API int64_t u32_SetWindowLongPtrW(uint64_t hwnd, int32_t idx, int64_t v)
{
    return winlong_set(win_from_hwnd(hwnd), idx, v);
}

/* --- dialog helpers --------------------------------------------------------- */

/* Child lookup by control id (direct children only, per Windows). */
static wn_window *dlg_item(wn_window *dlg, uint64_t id)
{
    for (int i = 0; i < g_hwnd_count; i++) {
        wn_window *c = g_hwnds[i].win;
        if (c && c->parent && dlg &&
            c->parent == (uint64_t)(uintptr_t)hwnd_of_window(dlg) &&
            c->id == id)
            return c;
    }
    return NULL;
}

static WN_API uint64_t u32_GetDlgItem(uint64_t hdlg, int32_t id)
{
    wn_window *d = win_from_hwnd(hdlg);
    wn_window *c = d ? dlg_item(d, (uint64_t)(int64_t)id) : NULL;
    wn_handle h = c ? hwnd_of_window(c) : 0;
    return (uint64_t)(uintptr_t)h;
}

/* Dialog base units: consistent with DLG_X/DLG_Y below (2 px / 4 px). */
static WN_API int32_t u32_MapDialogRect(uint64_t hdlg, void *rect)
{
    wn_window *d = win_from_hwnd(hdlg);
    if (!d || !rect)
        return 0;
    int32_t *r = rect;
    r[0] = DLG_X(r[0]);
    r[1] = DLG_Y(r[1]);
    r[2] = DLG_X(r[2]);
    r[3] = DLG_Y(r[3]);
    return 1;
}

static WN_API int32_t u32_IsDlgButtonChecked(uint64_t hdlg, int32_t id)
{
    uint64_t c = u32_GetDlgItem(hdlg, id);
    wn_window *w = c ? win_from_hwnd(c) : NULL;
    if (!w)
        return 0;
    return (int32_t)w->check;
}

static WN_API int32_t u32_CheckDlgButton(uint64_t hdlg, int32_t id,
                                         uint32_t check)
{
    uint64_t c = u32_GetDlgItem(hdlg, id);
    wn_window *w = c ? win_from_hwnd(c) : NULL;
    if (!w)
        return 0;
    w->check = check & 3;
    compose_child(w);
    return 1;
}

static WN_API int32_t u32_CheckRadioButton(uint64_t hdlg, int32_t first,
                                           int32_t last, int32_t check)
{
    wn_window *d = win_from_hwnd(hdlg);
    if (!d)
        return 0;
    for (int i = 0; i < g_hwnd_count; i++) {
        wn_window *c = g_hwnds[i].win;
        if (!c || c->parent != hdlg || !c->cls)
            continue;
        if (wn_strcaseeq(c->cls->name, "Button") &&
            (int64_t)c->id >= (int64_t)first &&
            (int64_t)c->id <= (int64_t)last) {
            c->check = ((int64_t)c->id == (int64_t)check) ? 1 : 0;
            compose_child(c);
        }
    }
    return 1;
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
            g_classes[i].cb_wnd_extra = *(const uint32_t *)(const void *)(p + 0x14);
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
        user32_set_wtext_utf8(win, win->title);
        win->style = style;
        win->ex_style = ex_style;
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
    user32_set_wtext_utf8(win, win->title);
    win->style = style;
    win->ex_style = ex_style;
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
    if (r) {
        wn_window *ww = win_from_hwnd(r);
        if (ww)
            ww->is_uni = 1;
    }
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
    if (w)
        return w->bwin;
    if (!hwnd) {
        /* GetDC(NULL): the desktop pseudo-window */
        extern uint64_t user32_desktop(void);
        wn_window *d = win_from_hwnd(user32_desktop());
        return d ? d->bwin : NULL;
    }
    return NULL;
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
    /* Changes must reach the screen: compose chains end at the top-level
     * window, whose bwin is the backend surface. Present it. */
    present_root(child);
}

static void present_root(wn_window *w)
{
    while (w && w->parent) {
        wn_window *p = win_from_hwnd(w->parent);
        if (!p)
            break;
        w = p;
    }
    if (!w || !w->bwin || !w->visible)
        return;
    const wn_backend *be = wn_backend_get();
    if (be && be->present)
        be->present(w->bwin);
}

static void compose_children_of(uint64_t parent)
{
    for (int i = 0; i < g_hwnd_count; i++) {
        wn_window *c = g_hwnds[i].win;
        if (c && c->parent == parent)
            compose_child(c);
    }
}

/* --- builtin control procs: Button, Edit, Static, ListBox, ComboBox, ScrollBar ---
 *
 * Each control owns its state in wn_window (check/caret/sel/items). Painting
 * goes to the control surface then composes onto the parent. Notifications
 * ride WM_COMMAND (buttons, lists, edits) as Windows does.
 */

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

#define WN_WM_COMMAND    0x0111
#define WN_WM_SETTEXT    0x000C
#define WN_WM_GETTEXT    0x000D
#define WN_WM_GETTEXTLENGTH 0x000E

extern WN_API int32_t g32_DrawTextA(wn_handle hdc, const char *s,
                                    int32_t count, void *rect, uint32_t fmt);
extern WN_API int32_t g32_TextOutA(wn_handle hdc, int x, int y,
                                   const char *s, int32_t count);
extern WN_API int32_t g32_Rectangle(wn_handle hdc, int l, int t, int r, int b);
extern WN_API int32_t g32_DefaultFontHeight(void);
extern WN_API void g32_DrawCtlFrame(wn_handle hdc, int x, int y,
                                    int radio, int state);
extern WN_API uint32_t g32_SetBkColor(wn_handle hdc, uint32_t color);

#define BST_UNCHECKED      0
#define BST_CHECKED        1
#define BST_INDETERMINATE  2

/* BM_ 0x00F0.. */
#define BM_GETCHECK   0x00F0
#define BM_SETCHECK   0x00F1
#define BM_CLICK      0x00F5
/* EM_ 0x00BA.. */
#define EM_GETSEL     0x00B0
#define EM_SETSEL     0x00B1
#define EM_REPLACESEL 0x00C2
#define EM_SETLIMITTEXT 0x00C5
#define EM_GETLINECOUNT 0x00BA
/* LB_ 0x0180.. */
#define LB_ADDSTRING     0x0180
#define LB_INSERTSTRING  0x0181
#define LB_DELETESTRING  0x0182
#define LB_GETCOUNT      0x018B
#define LB_GETCURSEL     0x0188
#define LB_SETCURSEL     0x0186
#define LB_GETTEXT       0x0189
#define LB_GETTEXTLEN    0x018A
#define LB_RESETCONTENT  0x0184
#define LB_GETSELITEMS   0x0191
#define LB_SETCOLUMNWIDTH 0x019C
#define LB_SETTOPINDEX   0x0197
#define LB_GETSELITEMS   0x0191
/* CB_ 0x0140.. */
#define CB_ADDSTRING     0x0143
#define CB_GETCOUNT      0x0146
#define CB_GETCURSEL     0x0147
#define CB_SETCURSEL     0x014E
#define CB_GETLBTEXT     0x0148
#define CB_GETLBTEXTLEN  0x0149
#define CB_RESETCONTENT  0x014B
#define CB_DELETESTRING  0x0154
#define CB_SHOWDROPDOWN  0x014F
/* SBM_ */
#define SBM_SETPOS       0x00E0
#define SBM_GETPOS       0x00E1
#define SBM_SETRANGE     0x00E2
#define SBM_GETRANGE     0x00E3

static void ctl_notify(wn_window *w, uint32_t code)
{
    if (w->parent)
        post_msg(w->parent, WN_WM_COMMAND,
                 (w->id & 0xFFFF) | ((uint64_t)code << 16),
                 (int64_t)(uintptr_t)hwnd_of_window(w));
}

static void ctl_repaint(wn_window *w)
{
    post_msg((uint64_t)(uintptr_t)hwnd_of_window(w), WN_WM_PAINT, 0, 0);
    compose_child(w);
}

/* item storage for list/combo */
static int ctl_items_reserve(wn_window *w, int need)
{
    if (need <= w->items_cap)
        return 0;
    int cap = w->items_cap ? w->items_cap * 2 : 16;
    while (cap < need)
        cap *= 2;
    char **ni = realloc(w->items, (size_t)cap * sizeof(char *));
    if (!ni)
        return -1;
    w->items = ni;
    w->items_cap = cap;
    return 0;
}

static int ctl_items_add(wn_window *w, const char *s)
{
    if (ctl_items_reserve(w, w->n_items + 1) != 0)
        return -1;
    w->items[w->n_items] = wn_xstrdup(s ? s : "");
    return w->n_items++;
}

static void ctl_items_clear(wn_window *w)
{
    for (int i = 0; i < w->n_items; i++)
        free(w->items[i]);
    free(w->items);
    w->items = NULL;
    w->n_items = w->items_cap = 0;
    w->sel = -1;
    w->top_item = 0;
}

/* UTF-16 text -> control storage (SETTEXT/GETTEXT core) */
static void ctl_set_text(wn_window *w, const char *utf8)
{
    snprintf(w->title, sizeof w->title, "%s", utf8 ? utf8 : "");
    user32_set_wtext_utf8(w, w->title);
    w->caret = (int)(strlen(w->title) < 511 ? strlen(w->title) : 511);
}

static int64_t ctl_get_text(wn_window *w, char *out, size_t cap)
{
    snprintf(out, cap, "%s", w->title);
    return (int64_t)strlen(out);
}

static int64_t ctl_get_text_w(wn_window *w, uint16_t *out, size_t cap16)
{
    size_t i = 0;
    while (w->wtext[i] && i + 1 < cap16) {
        out[i] = w->wtext[i];
        i++;
    }
    out[i] = 0;
    return (int64_t)i;
}

/* Edit: append a character to the text at the caret. */
static void ctl_edit_char(wn_window *w, uint16_t ch)
{
    if (ch < 0x20 && ch != '\r' && ch != '\n')
        return;
    size_t n = 0;
    while (w->wtext[n])
        n++;
    if (n + 1 >= 511)
        return;
    if (w->caret < 0 || (size_t)w->caret > n)
        w->caret = (int)n;
    /* insert at caret (memmove in uint16 units) */
    for (size_t i = n; i > (size_t)w->caret; i--)
        w->wtext[i] = w->wtext[i - 1];
    w->wtext[w->caret] = ch;
    w->wtext[n + 1] = 0;
    w->caret++;
    char *a = wn_utf16_to_utf8(w->wtext, n + 2);
    if (a) {
        snprintf(w->title, sizeof w->title, "%s", a);
        free(a);
    }
    ctl_notify(w, 0x0300 /* EN_CHANGE */);
}

/* row height for painting: font metrics via gdi (default font cell) */
static int ctl_row_h(void)
{
    extern WN_API int32_t g32_DefaultFontHeight(void);
    return g32_DefaultFontHeight();
}

static void ctl_paint_check(wn_handle hdc, int x, int y, int state, int radio)
{
    extern WN_API void g32_DrawCtlFrame(wn_handle hdc, int x, int y,
                                        int radio, int state);
    g32_DrawCtlFrame(hdc, x, y, radio, state);
}

static WN_API uint64_t ctl_proc(uint64_t hwnd, uint32_t msg, uint64_t wp,
                                int64_t lp)
{
    wn_window *w = win_from_hwnd(hwnd);
    if (!w)
        return 0;
    const char *cls = w->cls ? w->cls->name : "";
    ctl_kind k = ctl_kind_of(cls);
    switch (msg) {
    case WN_WM_PAINT: {
        wn_handle hdc = g32_GetDC(hwnd);
        if (!hdc)
            return 0;
        int W = w->cw, H = w->ch;
        int32_t rect[4] = { 0, 0, W, H };
        uint32_t face = (k == CTL_EDIT || k == CTL_LISTBOX) ? 0x00FFFFFF
                                                          : 0x00C8D0D4;
        wn_handle bg = g32_CreateSolidBrush(face);
        g32_FillRect(hdc, rect, bg);
        wn_handle_close(bg);
        wn_handle dark = g32_CreateSolidBrush(0x00606060);
        wn_handle lite = g32_CreateSolidBrush(0x00FFFFFF);
        int32_t top[4]  = { 0, 0, W, 1 };
        int32_t lef[4]  = { 0, 0, 1, H };
        int32_t bot[4]  = { 0, H - 1, W, H };
        int32_t rig[4]  = { W - 1, 0, W, H };
        g32_FillRect(hdc, top, k == CTL_STATIC ? lite : dark);
        g32_FillRect(hdc, lef, k == CTL_STATIC ? lite : dark);
        g32_FillRect(hdc, bot, k == CTL_STATIC ? dark : lite);
        g32_FillRect(hdc, rig, k == CTL_STATIC ? dark : lite);
        wn_handle_close(dark);
        wn_handle_close(lite);
        int rh = ctl_row_h();
        int focused = g_focus_hwnd == hwnd;
        g32_SetTextColor(hdc, focused && k == CTL_EDIT ? 0 : 0);
        g32_SetBkMode(hdc, 1 /* TRANSPARENT */);
        switch (k) {
        case CTL_BUTTON: {
            uint32_t bs = w->style & 0xF;
            if (bs == 0x2 /*BS_AUTOCHECKBOX*/ || bs == 0x1 /*BS_CHECKBOX*/ ||
                bs == 0x9 /*BS_AUTORADIO*/ || bs == 0x3 /*BS_RADIOBUTTON*/) {
                ctl_paint_check(hdc, 4, (H - 13) / 2, (int)w->check,
                                bs >= 0x3 && bs <= 0x9 ? 1 : 0);
                int32_t tr[4] = { 22, 0, W - 4, H };
                g32_DrawTextA(hdc, w->title, -1, tr,
                              0x20 | 0x100 | 0x24 /*SINGLELINE|NOPREFIX|VCENTER*/);
            } else if (bs == 0x5 /*BS_GROUPBOX*/) {
                /* frame + label on the top edge */
                int32_t fr[4] = { 1, 7, W - 1, H - 1 };
                g32_Rectangle(hdc, fr[0], fr[1], fr[2], fr[3]);
                int32_t tr[4] = { 8, 0, 8 + (int)strlen(w->title) * 8 + 4, 16 };
                wn_handle fbg = g32_CreateSolidBrush(0x00C8D0D4);
                g32_FillRect(hdc, tr, fbg);
                wn_handle_close(fbg);
                g32_DrawTextA(hdc, w->title, -1, tr,
                              0x20 | 0x100 | 0x24);
            } else {
                /* push button */
                int32_t tr[4] = { 4, 0, W - 4, H };
                uint32_t old = g32_SetBkColor(hdc, 0x00C8D0D4);
                (void)old;
                g32_SetBkMode(hdc, 1);
                g32_DrawTextA(hdc, w->title, -1, tr,
                              0x20 | 0x100 | 0x24 |
                              (focused ? 6u /*CENTER*/ : 6u));
            }
            break;
        }
        case CTL_EDIT: {
            int32_t tr[4] = { 3, 0, W - 3, H };
            g32_DrawTextA(hdc, w->title, -1, tr, 0x20 | 0x100 | 0x24);
            if (focused) {   /* caret after text */
                int cx = 3 + w->caret * 8;
                int32_t cr[4] = { cx, (H - rh) / 2, cx + 1, (H - rh) / 2 + rh };
                wn_handle cb = g32_CreateSolidBrush(0);
                g32_FillRect(hdc, cr, cb);
                wn_handle_close(cb);
            }
            break;
        }
        case CTL_STATIC: {
            uint32_t ss = w->style & 0x1F;
            if (ss == 0x1 /*SS_ICON*/ || ss == 0x3 /*SS_BITMAP*/) {
                /* resource painting handled via STM_SETIMAGE later */
            } else {
                int32_t tr[4] = { 4, 0, W - 4, H };
                uint32_t fmt = 0x20 | 0x100 | 0x24;
                if ((w->style & 0x3) == 0x1) fmt |= 2;          /* RIGHT */
                else if ((w->style & 0x3) == 0x2) fmt |= 6;     /* CENTER */
                g32_DrawTextA(hdc, w->title, -1, tr, fmt);
            }
            break;
        }
        case CTL_LISTBOX: {
            int rows = (H - 2) / rh;
            for (int i = 0; i < rows; i++) {
                int idx = w->top_item + i;
                if (idx >= w->n_items)
                    break;
                int yy = 1 + i * rh;
                if (idx == w->sel) {
                    int32_t sr[4] = { 1, yy, W - 1, yy + rh };
                    wn_handle sb = g32_CreateSolidBrush(0x00A8000A);
                    g32_FillRect(hdc, sr, sb);
                    wn_handle_close(sb);
                    g32_SetTextColor(hdc, 0x00FFFFFF);
                } else {
                    g32_SetTextColor(hdc, 0);
                }
                g32_TextOutA(hdc, 5, yy + 1, w->items[idx], -1);
            }
            g32_SetTextColor(hdc, 0);
            break;
        }
        case CTL_COMBO: {
            /* closed combo: edit field + arrow button */
            int32_t tr[4] = { 3, (H - rh - 2) / 2, W - 20, (H + rh) / 2 };
            g32_TextOutA(hdc, 3, (H - rh - 2) / 2,
                         w->sel >= 0 && w->sel < w->n_items ?
                         w->items[w->sel] : w->title, -1);
            (void)tr;
            wn_handle ab = g32_CreateSolidBrush(0x00A0A0A0);
            int32_t ar[4] = { W - 18, 1, W - 1, H - 1 };
            g32_FillRect(hdc, ar, ab);
            wn_handle_close(ab);
            break;
        }
        case CTL_SCROLLBAR:
        default:
            if (w->title[0])
                g32_TextOutA(hdc, 4, (H - rh) / 2, w->title, -1);
            break;
        }
        g32_ReleaseDC(hwnd, hdc);
        compose_child(w);
        return 0;
    }
    case WN_WM_CHAR: {
        if (k == CTL_EDIT) {
            ctl_edit_char(w, (uint16_t)wp);
            ctl_repaint(w);
            return 0;
        }
        return 0;
    }
    case WN_WM_LBUTTONDOWN: {
        switch (k) {
        case CTL_BUTTON: {
            uint32_t bs = w->style & 0xF;
            if (bs == 0x2 || bs == 0x9) {    /* auto check / auto radio */
                if (bs == 0x9) {
                    /* uncheck radio group siblings (same WS_GROUP run) */
                    for (int i = 0; i < g_hwnd_count; i++) {
                        wn_window *c = g_hwnds[i].win;
                        if (!c || c->parent != w->parent || !c->cls ||
                            !wn_strcaseeq(c->cls->name, "Button"))
                            continue;
                        if (c->style & 0x20000 /*WS_GROUP*/) {
                            if (c == w)
                                break;       /* entered our group */
                            /* still in an earlier group: reset marker */
                        }
                        if (c != w && (c->style & 0xF) == 0x9)
                            c->check = BST_UNCHECKED;
                    }
                    w->check = BST_CHECKED;
                } else {
                    w->check = w->check ? BST_UNCHECKED : BST_CHECKED;
                }
                ctl_repaint(w);
            }
            ctl_notify(w, 0 /* BN_CLICKED */);
            return 0;
        }
        case CTL_LISTBOX: {
            int rh = ctl_row_h();
            int my = (int)(int16_t)((uint64_t)lp >> 16);
            int idx = w->top_item + (my - 1) / rh;
            if (idx >= 0 && idx < w->n_items && idx != w->sel) {
                w->sel = idx;
                ctl_repaint(w);
                ctl_notify(w, 1 /* LBN_SELCHANGE */);
            } else if (idx >= 0 && idx < w->n_items) {
                ctl_notify(w, 2 /* LBN_DBLCLK-ish: second click */);
            }
            return 0;
        }
        case CTL_COMBO:
            ctl_notify(w, 1 /* CBN_SELCHANGE placeholder: open list */);
            return 0;
        default:
            return 0;
        }
    }
    case BM_GETCHECK:   return (uint64_t)w->check;
    case BM_SETCHECK:   w->check = (uint32_t)wp & 3; ctl_repaint(w); return 0;
    case BM_CLICK: {
        ctl_notify(w, 0 /* BN_CLICKED */);
        return 0;
    }
    case WN_WM_GETTEXT: {
        if (w->is_uni)
            return ctl_get_text_w(w, (uint16_t *)(uintptr_t)lp, (size_t)wp);
        return ctl_get_text(w, (char *)(uintptr_t)lp, (size_t)wp);
    }
    case WN_WM_GETTEXTLENGTH: {
        size_t n = 0;
        while (w->wtext[n]) n++;
        return (int64_t)n;
    }
    case WN_WM_SETTEXT: {
        if (w->is_uni) {
            char *a = wn_utf16_to_utf8((const uint16_t *)(uintptr_t)lp, 4096);
            ctl_set_text(w, a);
            free(a);
        } else {
            ctl_set_text(w, (const char *)(uintptr_t)lp);
        }
        ctl_repaint(w);
        return 1;
    }
    case EM_GETSEL: {
        int32_t *sel = (int32_t *)(uintptr_t)lp;
        if (sel) { sel[0] = w->caret; sel[1] = w->caret; }
        return 0;
    }
    case EM_SETSEL: w->caret = (int)(int32_t)(wp & 0xFFFFFFFF); return 0;
    case EM_SETLIMITTEXT: return 0;
    case EM_GETLINECOUNT: return 1;
    case EM_REPLACESEL: {
        ctl_set_text(w, (const char *)(uintptr_t)lp);
        ctl_repaint(w);
        ctl_notify(w, 0x0300 /* EN_CHANGE */);
        return 0;
    }
    case LB_ADDSTRING:
    case CB_ADDSTRING: {
        char *a = (lp && (wp & 1)) ? wn_utf16_to_utf8((const uint16_t *)(uintptr_t)lp, 4096)
                                   : wn_xstrdup(lp ? (const char *)(uintptr_t)lp : "");
        int idx = ctl_items_add(w, a);
        free(a);
        if (idx >= 0 && msg == CB_ADDSTRING && w->n_items == 1)
            w->sel = 0;
        ctl_repaint(w);
        return (uint64_t)(idx >= 0 ? idx : -1);
    }
    case LB_DELETESTRING:
    case CB_DELETESTRING: {
        int idx = (int)(int32_t)wp;
        if (idx < 0 || idx >= w->n_items)
            return -1;
        free(w->items[idx]);
        memmove(&w->items[idx], &w->items[idx + 1],
                (size_t)(w->n_items - idx - 1) * sizeof(char *));
        w->n_items--;
        if (w->sel > idx) w->sel--;
        if (w->sel == idx) w->sel = -1;
        ctl_repaint(w);
        return 0;
    }
    case LB_GETCOUNT:
    case CB_GETCOUNT: return (uint64_t)w->n_items;
    case LB_GETCURSEL:
    case CB_GETCURSEL: return (uint64_t)(w->sel >= 0 ? w->sel : -1);
    case LB_SETCURSEL:
    case CB_SETCURSEL: {
        int idx = (int)(int32_t)wp;
        if (idx < 0 || idx >= w->n_items)
            w->sel = -1;
        else
            w->sel = idx;
        ctl_repaint(w);
        return (uint64_t)(idx >= 0 && idx < w->n_items ? idx : -1);
    }
    case LB_GETTEXT:
    case CB_GETLBTEXT: {
        int idx = (int)(int32_t)wp;
        if (idx < 0 || idx >= w->n_items)
            return -1;
        if (lp && (msg == LB_GETTEXT || msg == CB_GETLBTEXT)) {
            /* ANSI form: caller buffer is `wp` bytes... we mirror title. */
            snprintf((char *)(uintptr_t)lp, 512, "%s", w->items[idx]);
        }
        return (int64_t)strlen(w->items[idx]);
    }
    case LB_GETTEXTLEN:
    case CB_GETLBTEXTLEN: {
        int idx = (int)(int32_t)wp;
        if (idx < 0 || idx >= w->n_items)
            return -1;
        return (int64_t)strlen(w->items[idx]);
    }
    case LB_RESETCONTENT:
    case CB_RESETCONTENT:
        ctl_items_clear(w);
        ctl_repaint(w);
        return 0;
    case LB_SETTOPINDEX:
        w->top_item = (int)(int32_t)wp;
        ctl_repaint(w);
        return 0;
    case SBM_SETPOS: {
        int64_t old = w->sel;
        w->sel = (int)(int32_t)wp;
        ctl_repaint(w);
        return old;
    }
    case SBM_GETPOS: return (uint64_t)w->sel;
    case SBM_SETRANGE: return 0;
    case SBM_GETRANGE: return 0;
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
/* --- IsDialogMessage: dialog keyboard navigation ----------------------------------
 * Tab/Shift-Tab cycle WS_TABSTOP children; Enter -> IDOK; Esc -> IDCANCEL;
 * arrows move radio selection within a WS_GROUP run. MSG x64:
 * hwnd@0(8), message@8(4), wParam@0x10(8), lParam@0x18(8). */
static int32_t u32_IsDialogMessage_impl(const uint8_t *msg)
{
    if (!msg)
        return 0;
    uint64_t hwnd = *(const uint64_t *)(const void *)msg;
    uint32_t message = *(const uint32_t *)(const void *)(msg + 8);
    uint64_t wp = *(const uint64_t *)(const void *)(msg + 0x10);
    wn_window *dlg = win_from_hwnd(hwnd);
    if (!dlg || !dlg->is_dialog)
        return 0;
    if (message != WN_WM_KEYDOWN)
        return 0;
    uint32_t vk = (uint32_t)wp;
    /* collect direct children in creation order */
    wn_window *kids[64];
    int nk = 0;
    for (int i = 0; i < g_hwnd_count && nk < 64; i++) {
        wn_window *c = g_hwnds[i].win;
        if (c && c->parent == hwnd && !c->in_destroy)
            kids[nk++] = c;
    }
    int cur = -1;
    for (int i = 0; i < nk; i++)
        if ((uint64_t)(uintptr_t)hwnd_of_window(kids[i]) == g_focus_hwnd)
            cur = i;
    if (vk == 0x09 /*VK_TAB*/) {
        int shift = 0;   /* (GetKeyState-based; v1: plain Tab forward) */
        int start = cur >= 0 ? cur : -1;
        for (int step = shift ? -1 : 1, i = start + step, guard = 0;
             guard < nk; i = (i + nk) % nk, guard++) {
            if (i < 0)
                i = nk - 1;
            if (kids[i]->style & 0x10000 /*WS_TABSTOP*/) {
                user32_set_focus_internal((uint64_t)(uintptr_t)
                                          hwnd_of_window(kids[i]));
                return 1;
            }
        }
        return 1;   /* consumed even if no tabstops */
    }
    if (vk == 0x0D /*VK_RETURN*/) {
        /* default button: WS_DEFPUSHBUTTON(0x2000) first, else IDOK 1/2 */
        for (int i = 0; i < nk; i++) {
            if (kids[i]->cls && wn_strcaseeq(kids[i]->cls->name, "Button") &&
                (kids[i]->style & 0x2000)) {
                ctl_notify(kids[i], 0 /*BN_CLICKED*/);
                return 1;
            }
        }
        for (int i = 0; i < nk; i++) {
            if (kids[i]->id == 1 /*IDOK*/ || kids[i]->id == 2 /*IDCANCEL*/) {
                ctl_notify(kids[i], 0);
                return 1;
            }
        }
        return 0;   /* let Enter reach the focused control (multiline edit) */
    }
    if (vk == 0x1B /*VK_ESCAPE*/) {
        for (int i = 0; i < nk; i++) {
            if (kids[i]->id == 2 /*IDCANCEL*/) {
                ctl_notify(kids[i], 0);
                return 1;
            }
        }
        return 1;
    }
    if (vk == 0x25 /*LEFT*/ || vk == 0x27 /*RIGHT*/) {
        /* radio group navigation around the focused radio */
        if (cur >= 0 && kids[cur]->cls &&
            wn_strcaseeq(kids[cur]->cls->name, "Button") &&
            (kids[cur]->style & 0xF) == 0x9) {
            int dir = vk == 0x25 ? -1 : 1;
            for (int i = cur + dir, guard = 0; guard < nk;
                 i = (i + nk) % nk, guard++) {
                if (kids[i]->style & 0x20000 /*WS_GROUP: stop at group edge*/)
                    break;
                if (kids[i]->cls && wn_strcaseeq(kids[i]->cls->name, "Button") &&
                    (kids[i]->style & 0xF) == 0x9) {
                    kids[i]->check = BST_CHECKED;
                    kids[cur]->check = BST_UNCHECKED;
                    user32_set_focus_internal((uint64_t)(uintptr_t)
                                              hwnd_of_window(kids[i]));
                    ctl_notify(kids[i], 0 /*BN_CLICKED*/);
                    ctl_repaint(kids[i]);
                    return 1;
                }
            }
        }
    }
    return 0;
}

static WN_API int32_t u32_IsDialogMessageA(void *msg)
{
    return u32_IsDialogMessage_impl((const uint8_t *)msg);
}

static WN_API int64_t u32_DialogBoxParamA(uint64_t hinst, const void *tmpl,
                                          uint64_t parent, uint64_t dlgproc,
                                          uint64_t param)
{
    uint64_t hwnd = create_dialog_from_template(hinst, tmpl, parent, dlgproc,
                                                param, 1);
    if (!hwnd)
        return -1;
    wn_window *dw = win_from_hwnd(hwnd);
    /* initial focus: first WS_TABSTOP child (Windows semantics) */
    {
        uint64_t first_tab = 0;
        for (int i = 0; i < g_hwnd_count && !first_tab; i++) {
            wn_window *c = g_hwnds[i].win;
            if (c && c->parent == hwnd && (c->style & 0x10000))
                first_tab = (uint64_t)(uintptr_t)hwnd_of_window(c);
        }
        user32_set_focus_internal(first_tab ? first_tab : hwnd);
        u32_SetActiveWindow(hwnd);
    }
    wn_msg m;
    while (!dw->dlg_done) {
        int32_t r = u32_GetMessageA(&m, 0, 0, 0);
        if (r <= 0)
            break;
        if (!u32_IsDialogMessageA(&m))
            u32_DispatchMessageA(&m);
    }
    user32_set_focus_internal(0);
    u32_SetActiveWindow(parent ? parent : 0);
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

/* --- cursors + icons ------------------------------------------------------------
 * LoadCursor/LoadIcon return handle-backed resources; the standard IDC_/IDI_
 * names draw from built-in pixel art. Exe resource icons load through
 * kernel32's RT_GROUP_ICON/RT_ICON machinery (resource walker). */

typedef struct {
    uint32_t id;             /* numeric resource id or 0 for named */
    int is_icon;             /* 0 = cursor, 1 = icon */
} u32_res;

static wn_handle res_handle(uint32_t id, int is_icon)
{
    u32_res *r = wn_xcalloc(1, sizeof *r);
    r->id = id;
    r->is_icon = is_icon;
    return wn_handle_alloc(WN_HTYPE_GFX, r);
}

static uint32_t res_name_to_id(const char *name, const char *const *names,
                               int base)
{
    /* "#123" or "IDC_ARROW"-style: compare sz form. */
    if (!name || !*name)
        return 0;
    if (name[0] == '#') {
        long v = strtol(name + 1, NULL, 10);
        return (uint32_t)v;
    }
    for (int i = 0; names[i]; i++)
        if (!strcmp(name, names[i]))
            return (uint32_t)(base + i);
    /* strip path: "res\\IDC_ARROW" */
    const char *bs = strrchr(name, '\\');
    if (bs)
        return res_name_to_id(bs + 1, names, base);
    return 0;
}

static const char *const g_idc_names[] = {
    "IDC_APPSTARTING", "IDC_ARROW", "IDC_CROSS", "IDC_HAND", "IDC_HELP",
    "IDC_IBEAM", "IDC_ICON", "IDC_NO", "IDC_SIZE", "IDC_SIZEALL",
    "IDC_SIZENESW", "IDC_SIZENS", "IDC_SIZENWSE", "IDC_SIZEWE", "IDC_UPARROW",
    "IDC_WAIT", NULL
};
static const char *const g_idi_names[] = {
    "IDI_APPLICATION", "IDI_ASTERISK", "IDI_ERROR", "IDI_EXCLAMATION",
    "IDI_HAND", "IDI_INFORMATION", "IDI_QUESTION", "IDI_SHIELD", "IDI_WARNING",
    "IDI_WINLOGO", NULL
};

static WN_API wn_handle u32_LoadCursorA(uint64_t hinst, const char *name)
{
    (void)hinst;   /* process-defined cursors: not yet (documented gap) */
    uint32_t id = res_name_to_id(name, g_idc_names, 32512 /*IDC_ARROW base*/);
    if (!id)
        wn_log(WN_LOG_WARN, "user32: LoadCursorA('%s') unknown", name);
    return res_handle(id, 0);
}

static WN_API wn_handle u32_LoadCursorW(uint64_t hinst, const uint16_t *name)
{
    char *a = name ? wn_utf16_to_utf8(name, 256) : NULL;
    wn_handle h = u32_LoadCursorA(hinst, a);
    free(a);
    return h;
}

static WN_API wn_handle u32_LoadIconA(uint64_t hinst, const char *name)
{
    uint32_t id = res_name_to_id(name, g_idi_names, 100 /*IDI base*/);
    if (hinst && hinst != (uint64_t)(uintptr_t)g_proc.exe->base) {
        wn_log(WN_LOG_DEBUG, "user32: LoadIconA(hinst=0x%llx) '%s' -> "
               "resource walk", (unsigned long long)hinst, name);
    }
    if (!id && name && name[0] == '#')
        id = res_name_to_id(name, g_idi_names, 100);
    return res_handle(id, 1);
}

static WN_API wn_handle u32_LoadIconW(uint64_t hinst, const uint16_t *name)
{
    char *a = name ? wn_utf16_to_utf8(name, 256) : NULL;
    wn_handle h = u32_LoadIconA(hinst, a);
    free(a);
    return h;
}

static WN_API wn_handle u32_SetCursor(wn_handle cur)
{
    wn_handle old = 0;
    /* visual cursor shaping is a backend feature (later); the handle
     * round-trips so apps can restore the previous cursor. */
    (void)cur;
    return old;
}

/* DrawTextA/W: documented as user32 APIs (the rasterizer lives in gdi32,
 * which is where our engine is). */
static WN_API int32_t u32_DrawTextA(wn_handle hdc, const char *s,
                                    int32_t count, void *rect, uint32_t fmt)
{
    extern WN_API int32_t g32_DrawTextA(wn_handle, const char *, int32_t,
                                        void *, uint32_t);
    return g32_DrawTextA(hdc, s, count, rect, fmt);
}

static WN_API int32_t u32_DrawTextW(wn_handle hdc, const uint16_t *s,
                                    int32_t count, void *rect, uint32_t fmt)
{
    extern WN_API int32_t g32_DrawTextW(wn_handle, const uint16_t *, int32_t,
                                        void *, uint32_t);
    return g32_DrawTextW(hdc, s, count, rect, fmt);
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
    { "CheckDlgButton", u32_CheckDlgButton },
    { "DrawTextA", u32_DrawTextA },
    { "DrawTextW", u32_DrawTextW },
    { "CheckRadioButton", u32_CheckRadioButton },
    { "GetActiveWindow", u32_GetActiveWindow },
    { "GetDesktopWindow", u32_GetDesktopWindow },
    { "GetDlgItem", u32_GetDlgItem },
    { "GetFocus", u32_GetFocus },
    { "GetForegroundWindow", u32_GetForegroundWindow },
    { "GetWindowLongA", u32_GetWindowLongA },
    { "GetWindowLongW", u32_GetWindowLongW },
    { "GetWindowLongPtrA", u32_GetWindowLongPtrA },
    { "GetWindowLongPtrW", u32_GetWindowLongPtrW },
    { "IsDlgButtonChecked", u32_IsDlgButtonChecked },
    { "LoadCursorA", u32_LoadCursorA },
    { "SetCursor", u32_SetCursor },
    { "LoadCursorW", u32_LoadCursorW },
    { "LoadIconA", u32_LoadIconA },
    { "LoadIconW", u32_LoadIconW },
    { "MapDialogRect", u32_MapDialogRect },
    { "SetActiveWindow", u32_SetActiveWindow },
    { "SetFocus", u32_SetFocus },
    { "SetWindowLongA", u32_SetWindowLongA },
    { "SetWindowLongW", u32_SetWindowLongW },
    { "SetWindowLongPtrA", u32_SetWindowLongPtrA },
    { "SetWindowLongPtrW", u32_SetWindowLongPtrW },
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
