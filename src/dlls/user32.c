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
#include "wn_format.h"

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
    WN_API wn_abiword (*proc)(wn_abiword, uint32_t, wn_abiword,
                              wn_abiword_s);
    uint32_t style;
    uint32_t cb_wnd_extra;      /* bytes of GWLP storage past the fixed area */
    int used;
} wn_wndclass;

typedef struct wn_timer {
    uint64_t hwnd;
    uintptr_t id;
    uint64_t period_ms;
    uint64_t next_fire;
    WN_API void (*proc)(wn_abiword, uint32_t, uintptr_t, uint32_t);
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
    uint64_t owner;           /* top-level OWNER (dialogs): not a parent */
    int wx, wy;               /* position in parent / on screen */
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
static int g_backend_up;
static int g_quit_posted;
static uint32_t g_quit_code;
static void tv_free(wn_window *w);       /* tree view payload (defined later) */
static int ctl_row_h(void);              /* control row height (defined later) */
static uint64_t g_paint_counter;
/* focus + activation (single-GUI-thread model). */
static uint64_t g_focus_hwnd;       /* 0 = unset */
static uint64_t g_active_hwnd;      /* 0 = unset */
static uint64_t g_capture_hwnd;    /* mouse capture window (SetCapture) */
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
static void win_screen_origin(wn_window *w, int *x, int *y);
static WN_API uint64_t u32_SendMessageA(wn_abiword hwnd, uint32_t msg,
                                        wn_abiword wp, wn_abiword_s lp);
static WN_API int32_t u32_MessageBoxW(wn_abiword hwnd, const uint16_t *text,
                                     const uint16_t *caption, uint32_t type);
#define DLG_X(n) ((int)((n) * 4 / 2 + ((n) & 1)))
#define DLG_Y(n) ((int)((n) * 8 / 2))

/* Synchronous delivery — Windows sends WM_SIZE/WM_MOVE from INSIDE
 * SetWindowPos/MoveWindow (they are never queued). Apps measure with
 * GetWindowRect right after MoveWindow and relayout synchronously; queueing
 * them also let putty's layout bursts overflow the queue. */
static void deliver_now(uint64_t hwnd, uint32_t msg, uint64_t wp, int64_t lp)
{
    u32_SendMessageA(hwnd, msg, wp, lp);
}

/* --- queue -------------------------------------------------------------------- */

/* Growable ring buffer. Windows coalesces WM_MOUSEMOVE (only the newest
 * pending position exists per queue) and generates WM_PAINT from the update
 * region instead of queueing it — putty's layout code used to flood 128-slot
 * queue with WM_SIZE/WM_PAINT pairs and the overflow DROPPED real input
 * (user-visible: "message queue overflow (dropped 0x5/0xf/0x200)" spam and
 * dead clicks). We keep the ring small and grow it only if a burst survives
 * coalescing (cross-thread posts). */
#define WN_MSG_QUEUE_DEPTH 128
#define WN_MSG_QUEUE_MAX   8192

static wn_msg *g_queue;               /* malloc'd ring, g_q_depth slots */
static int g_q_depth = WN_MSG_QUEUE_DEPTH;
static int g_q_head, g_q_count;
static int g_msg_fd = -1;

static void queue_push(const wn_msg *m)
{
    if (!g_queue)
        g_queue = wn_xmalloc((size_t)WN_MSG_QUEUE_DEPTH * sizeof(wn_msg));
    /* WM_MOUSEMOVE coalescing: replace a pending move for the same window
     * in place (keeps queue order, updates to the newest position). */
    if (m->message == 0x0200 /* WM_MOUSEMOVE */) {
        for (int i = 0; i < g_q_count; i++) {
            int slot = (g_q_head + i) % g_q_depth;
            if (g_queue[slot].message == 0x0200 &&
                g_queue[slot].hwnd == m->hwnd) {
                g_queue[slot] = *m;
                return;
            }
        }
    }
    if (g_q_count >= g_q_depth) {
        if (g_q_depth < WN_MSG_QUEUE_MAX) {
            int nd = g_q_depth * 2;
            wn_msg *nq = wn_xmalloc((size_t)nd * sizeof(wn_msg));
            for (int i = 0; i < g_q_count; i++)
                nq[i] = g_queue[(g_q_head + i) % g_q_depth];
            free(g_queue);
            g_queue = nq;
            g_q_head = 0;
            g_q_depth = nd;
        } else {
            wn_log(WN_LOG_WARN, "user32: message queue overflow at %d "
                   "(dropped 0x%x)", g_q_depth, m->message);
            return;
        }
    }
    g_queue[(g_q_head + g_q_count) % g_q_depth] = *m;
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
    g_q_head = (g_q_head + 1) % g_q_depth;
    g_q_count--;
    return 1;
}

/* Peek without removing (PeekMessage PM_NOREMOVE). */
static int queue_peek(wn_msg *out)
{
    if (g_q_count == 0)
        return 0;
    *out = g_queue[g_q_head];
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

/* cursor + keyboard-state tracking (GetCursorPos/GetKeyboardState). */
static int g_mouse_x = -1, g_mouse_y = -1;
static uint8_t g_key_state[256];
static uint32_t g_last_msg_time;

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
        /* WM_PAINT is generated from the dirty flag by the message pump —
         * NEVER posted directly (queue-flood bug, see queue_push comment). */
        break;
    case WN_BEV_CONFIGURE: {
        /* moved without resizing (WM drag): update + queued WM_MOVE */
        if (w->parent == 0) {
            w->wx = ev->x;
            w->wy = ev->y;
            post_msg(h, WN_WM_MOVE, 0,
                     (int64_t)(((uint64_t)(uint16_t)ev->x) |
                               ((uint64_t)(uint16_t)ev->y << 16)));
        }
        break;
    }
    case WN_BEV_RESIZE:
        if (b->pixels) {
            b->width = ev->x;
            b->height = ev->y;
            b->stride = ev->x * 4;
            free(b->pixels);
            b->pixels = wn_xmalloc((size_t)ev->x * ev->y * 4 + 64);
            memset(b->pixels, 0xFF, (size_t)ev->x * ev->y * 4);
        }
        if (w->parent == 0) {
            w->cw = ev->x;
            w->ch = ev->y;
            /* the backend knows its position; sync it for GetWindowRect */
            const wn_backend *be = wn_backend_get();
            if (be && be->win_pos)
                be->win_pos(b, &w->wx, &w->wy);
        }
        deliver_now(h, WN_WM_SIZE, 0,
                    (int64_t)(((uint64_t)(uint16_t)ev->x) |
                              ((uint64_t)(uint16_t)ev->y << 16)));
        break;
    case WN_BEV_CLOSE:
        post_msg(h, WN_WM_CLOSE, 0, 0);
        break;
    case WN_BEV_KEY:
    case WN_BEV_KEYUP: {
        uint32_t vk = wn_user32_vk_from_keysym((uint32_t)ev->val);
        if (vk) {
            /* keyboard-state tracking for GetKeyboardState */
            if (vk < 256) {
                if (ev->type == WN_BEV_KEY)
                    g_key_state[vk / 8] |= (uint8_t)(1u << (vk % 8));
                else
                    g_key_state[vk / 8] &= (uint8_t)~(1u << (vk % 8));
            }
            /* keyboard goes to the FOCUS window, not the event window */
            uint64_t target = g_focus_hwnd ? g_focus_hwnd : h;
            wn_window *tw = win_from_hwnd(target);
            if (!tw)
                target = h;
            post_msg(target, ev->type == WN_BEV_KEY ? WN_WM_KEYDOWN
                                                    : WN_WM_KEYUP, vk, 0);
        }
        break;
    }
    case WN_BEV_TEXT:
        post_msg(g_focus_hwnd ? g_focus_hwnd : h, WN_WM_CHAR,
                 (uint64_t)(uint32_t)ev->val, 0);
        break;
    case WN_BEV_MOUSE_MOVE:
        /* approximate cursor tracking for GetCursorPos (root coords) */
        {
            int ox, oy;
            win_screen_origin(w, &ox, &oy);
            g_mouse_x = ox + ev->x;
            g_mouse_y = oy + ev->y;
        }
        post_msg(g_capture_hwnd ? g_capture_hwnd : h, WN_WM_MOUSEMOVE, 0,
                 (int64_t)(((uint64_t)(uint16_t)ev->x) |
                           ((uint64_t)(uint16_t)ev->y << 16)));
        break;
    case WN_BEV_MOUSE_BUTTON: {
        wn_log(WN_LOG_TRACE, "user32: mouse button win=%llx val=%d btn=%d "
               "at %d,%d", (unsigned long long)h, ev->val, ev->val2,
               ev->x, ev->y);
        uint32_t msg = 0;
        uint64_t wp = 1 /* MK_LBUTTON */;
        if (ev->val2 == 1)      msg = ev->val ? WN_WM_LBUTTONDOWN : WN_WM_LBUTTONUP;
        else if (ev->val2 == 3) { msg = ev->val ? WN_WM_RBUTTONDOWN : WN_WM_RBUTTONUP; wp = 2; }
        if (msg) {
            /* Disabled top-level windows eat no input: putty disables its
             * config box while the About modal is up, and X11 still
             * delivers clicks to that window. */
            wn_window *ew = win_from_hwnd(h);
            if (ew && (ew->style & 0x08000000u /*WS_DISABLED*/) &&
                !g_capture_hwnd)
                break;
            /* Captured window eats all button messages (Windows contract). */
            if (g_capture_hwnd) {
                post_msg(g_capture_hwnd, msg, wp,
                         (int64_t)(((uint64_t)(uint16_t)ev->x) |
                                   ((uint64_t)(uint16_t)ev->y << 16)));
                break;
            }
            /* hit-test: deliver to the deepest visible, ENABLED child under
             * the cursor, with coordinates translated to its origin. Windows
             * never delivers mouse input to WS_DISABLED windows — putty
             * disables the config box while its About modal runs and the
             * clicks MUST fall through. */
            uint64_t target = h;
            int mx = (int)(int16_t)ev->x, my = (int)(int16_t)ev->y;
            for (int depth = 0; depth < 8; depth++) {
                uint64_t next = 0;
                int nx = 0, ny = 0;
                for (int i = 0; i < g_hwnd_count; i++) {
                    wn_window *c = g_hwnds[i].win;
                    if (!c || c->parent != target || !c->visible ||
                        c->in_destroy || (c->style & 0x08000000u /*WS_DISABLED*/))
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
    if (g_msg_fd < 0)
        return -1;
    /* state=1 on success — WITHOUT this, every CreateWindowEx re-ran
     * wn_backend_init() and created a NEW eventfd, overwriting g_msg_fd
     * and leaking the old fd per call (dialog items! ~50 per dialog).
     * After a long interactive session the process hit EMFILE ("Too
     * many open files") and the registry save was the first casualty
     * (user-reported: cannot open system.reg.tmp for write). */
    state = 1;
    return 0;
}

static WN_API int32_t u32_ShowWindow(wn_abiword hwnd, int32_t cmd)
{
    wn_window *w = win_from_hwnd(hwnd);
    if (!w || !w->bwin)
        return 0;
    const wn_backend *be = wn_backend_get();
    int was_visible = w->visible;
    /* Only top-level windows have a real backend surface; children are
     * offscreen surfaces composed by their parent (be->win_show on a child
     * bwin crashed on priv=NULL — the putty About-box segfault). */
    if (!w->parent && be && be->win_show)
        be->win_show(w->bwin);
    if (cmd != 0 /* SW_HIDE */)
        w->visible = 1;
    else
        w->visible = 0;
    if (w->parent && w->visible)
        compose_child(w);
    return was_visible;
}

/* --- MoveWindow / SetWindowPos ----------------------------------------------------
 * Children: coordinates update + parent recompose. Top-level: backend
 * window resize (pixel buffer reallocated). WM_SIZE/WM_MOVE are DELIVERED
 * synchronously (Windows semantics: they are sent inside SetWindowPos,
 * never queued); WM_PAINT is scheduled via the dirty flag only. */
static void compose_children_of(uint64_t parent);   /* fwd (defined later) */
static void user32_move_resize(uint64_t hwnd, int x, int y, int w, int h,
                               int do_move, int do_size)
{
    wn_window *win = win_from_hwnd(hwnd);
    if (!win)
        return;
    if (do_size && w < 1)
        w = 1;
    if (do_size && h < 1)
        h = 1;
    int old_w = win->cw, old_h = win->ch;
    int old_x = win->wx, old_y = win->wy;
    if (win->parent) {                 /* child: coords + recompose parent */
        if (do_move) { win->wx = x; win->wy = y; }
        if (do_size) { win->cw = w; win->ch = h; }
        if (win->bwin) {
            win->bwin->width = win->cw;
            win->bwin->height = win->ch;
            win->bwin->stride = win->cw * 4;
            free(win->bwin->pixels);
            win->bwin->pixels = wn_xmalloc((size_t)win->cw * win->ch * 4 + 64);
            memset(win->bwin->pixels, 0xFF, (size_t)win->cw * win->ch * 4);
        }
        compose_children_of(win->parent);
    } else {                           /* top-level: backend move/resize */
        if (do_move) { win->wx = x; win->wy = y; }
        if (do_size && (win->cw != w || win->ch != h)) {
            const wn_backend *be = wn_backend_get();
            if (be && be->win_move_resize)
                be->win_move_resize(win->bwin, x, y, w, h);
            win->bwin->width = win->cw = w;
            win->bwin->height = win->ch = h;
            win->bwin->stride = w * 4;
            compose_children_of(hwnd);
        } else if (do_move && win->bwin) {
            const wn_backend *be = wn_backend_get();
            if (be && be->win_move_resize)
                be->win_move_resize(win->bwin, x, y, win->cw, win->ch);
        }
    }
    if (do_size && (win->cw != old_w || win->ch != old_h))
        deliver_now(hwnd, WN_WM_SIZE, 0,
                    (int64_t)(((uint64_t)(uint16_t)win->cw) |
                              ((uint64_t)(uint16_t)win->ch << 16)));
    if (do_move && (win->wx != old_x || win->wy != old_y))
        deliver_now(hwnd, WN_WM_MOVE, 0,
                    (int64_t)(((uint64_t)(uint16_t)win->wx) |
                              ((uint64_t)(uint16_t)win->wy << 16)));
    /* full-surface damage: the pump will synthesize ONE WM_PAINT */
    win->dirty.l = 0;
    win->dirty.t = 0;
    win->dirty.r = win->cw;
    win->dirty.b = win->ch;
    if (win->parent && win->visible)
        compose_child(win);
}

static WN_API int32_t u32_MoveWindow(wn_abiword hwnd, int32_t x, int32_t y,
                                     int32_t w, int32_t h, int32_t repaint)
{
    (void)repaint;
    wn_log(WN_LOG_TRACE, "user32: MoveWindow hwnd=0x%llx %d,%d %dx%d",
           (unsigned long long)hwnd, x, y, w, h);
    if (!win_from_hwnd(hwnd)) {
        wn_last_error_set(WN_ERR_INVALID_HANDLE);
        return 0;
    }
    user32_move_resize(hwnd, x, y, w, h, 1, 1);
    return 1;
}

static WN_API int32_t u32_SetWindowPos(wn_abiword hwnd, wn_abiword after,
                                       int32_t x, int32_t y, int32_t cx,
                                       int32_t cy, uint32_t flags)
{
    wn_window *win = win_from_hwnd(hwnd);
    if (!win) {
        wn_last_error_set(WN_ERR_INVALID_HANDLE);
        return 0;
    }
    wn_log(WN_LOG_TRACE, "user32: SetWindowPos hwnd=0x%llx %d,%d %dx%d "
           "flags=0x%x", (unsigned long long)hwnd, x, y, cx, cy, flags);
    (void)after;   /* Z-order changes: unsupported (single-layer compose) */
    if (!(flags & 0x0001 /* SWP_NOSIZE */)) {
        if (cx < 1) cx = 1;
        if (cy < 1) cy = 1;
        user32_move_resize(hwnd, x, y, cx, cy,
                           !(flags & 0x0002 /* SWP_NOMOVE */) ? 1 : 0, 1);
    } else if (!(flags & 0x0002 /* SWP_NOMOVE */)) {
        user32_move_resize(hwnd, x, y, win->cw, win->ch, 1, 0);
    } else {
        return 1;
    }
    if (flags & 0x0040 /* SWP_SHOWWINDOW */)
        u32_ShowWindow(hwnd, 5);
    else if (flags & 0x0080 /* SWP_HIDEWINDOW */)
        u32_ShowWindow(hwnd, 0);
    return 1;
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

static WN_API uint64_t u32_SetFocus(wn_abiword hwnd)
{
    uint64_t old = g_focus_hwnd;
    user32_set_focus_internal(hwnd);
    return old;
}

static WN_API uint64_t u32_GetFocus(void)
{
    return g_focus_hwnd;
}

static WN_API uint64_t u32_SetActiveWindow(wn_abiword hwnd)
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

/* --- mouse capture + registered messages ------------------------------------
 * SetCapture/ReleaseCapture route mouse messages to the captured window;
 * RegisterWindowMessage returns a unique id >= 0xC000 (Windows contract).
 * Putty's button handlers call ReleaseCapture on every click. */
static uint32_t g_next_regmsg = 0xC000;

static WN_API uint64_t u32_SetCapture(wn_abiword hwnd)
{
    uint64_t old = g_capture_hwnd;
    if (win_from_hwnd(hwnd))
        g_capture_hwnd = hwnd;
    return old;
}

static WN_API int32_t u32_ReleaseCapture(void)
{
    int32_t had = g_capture_hwnd != 0;
    g_capture_hwnd = 0;
    return had;
}

static WN_API uint64_t u32_GetCapture(void)
{
    return g_capture_hwnd;
}

static WN_API uint32_t u32_RegisterWindowMessageA(const char *name)
{
    if (!name || !*name) {
        wn_last_error_set(WN_ERR_INVALID_PARAMETER);
        return 0;
    }
    if (g_next_regmsg >= 0xFFFF)
        return 0;
    wn_log(WN_LOG_DEBUG, "user32: RegisterWindowMessageA('%s') -> 0x%04X",
           name, g_next_regmsg);
    return g_next_regmsg++;
}

static WN_API uint32_t u32_RegisterWindowMessageW(const uint16_t *name)
{
    char *a = name ? wn_utf16_to_utf8(name, 256) : NULL;
    uint32_t r = a ? u32_RegisterWindowMessageA(a) : 0;
    free(a);
    return r;
}

/* Desktop pseudo-window: offscreen surface, no backend window, never shown.
 * GetDC(NULL) draws into it (screen-size scratch). */
uint64_t user32_desktop(void)
{
    if (g_desktop_hwnd)
        return g_desktop_hwnd;
    ensure_gui();   /* need the backend up for the real screen size */
    wn_window *win = wn_xcalloc(1, sizeof *win);
    win->cls = NULL;
    win->is_desktop = 1;
    win->style = 0;
    /* REAL screen size: putty's centre_dialog measures the desktop via
     * GetWindowRect(GetDesktopWindow()) and the old hardcoded 1280x800
     * put dialogs in wrong places on other screens. */
    {
        const wn_backend *be = wn_backend_get();
        int W = 640, H = 480;
        if (be && be->screen_size)
            be->screen_size(&W, &H);
        win->cw = W;
        win->ch = H;
        win->bwin = wn_xcalloc(1, sizeof(wn_bwin));
        win->bwin->width = W;
        win->bwin->height = H;
        win->bwin->stride = W * 4;
        win->bwin->pixels = wn_xmalloc((size_t)W * H * 4 + 64);
        memset(win->bwin->pixels, 0xFF, (size_t)W * H * 4);
    }
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

static WN_API int64_t u32_GetWindowLongA(wn_abiword hwnd, int32_t idx)
{
    return winlong_get(win_from_hwnd(hwnd), idx);
}

static WN_API int64_t u32_GetWindowLongW(wn_abiword hwnd, int32_t idx)
{
    return winlong_get(win_from_hwnd(hwnd), idx);
}

static WN_API int64_t u32_GetWindowLongPtrA(wn_abiword hwnd, int32_t idx)
{
    return winlong_get(win_from_hwnd(hwnd), idx);
}

static WN_API int64_t u32_GetWindowLongPtrW(wn_abiword hwnd, int32_t idx)
{
    return winlong_get(win_from_hwnd(hwnd), idx);
}

static WN_API int64_t u32_SetWindowLongA(wn_abiword hwnd, int32_t idx, wn_abiword_s v)
{
    return winlong_set(win_from_hwnd(hwnd), idx, v);
}

static WN_API int64_t u32_SetWindowLongW(wn_abiword hwnd, int32_t idx, wn_abiword_s v)
{
    return winlong_set(win_from_hwnd(hwnd), idx, v);
}

static WN_API int64_t u32_SetWindowLongPtrA(wn_abiword hwnd, int32_t idx, wn_abiword_s v)
{
    return winlong_set(win_from_hwnd(hwnd), idx, v);
}

static WN_API int64_t u32_SetWindowLongPtrW(wn_abiword hwnd, int32_t idx, wn_abiword_s v)
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

static WN_API uint64_t u32_GetDlgItem(wn_abiword hdlg, int32_t id)
{
    wn_window *d = win_from_hwnd(hdlg);
    wn_window *c = d ? dlg_item(d, (uint64_t)(int64_t)id) : NULL;
    wn_handle h = c ? hwnd_of_window(c) : 0;
    return (uint64_t)(uintptr_t)h;
}

/* Dialog base units: consistent with DLG_X/DLG_Y below (2 px / 4 px). */
static WN_API int32_t u32_MapDialogRect(wn_abiword hdlg, void *rect)
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

static WN_API int32_t u32_IsDlgButtonChecked(wn_abiword hdlg, int32_t id)
{
    uint64_t c = u32_GetDlgItem(hdlg, id);
    wn_window *w = c ? win_from_hwnd(c) : NULL;
    if (!w)
        return 0;
    return (int32_t)w->check;
}

static WN_API int32_t u32_CheckDlgButton(wn_abiword hdlg, int32_t id,
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

static WN_API int32_t u32_CheckRadioButton(wn_abiword hdlg, int32_t first,
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
     * cbWndExtra@0x14, hInstance@0x18, ..., lpszClassName@0x40.
     * i386: style@0, lpfnWndProc@4, cbClsExtra@8, cbWndExtra@0xC,
     * hInstance@0x10, ..., lpszClassName@0x24 (40-byte struct). */
    const uint8_t *p = wc;
#if defined(__x86_64__)
    const char *name = *(const char **)(const void *)(p + 0x40);
    WN_API wn_abiword (*proc)(wn_abiword, uint32_t, wn_abiword,
                              wn_abiword_s) =
        (WN_API wn_abiword (*)(wn_abiword, uint32_t, wn_abiword,
                               wn_abiword_s))
        *(const void **)(const void *)(p + 8);
    uint32_t cb_wnd_extra = *(const uint32_t *)(const void *)(p + 0x14);
#else
    const char *name = *(const char **)(const void *)(p + 0x24);
    WN_API wn_abiword (*proc)(wn_abiword, uint32_t, wn_abiword,
                              wn_abiword_s) =
        (WN_API wn_abiword (*)(wn_abiword, uint32_t, wn_abiword,
                               wn_abiword_s))
        *(const void **)(const void *)(p + 4);
    uint32_t cb_wnd_extra = *(const uint32_t *)(const void *)(p + 0xC);
#endif
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
            g_classes[i].cb_wnd_extra = cb_wnd_extra;
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
                                           wn_abiword parent, wn_abiword menu,
                                           wn_abiword hinst, void *param)
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
    /* Child vs top-level: Windows decides by WS_CHILD, not by the presence
     * of a parent argument. DIALOGS are passed their owner as "parent" by
     * the dialog manager but are top-level WS_POPUP windows — treating them
     * as children composed them into the owner's surface and crashed on
     * ShowWindow (priv=NULL; the putty About-box segfault). */
    if (parent && (style & 0x40000000u /*WS_CHILD*/)) {
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
        /* WS_VISIBLE children must be hit-testable/composable immediately:
         * the dialog engine creates children with WS_VISIBLE and never
         * calls ShowWindow on them (found via putty: clicks fell through
         * to the dialog because every child's visible flag was 0). */
        win->visible = (style & 0x10000000u) ? 1 : 0;
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
    win->owner = parent;              /* owner != parent: stays top-level */
    win->wx = x;
    win->wy = y;
    if (w <= 0) w = 640;
    if (h <= 0) h = 480;
    win->cw = w;                     /* canonical size (cw/ch, not just bwin) */
    win->ch = h;
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

    /* The backend creates X windows at (0,0); honor the requested position
     * (owner-relative dialogs, apps that pre-position their windows). */
    if ((x != 0 || y != 0) && be->win_move_resize)
        be->win_move_resize(win->bwin, x, y, w, h);
    /* Windows semantics: windows without WS_THICKFRAME are NOT user-
     * resizable (dialogs!). X11 WMs resize anything that lacks size hints
     * — locking min==max keeps fixed dialogs fixed (the "resizing breaks
     * the entire app" report: putty's config box is fixed-size on
     * Windows). */
    if (!(style & 0x00040000u /*WS_THICKFRAME*/) && be->win_fixed_size)
        be->win_fixed_size(win->bwin);

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
                                           wn_abiword parent, wn_abiword menu,
                                           wn_abiword hinst, void *param)
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

static WN_API int32_t u32_DestroyWindow(wn_abiword hwnd)
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
    /* control payloads (tree view nodes, list items) */
    if (w->ctl_priv)
        tv_free(w);
    for (int i = 0; i < w->n_items; i++)
        free(w->items[i]);
    free(w->items);
    w->items = NULL;
    w->n_items = w->items_cap = 0;
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

/* Fill the guest MSG x64 struct from an internal message:
 * hwnd@0, message@8, wParam@0x10, lParam@0x18, time@0x20, pt@0x24. */
/* Guest MSG layout (winuser.h): x64 = 48 bytes, i386 = 28 bytes. Writing
 * the x64 shape on i386 smashes the caller's frame past its 28-byte MSG. */
#if defined(__x86_64__)
#define WN_MSG_HOFF    0x00
#define WN_MSG_MSGOFF  0x08
#define WN_MSG_WPOFF   0x10
#define WN_MSG_LPOFF   0x18
#define WN_MSG_TIMEOFF 0x20
#define WN_MSG_FILL    0x30
#else
#define WN_MSG_HOFF    0x00
#define WN_MSG_MSGOFF  0x04
#define WN_MSG_WPOFF   0x08
#define WN_MSG_LPOFF   0x0C
#define WN_MSG_TIMEOFF 0x10
#define WN_MSG_FILL    0x1C
#endif

static void fill_msg(void *msg_out, const wn_msg *m)
{
    uint8_t *o = msg_out;
    memset(o, 0, WN_MSG_FILL);
#if defined(__x86_64__)
    *(uint64_t *)(void *)(o + WN_MSG_HOFF) = m->hwnd;
    *(uint64_t *)(void *)(o + WN_MSG_WPOFF) = m->wparam;
    *(int64_t *)(void *)(o + WN_MSG_LPOFF) = m->lparam;
#else
    *(uint32_t *)(void *)(o + WN_MSG_HOFF) = (uint32_t)m->hwnd;
    *(uint32_t *)(void *)(o + WN_MSG_WPOFF) = (uint32_t)m->wparam;
    *(int32_t *)(void *)(o + WN_MSG_LPOFF) = (int32_t)m->lparam;
#endif
    *(uint32_t *)(void *)(o + WN_MSG_MSGOFF) = m->message;
    *(uint32_t *)(void *)(o + WN_MSG_TIMEOFF) = m->time;
    g_last_msg_time = m->time;    /* GetMessageTime */
}

/* One non-blocking pump pass: timers, synthesized paints, backend events.
 * Returns 1 if anything might have entered the queue. */
static int pump_once(void)
{
    const wn_backend *be = wn_backend_get();
    int got = 0;
    fire_timers();               /* may queue WM_TIMER */
    generate_paints();           /* queues ONE WM_PAINT per dirty window */
    if (be && be->pump)
        got = be->pump(0);       /* input/expose/configure events */
    if (g_q_count || g_quit_posted)
        return 1;
    fire_timers();
    generate_paints();           /* events may have dirtied windows */
    return got || g_q_count || g_quit_posted;
}

static WN_API int32_t u32_GetMessageA(void *msg_out, wn_abiword hwnd,
                                      uint32_t min, uint32_t max)
{
    (void)hwnd; (void)min; (void)max;
    if (ensure_gui() != 0)
        return -1;
    for (;;) {
        wn_msg m;
        /* WM_QUIT wins (checked before consuming a posted message — the
         * old order dropped one real message on exit). */
        if (g_quit_posted) {
            wn_msg q = { .hwnd = 0, .message = WN_WM_QUIT,
                         .wparam = g_quit_code };
            fill_msg(msg_out, &q);
            return 0;
        }
        if (queue_pop(&m)) {
            fill_msg(msg_out, &m);
            return 1;
        }
        if (pump_once())
            continue;
        /* Block until a posted message, a timer deadline, or backend
         * input. The backend's poll fd makes X11 input wake us instantly
         * (the old 100ms-capped poll made mouse tracking sluggish). */
        uint64_t now = wn_monotonic_ns() / 1000000;
        int wait = 100;
        for (int i = 0; i < 32; i++) {
            if (g_timers[i].active && g_timers[i].next_fire > now) {
                int ms = (int)(g_timers[i].next_fire - now);
                if (ms < wait)
                    wait = ms;
            }
        }
        struct pollfd pfds[2];
        int n = 0;
        if (g_msg_fd >= 0) {
            pfds[n].fd = g_msg_fd;
            pfds[n].events = POLLIN;
            n++;
        }
        const wn_backend *be = wn_backend_get();
        if (be && be->poll_fd && be->poll_fd() >= 0) {
            pfds[n].fd = be->poll_fd();
            pfds[n].events = POLLIN;
            n++;
        }
        if (n)
            poll(pfds, n, wait);
        if (g_msg_fd >= 0) {
            uint64_t v;
            (void)!read(g_msg_fd, &v, 8);
        }
    }
}

static WN_API int32_t u32_PeekMessageA(void *msg_out, wn_abiword hwnd,
                                       uint32_t min, uint32_t max,
                                       uint32_t remove)
{
    (void)hwnd; (void)min; (void)max;   /* filters unsupported yet */
    wn_msg m;
    /* PeekMessage must pump (Windows processes sent messages and input
     * here); modal loops that poll with PM_NOREMOVE previously starved
     * the whole input path. */
    pump_once();
    if (g_quit_posted) {
        wn_msg q = { .hwnd = 0, .message = WN_WM_QUIT,
                     .wparam = g_quit_code };
        fill_msg(msg_out, &q);
        return 0;
    }
    if (remove & 1 /* PM_NOREMOVE */) {
        if (!queue_peek(&m))
            return 0;
    } else {
        if (!queue_pop(&m))
            return 0;
    }
    fill_msg(msg_out, &m);
    return 1;
}

static WN_API uint64_t u32_DispatchMessageA(const void *msg)
{
    const uint8_t *p = msg;
    wn_abiword hwnd = *(const wn_abiword *)(const void *)(p + WN_MSG_HOFF);
    uint32_t message = *(const uint32_t *)(const void *)(p + WN_MSG_MSGOFF);
    wn_abiword wp = *(const wn_abiword *)(const void *)(p + WN_MSG_WPOFF);
    wn_abiword_s lp = *(const wn_abiword_s *)(const void *)(p + WN_MSG_LPOFF);
    wn_window *w = win_from_hwnd(hwnd);
    wn_log(WN_LOG_DEBUG, "dispatch: hwnd=%llx msg=%u wp=%llx lp=%llx w=%p",
           (unsigned long long)hwnd, message, (unsigned long long)wp,
           (unsigned long long)lp, (void *)w);
    if (w && w->cls && w->cls->proc) {
        wn_log(WN_LOG_DEBUG, "dispatch: -> proc %p", (void *)(uintptr_t)w->cls->proc);
        return w->cls->proc(hwnd, message, wp, lp);
    }
    return 0;
}

static WN_API uint64_t u32_DefWindowProcA(wn_abiword hwnd, uint32_t msg,
                                          wn_abiword wp, wn_abiword_s lp)
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

static WN_API int32_t u32_PostMessageA(wn_abiword hwnd, uint32_t msg,
                                       wn_abiword wp, wn_abiword_s lp)
{
    post_msg(hwnd, msg, wp, lp);
    return 1;
}

static WN_API uint64_t u32_SendMessageA(wn_abiword hwnd, uint32_t msg,
                                        wn_abiword wp, wn_abiword_s lp)
{
    wn_window *w = win_from_hwnd(hwnd);
    if (w && w->cls && w->cls->proc)
        return w->cls->proc(hwnd, msg, wp, lp);
    return u32_DefWindowProcA(hwnd, msg, wp, lp);
}

static WN_API uintptr_t u32_SetTimer(wn_abiword hwnd, uintptr_t id,
                                     uint32_t ms,
                                     WN_API void (*proc)(wn_abiword, uint32_t,
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

static WN_API int32_t u32_KillTimer(wn_abiword hwnd, uintptr_t id)
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

/* GetClientRect uses the canonical size too (cw/ch == bwin size since the
 * create/resize paths keep them in lockstep). */
static WN_API int32_t u32_GetClientRect(wn_abiword hwnd, void *rect)
{
    wn_window *w = win_from_hwnd(hwnd);
    if (!w || !rect)
        return 0;
    int32_t *r = rect;
    r[0] = 0;
    r[1] = 0;
    r[2] = w->cw;
    r[3] = w->ch;
    return 1;
}


static WN_API int32_t u32_IsWindow(wn_abiword hwnd)
{
    return win_from_hwnd(hwnd) != NULL;
}

static WN_API int32_t u32_UpdateWindow(wn_abiword hwnd)
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
extern WN_API wn_handle g32_GetDC(wn_abiword hwnd);
extern WN_API int32_t g32_ReleaseDC(wn_abiword hwnd, wn_handle hdc);
extern WN_API int32_t g32_FillRect(wn_handle hdc, const void *rect, wn_handle brush);


/* ========================================================================== */
/* Builtin control classes + dialog engine                                     */
/* ========================================================================== */

extern WN_API int32_t g32_TextOutA(wn_handle hdc, int x, int y,
                                   const char *s, int32_t count);
extern WN_API uint32_t g32_SetTextColor(wn_handle hdc, uint32_t color);
extern WN_API int32_t g32_SetPixel(wn_handle hdc, int32_t x, int32_t y,
                                   uint32_t color);
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
    /* Group boxes paint directly onto the parent (transparent interiors);
     * their own surface is never composited. */
    if (child->cls && wn_strcaseeq(child->cls->name, "Button") &&
        (child->style & 0xF) == 0x7 /*BS_GROUPBOX*/)
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
               CTL_SCROLLBAR, CTL_TREEVIEW } ctl_kind;

static ctl_kind ctl_kind_of(const char *cls)
{
    if (wn_strcaseeq(cls, "Button"))         return CTL_BUTTON;
    if (wn_strcaseeq(cls, "Static"))         return CTL_STATIC;
    if (wn_strcaseeq(cls, "Edit"))           return CTL_EDIT;
    if (wn_strcaseeq(cls, "ListBox"))        return CTL_LISTBOX;
    if (wn_strcaseeq(cls, "ComboBox"))       return CTL_COMBO;
    if (wn_strcaseeq(cls, "SysTreeView32"))  return CTL_TREEVIEW;
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
    wn_log(WN_LOG_TRACE, "user32: ctl_notify id=%llu code=%u -> parent",
           (unsigned long long)w->id, code);
    if (w->parent)
        post_msg(w->parent, WN_WM_COMMAND,
                 (w->id & 0xFFFF) | ((uint64_t)code << 16),
                 (int64_t)(uintptr_t)hwnd_of_window(w));
}

static void ctl_repaint(wn_window *w)
{
    /* Damage the full control surface; the pump synthesizes ONE WM_PAINT
     * (no direct queue posts — putty adds dozens of list items in a burst
     * and every post used to be a queue slot). Compose immediately so the
     * pixels already rendered are visible without waiting for the pump. */
    w->dirty.l = 0;
    w->dirty.t = 0;
    w->dirty.r = w->cw;
    w->dirty.b = w->ch;
    compose_child(w);
}

/* --- SysTreeView32 (comctl32 tree view) --------------------------------------------
 * PuTTY's config box is built around one: the category pane is a tree view
 * (dialog.c: CreateWindowEx(WS_EX_CLIENTEDGE, WC_TREEVIEW, ...)), and a
 * TVN_SELCHANGED WM_NOTIFY tells the dlgproc to rebuild the right-hand
 * panel. Struct layouts are the Win64 ABI:
 *   TVITEM x64: mask@0(4) hItem@8(8) state@16(4) stateMask@20(4) pszText@24(8)
 *               cchTextMax@32(4) iImage@36(4) iSelectedImage@40(4)
 *               cChildren@44(4) lParam@48(8)                      = 56 bytes
 *   TVINSERTSTRUCT: hParent@0(8) hInsertAfter@8(8) item@16(56)     = 72
 *   NMTREEVIEW: hdr@0(24) action@24 itemOld@32 itemNew@88 ptDrag@144 = 152
 * Item handles are index+1 (0 = NULL; TVI_* are 0xFFFF0000+ so no clash). */

/* TVI_* are (HTREEITEM)(ULONG_PTR)-0x10000 etc. — SIGN-EXTENDED to
 * 0xFFFFFFFFFFFF0000+ in Win64. A zero-extended 0xFFFF0000 constant made
 * every root insert fail silently (putty's walk then parented everything to
 * NULL and the Session/Terminal/Window/Connection categories vanished —
 * found by disassembling the TVI_ROOT constant in putty.exe). */
#define TVI_ROOT_H   0xFFFFFFFFFFFF0000ULL
#define TVI_FIRST_H  0xFFFFFFFFFFFF0001ULL
#define TVI_LAST_H   0xFFFFFFFFFFFF0002ULL
#define TVI_SORT_H   0xFFFFFFFFFFFF0003ULL
#define TVIS_SELECTED_ 0x0002u
#define TVIS_EXPANDED_ 0x0020u
#define TVM_INSERTITEMA_ 0x1100u
#define TVM_INSERTITEMW_ 0x1132u
#define TVM_DELETEITEM_  0x1101u
#define TVM_EXPAND_      0x1102u
#define TVM_GETITEMRECT_ 0x1104u
#define TVM_GETCOUNT_    0x1105u
#define TVM_GETNEXTITEM_ 0x110Au
#define TVM_SELECTITEM_  0x110Bu
#define TVM_GETITEMA_    0x110Cu
#define TVM_GETITEMW_    0x113Eu
#define TVM_SETITEMA_    0x110Du
#define TVM_ENSUREVISIBLE_ 0x1114u
#define TVM_SETITEMHEIGHT_ 0x111Bu
#define TVM_GETITEMHEIGHT_ 0x111Cu
#define TVN_SELCHANGEDA_ 0xFFFFFE6Eu   /* TVN_FIRST(-400) - 2 */
#define WM_NOTIFY_       0x004Eu

#define TV_MAX_NODES 4096

typedef struct tv_node {
    char     *text;
    uint64_t  lparam;
    uint32_t  state;
    int       parent;            /* -1 = root level */
    int       first_child, last_child;
    int       next, prev;        /* siblings, -1 = none */
    int       has_children;
} tv_node;

typedef struct {
    tv_node *nodes;
    int      count, cap;
    int      root_first, root_last;
    int      sel;                /* index, -1 = none */
} tv_data;

static tv_data *tv_of(wn_window *w)
{
    if (!w->ctl_priv) {
        tv_data *tv = wn_xcalloc(1, sizeof *tv);
        tv->root_first = tv->root_last = -1;
        tv->sel = -1;
        w->ctl_priv = tv;
    }
    return w->ctl_priv;
}

static void tv_free(wn_window *w)
{
    tv_data *tv = w->ctl_priv;
    if (!tv)
        return;
    for (int i = 0; i < tv->count; i++)
        free(tv->nodes[i].text);
    free(tv->nodes);
    free(tv);
    w->ctl_priv = NULL;
}

static int tv_has_children(tv_data *tv, int idx)
{
    return tv->nodes[idx].first_child >= 0 || tv->nodes[idx].has_children;
}

/* Depth-first visible walk (children only of EXPANDED nodes). Writes the
 * visible indices into vis[] (capacity cap); returns the count. */
static int tv_walk_visible(tv_data *tv, int *vis, int cap)
{
    int n = 0;
    int cur = tv->root_first;
    while (cur >= 0 && n < cap) {
        vis[n++] = cur;
        if (tv->nodes[cur].first_child >= 0 &&
            (tv->nodes[cur].state & TVIS_EXPANDED_)) {
            cur = tv->nodes[cur].first_child;
            continue;
        }
        if (tv->nodes[cur].next >= 0) {
            cur = tv->nodes[cur].next;
            continue;
        }
        /* up to the nearest ancestor with a following sibling */
        while (cur >= 0 && tv->nodes[cur].next < 0)
            cur = tv->nodes[cur].parent;
        if (cur >= 0)
            cur = tv->nodes[cur].next;
    }
    return n;
}

static int tv_reserve(tv_data *tv, int need)
{
    if (need <= tv->count)
        return 0;
    if (need > TV_MAX_NODES)
        return -1;
    if (need > tv->cap) {
        int cap = tv->cap ? tv->cap * 2 : 64;
        while (cap < need)
            cap *= 2;
        tv_node *nn = realloc(tv->nodes, (size_t)cap * sizeof(tv_node));
        if (!nn)
            return -1;
        tv->nodes = nn;
        tv->cap = cap;
    }
    return 0;
}

/* TVM_INSERTITEM: returns the new HTREEITEM (index+1) or 0. */
static uint64_t tv_insert(wn_window *w, const uint8_t *ins_raw, int wide)
{
    tv_data *tv = tv_of(w);
    if (!ins_raw || tv->count >= TV_MAX_NODES)
        return 0;
    uint64_t hparent    = *(const uint64_t *)(const void *)(ins_raw + 0);
    uint64_t hafter     = *(const uint64_t *)(const void *)(ins_raw + 8);
    const uint8_t *item = ins_raw + 16;
    uint32_t mask   = *(const uint32_t *)(const void *)(item + 0);
    /* hItem @8 unused on insert */
    uint64_t psz    = *(const uint64_t *)(const void *)(item + 24);
    int cchildren   = *(const int32_t *)(const void *)(item + 44);
    uint64_t lparam = *(const uint64_t *)(const void *)(item + 48);

    char text[512] = "";
    if ((mask & 0x1 /*TVIF_TEXT*/) && psz) {
        if (wide) {
            char *a = wn_utf16_to_utf8((const uint16_t *)(uintptr_t)psz, 512);
            snprintf(text, sizeof text, "%s", a ? a : "");
            free(a);
        } else {
            snprintf(text, sizeof text, "%s", (const char *)(uintptr_t)psz);
        }
    }
    int pidx = -1;
    if (hparent && hparent != TVI_ROOT_H) {
        if (hparent > (uint64_t)tv->count || hparent >= TVI_ROOT_H)
            return 0;                    /* invalid parent handle */
        pidx = (int)hparent - 1;
    }
    if (tv_reserve(tv, tv->count + 1) != 0)
        return 0;
    tv_node *nd = &tv->nodes[tv->count];
    memset(nd, 0, sizeof *nd);
    nd->text = wn_xstrdup(text);
    nd->lparam = (mask & 0x4 /*TVIF_PARAM*/) ? lparam : 0;
    nd->state = 0;
    nd->parent = pidx;
    nd->first_child = nd->last_child = -1;
    nd->next = nd->prev = -1;
    nd->has_children = (mask & 0x40 /*TVIF_CHILDREN*/) ? (cchildren != 0) : 0;
    int idx = tv->count++;

    /* link into the parent's child chain (or the root chain) */
    int *first, *last;
    if (pidx < 0) {
        first = &tv->root_first;
        last = &tv->root_last;
    } else {
        first = &tv->nodes[pidx].first_child;
        last = &tv->nodes[pidx].last_child;
    }
    int after;
    if (hafter == TVI_FIRST_H)
        after = -2;                    /* prepend */
    else if (hafter == TVI_SORT_H)
        after = *last;                 /* v1: append (sorting not needed) */
    else if (hafter == TVI_LAST_H || hafter == 0 || hafter >= TVI_ROOT_H)
        after = *last;                 /* append; NULL == TVI_LAST (putty) */
    else if (hafter <= (uint64_t)tv->count)
        after = (int)hafter - 1;
    else
        after = *last;
    if (after == -2 || *first < 0) {
        if (*first < 0) {
            *first = *last = idx;
        } else {
            nd->next = *first;
            tv->nodes[*first].prev = idx;
            *first = idx;
        }
    } else {
        int nx = tv->nodes[after].next;
        nd->prev = after;
        nd->next = nx;
        tv->nodes[after].next = idx;
        if (nx >= 0)
            tv->nodes[nx].prev = idx;
        else
            *last = idx;
    }
    if (pidx >= 0)
        tv->nodes[pidx].has_children = 1;
    wn_log(WN_LOG_DEBUG, "user32: TVM_INSERTITEM '%s' parent=%d -> 0x%llx",
           text, pidx, (unsigned long long)idx + 1);
    return (uint64_t)idx + 1;
}

/* Fill a caller TVITEM (A or W) from a node. Returns 1 on success. */
static int tv_get_item(wn_window *w, uint8_t *item, int wide)
{
    tv_data *tv = tv_of(w);
    uint32_t mask = *(const uint32_t *)(const void *)(item + 0);
    uint64_t hitem = *(const uint64_t *)(const void *)(item + 8);
    if (!hitem || hitem > (uint64_t)tv->count)
        return 0;
    int idx = (int)hitem - 1;
    tv_node *nd = &tv->nodes[idx];
    if (mask & 0x1 /*TVIF_TEXT*/) {
        uint64_t psz = *(const uint64_t *)(const void *)(item + 24);
        int cap = *(const int32_t *)(const void *)(item + 32);
        if (psz && cap > 0) {
            if (wide) {
                uint16_t *wt = (uint16_t *)(uintptr_t)psz;
                size_t l = 0;
                while (nd->text[l] && l < (size_t)(cap - 1)) {
                    wt[l] = (uint8_t)nd->text[l];   /* latin1-ish; fine */
                    l++;
                }
                wt[l] = 0;
            } else {
                snprintf((char *)(uintptr_t)psz, (size_t)cap, "%s", nd->text);
            }
        }
    }
    if (mask & 0x4 /*TVIF_PARAM*/)
        *(uint64_t *)(void *)(item + 48) = nd->lparam;
    if (mask & 0x8 /*TVIF_STATE*/) {
        uint32_t st = nd->state;
        if (idx == tv->sel)
            st |= TVIS_SELECTED_;
        *(uint32_t *)(void *)(item + 16) = st;
    }
    if (mask & 0x40 /*TVIF_CHILDREN*/)
        *(int32_t *)(void *)(item + 44) = tv_has_children(tv, idx) ? 1 : 0;
    return 1;
}

/* TVN_SELCHANGED to the parent, delivered SYNCHRONOUSLY (Windows delivers
 * WM_NOTIFY inside TreeView_SelectItem; putty's TVN handler rebuilds the
 * panel immediately). itemOld/itemNew are prefilled. */
static void tv_notify_selchanged(wn_window *w, int old_idx, int new_idx)
{
    tv_data *tv = tv_of(w);
    uint8_t buf[160];
    memset(buf, 0, sizeof buf);
    uint64_t parent_h = w->parent ? w->parent : 0;
    *(uint64_t *)(void *)(buf + 0)  = (uint64_t)(uintptr_t)hwnd_of_window(w); /* hwndFrom */
    *(uint64_t *)(void *)(buf + 8)  = w->id;                      /* idFrom */
    *(uint32_t *)(void *)(buf + 16) = TVN_SELCHANGEDA_;
    for (int pass = 0; pass < 2; pass++) {
        int idx = pass == 0 ? old_idx : new_idx;
        uint8_t *it = buf + (pass == 0 ? 32 : 88);
        if (idx >= 0 && idx < tv->count) {
            *(uint32_t *)(void *)(it + 0) = 0x1 | 0x4 | 0x8 | 0x40;
            *(uint64_t *)(void *)(it + 8) = (uint64_t)idx + 1;
            *(uint32_t *)(void *)(it + 16) = (idx == tv->sel) ? TVIS_SELECTED_ : 0;
            *(uint64_t *)(void *)(it + 48) = tv->nodes[idx].lparam;
            *(int32_t *)(void *)(it + 44) = tv_has_children(tv, idx);
        }
    }
    if (parent_h)
        u32_SendMessageA(parent_h, WM_NOTIFY_, w->id,
                         (int64_t)(uintptr_t)buf);
}

/* Select + notify. Returns 1 on success. */
static int tv_select(wn_window *w, int idx, int notify)
{
    tv_data *tv = tv_of(w);
    if (idx < -1 || idx >= tv->count)
        return 0;
    int old = tv->sel;
    if (idx == old)
        return 1;
    tv->sel = idx;
    ctl_repaint(w);
    if (notify)
        tv_notify_selchanged(w, old, idx);
    return 1;
}

static int tv_get_next(wn_window *w, uint32_t code, uint64_t hitem)
{
    tv_data *tv = tv_of(w);
    int is_tvi = (hitem == 0 || hitem >= TVI_ROOT_H);
    switch (code) {
    case 0: /* TVGN_ROOT */   return tv->root_first;
    case 9: /* TVGN_CARET */  return tv->sel;
    case 4: { /* TVGN_CHILD: TVI_ROOT asks for the first root */
        if (hitem == TVI_ROOT_H)
            return tv->root_first;
        if (is_tvi || hitem > (uint64_t)tv->count)
            return -1;
        return tv->nodes[hitem - 1].first_child;
    }
    case 3: { /* TVGN_PARENT */
        if (is_tvi || hitem > (uint64_t)tv->count)
            return -1;
        return tv->nodes[hitem - 1].parent;
    }
    case 1: { /* TVGN_NEXT */
        if (is_tvi || hitem > (uint64_t)tv->count)
            return -1;
        return tv->nodes[hitem - 1].next;
    }
    case 2: { /* TVGN_PREVIOUS */
        if (is_tvi || hitem > (uint64_t)tv->count)
            return -1;
        return tv->nodes[hitem - 1].prev;
    }
    case 5: { /* TVGN_FIRSTVISIBLE */
        int vis[256];
        int n = tv_walk_visible(tv, vis, 256);
        return n > 0 ? vis[0] : -1;
    }
    default:
        return -1;
    }
}

static void tv_paint(wn_window *w, wn_handle hdc)
{
    tv_data *tv = tv_of(w);
    int W = w->cw, H = w->ch;
    int rh = ctl_row_h() + 2;
    int vis[512];
    int n = tv_walk_visible(tv, vis, 512);
    int rows = (H - 2) / rh;
    for (int i = 0; i < rows && i < n; i++) {
        int idx = vis[i];
        tv_node *nd = &tv->nodes[idx];
        int level = 0;
        for (int p = nd->parent; p >= 0; p = tv->nodes[p].parent)
            level++;
        int x = 4 + level * 18;
        int y = 1 + i * rh;
        /* toggle box for parents */
        if (tv_has_children(tv, idx)) {
            int32_t bx[4] = { x, y + (rh - 11) / 2, x + 11,
                              y + (rh - 11) / 2 + 11 };
            wn_handle bb = g32_CreateSolidBrush(0x00FFFFFF);
            g32_FillRect(hdc, bx, bb);
            wn_handle_close(bb);
            int cy = y + (rh - 11) / 2 + 5;
            for (int t = 2; t < 9; t++)
                g32_SetPixel(hdc, x + t, cy, 0);
            if (!(nd->state & TVIS_EXPANDED_))
                for (int t = 2; t < 9; t++)
                    g32_SetPixel(hdc, x + 5, y + (rh - 11) / 2 + t, 0);
            x += 15;
        } else {
            x += 15;
        }
        if (idx == tv->sel) {
            int32_t sr[4] = { x - 1, y, W - 1, y + rh };
            wn_handle sb = g32_CreateSolidBrush(0x00A8000A);
            g32_FillRect(hdc, sr, sb);
            wn_handle_close(sb);
            g32_SetTextColor(hdc, 0x00FFFFFF);
        } else {
            g32_SetTextColor(hdc, 0);
        }
        int32_t tr[4] = { x + 2, y, W - 2, y + rh };
        g32_DrawTextA(hdc, nd->text, -1, tr,
                      0x20 | 0x100 | 0x24 /*SINGLELINE|NOPREFIX|VCENTER*/);
    }
    g32_SetTextColor(hdc, 0);
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

static WN_API wn_abiword ctl_proc(wn_abiword hwnd, uint32_t msg,
                                  wn_abiword wp, wn_abiword_s lp)
{
    wn_window *w = win_from_hwnd(hwnd);
    if (!w)
        return 0;
    /* #32770 dialog: every message goes to the guest dlgproc (WM_COMMAND
     * from child controls, WM_CLOSE, ...). Without this the dialog was a
     * black hole: clicks produced WM_COMMANDs that vanished in ctl_proc's
     * default case. WM_PAINT is special: DefDlgProc's job is erasing the
     * background and composing children — the guest dlgproc never paints
     * the face color itself (found via putty: dialog went black after the
     * routing fix). */
    if (w->is_dialog && w->dlgproc) {
        if (msg == WN_WM_PAINT) {
            wn_handle hdc = g32_GetDC(hwnd);
            if (hdc) {
                int32_t rect[4] = { 0, 0, w->cw, w->ch };
                wn_handle bg = g32_CreateSolidBrush(0x00C8D0D4 /*face*/);
                g32_FillRect(hdc, rect, bg);
                wn_handle_close(bg);
            }
            compose_children_of(hwnd);
            const wn_backend *be = wn_backend_get();
            if (be && be->present && w->bwin)
                be->present(w->bwin);
            w->dirty.l = -1;
            w->paint_pending = 0;   /* re-arm generate_paints */
        }
        typedef WN_API wn_abiword_s (*dlgproc_fn)(
            wn_abiword, uint32_t, wn_abiword, wn_abiword_s);
        int64_t r = ((dlgproc_fn)(uintptr_t)w->dlgproc)(hwnd, msg, wp, lp);
        if (r)
            return (uint64_t)r;
        return u32_DefWindowProcA(hwnd, msg, wp, lp);
    }
    const char *cls = w->cls ? w->cls->name : "";
    ctl_kind k = ctl_kind_of(cls);
    switch (msg) {
    case WN_WM_PAINT: {
        int is_gb = (k == CTL_BUTTON && (w->style & 0xF) == 0x7);
        /* Group boxes paint TRANSPARENTLY onto the PARENT canvas (Windows
         * composes them last, top of the sibling z-order; putty creates the
         * panel group box after the fields). Their own surface would be
         * opaque white — blitting it covered the fields. */
        int off_x = 0, off_y = 0;
        wn_handle hdc;
        if (is_gb && w->parent) {
            hdc = g32_GetDC(w->parent);
            off_x = w->wx;
            off_y = w->wy;
        } else {
            hdc = g32_GetDC(hwnd);
        }
        if (!hdc)
            return 0;
        int W = w->cw, H = w->ch;
        int32_t rect[4] = { 0, 0, W, H };
        uint32_t face = (k == CTL_EDIT || k == CTL_LISTBOX || k == CTL_TREEVIEW)
                          ? 0x00FFFFFF : 0x00C8D0D4;
        int is_groupbox = is_gb;
        if (!is_groupbox) {
            wn_handle bg = g32_CreateSolidBrush(face);
            g32_FillRect(hdc, rect, bg);
            wn_handle_close(bg);
        }
        wn_handle dark = g32_CreateSolidBrush(0x00606060);
        wn_handle lite = g32_CreateSolidBrush(0x00FFFFFF);
        int32_t top[4]  = { 0, 0, W, 1 };
        int32_t lef[4]  = { 0, 0, 1, H };
        int32_t bot[4]  = { 0, H - 1, W, H };
        int32_t rig[4]  = { W - 1, 0, W, H };
        if (!is_groupbox) {    /* the groupbox draws its own frame */
            g32_FillRect(hdc, top, k == CTL_STATIC ? lite : dark);
            g32_FillRect(hdc, lef, k == CTL_STATIC ? lite : dark);
            g32_FillRect(hdc, bot, k == CTL_STATIC ? dark : lite);
            g32_FillRect(hdc, rig, k == CTL_STATIC ? dark : lite);
        }
        wn_handle_close(dark);
        wn_handle_close(lite);
        int rh = ctl_row_h();
        int focused = g_focus_hwnd == hwnd;
        int disabled = (w->style & 0x08000000u) != 0;
        g32_SetTextColor(hdc, disabled ? 0x00808080 /*COLOR_GRAYTEXT*/ : 0);
        g32_SetBkMode(hdc, 1 /* TRANSPARENT */);
        switch (k) {
        case CTL_BUTTON: {
            uint32_t bs = w->style & 0xF;
            if (bs == 0x2 /*BS_AUTOCHECKBOX*/ || bs == 0x3 /*BS_CHECKBOX*/ ||
                bs == 0x9 /*BS_AUTORADIO*/ || bs == 0x4 /*BS_RADIOBUTTON*/) {
                ctl_paint_check(hdc, 4, (H - 13) / 2, (int)w->check,
                                bs == 0x9 || bs == 0x4 ? 1 : 0);
                int32_t tr[4] = { 22, 0, W - 4, H };
                g32_DrawTextA(hdc, w->title, -1, tr,
                              0x20 | 0x24 /*SINGLELINE|VCENTER: prefix parsed*/);
            } else if (bs == 0x7 /*BS_GROUPBOX — 0x7! 0x5 is BS_3STATE*/) {
                /* frame + label on the top edge, in PARENT coordinates */
                int32_t fr[4] = { off_x + 1, off_y + 7, off_x + W - 1,
                                  off_y + H - 1 };
                g32_Rectangle(hdc, fr[0], fr[1], fr[2], fr[3]);
                int32_t tr[4] = { off_x + 8, off_y,
                                  off_x + 8 + (int)strlen(w->title) * 8 + 4,
                                  off_y + 16 };
                wn_handle fbg = g32_CreateSolidBrush(0x00C8D0D4);
                g32_FillRect(hdc, tr, fbg);
                wn_handle_close(fbg);
                g32_DrawTextA(hdc, w->title, -1, tr,
                              0x20 | 0x24);
            } else {
                /* push button: raised 3D frame + centered text + focus.
                 * NO DT_NOPREFIX: button captions parse '&x' accelerators
                 * (putty: "&About" etc.). */
                extern WN_API int32_t g32_DrawEdge(wn_handle, void *rect,
                                                   uint32_t, uint32_t);
                int32_t fr[4] = { 0, 0, W - 1, H - 1 };
                g32_DrawEdge(hdc, fr, 0 /*BDR_RAISEDOUTER|BDR_RAISEDINNER*/,
                             0x4 /*BF_RECT*/);
                int32_t tr[4] = { 4, 0, W - 4, H };
                uint32_t old = g32_SetBkColor(hdc, 0x00C8D0D4);
                (void)old;
                g32_SetBkMode(hdc, 1);
                g32_DrawTextA(hdc, w->title, -1, tr,
                              0x20 | 0x24 | 6 /*CENTER: prefix parsed*/);
                if (focused && !disabled) {   /* dotted focus rect */
                    extern WN_API int32_t g32_SetPixel(wn_handle, int32_t,
                                                        int32_t, uint32_t);
                    for (int fy = 2; fy < H - 2; fy += 2) {
                        for (int fx = 2; fx < W - 2; fx += 2) {
                            if (fy == 2 || fy > H - 5 || fx == 2 || fx > W - 5)
                                g32_SetPixel(hdc, fx, fy, 0);
                        }
                    }
                }
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
                uint32_t fmt = 0x20 | 0x24;   /* statics parse prefixes */
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
        case CTL_TREEVIEW:
            tv_paint(w, hdc);
            break;
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
        g32_ReleaseDC(is_groupbox && w->parent ? w->parent : hwnd, hdc);
        /* Paint completed: clear the pending flag so generate_paints()
         * can post future WM_PAINTs for this window (typing, selection
         * changes...). Without this a control painted ONCE and never
         * again — paint_pending was only cleared via g32_EndPaint, which
         * the builtin control classes never call. */
        wn_user32_validate_paint(hwnd);
        if (is_groupbox) {
            /* painted into the parent; damage that region and present */
            wn_window *pw = w->parent ? win_from_hwnd(w->parent) : NULL;
            if (pw) {
                if (pw->dirty.l < 0) {
                    pw->dirty.l = w->wx;
                    pw->dirty.t = w->wy;
                    pw->dirty.r = w->wx + w->cw;
                    pw->dirty.b = w->wy + w->ch;
                } else {
                    if (w->wx < pw->dirty.l) pw->dirty.l = w->wx;
                    if (w->wy < pw->dirty.t) pw->dirty.t = w->wy;
                    if (w->wx + w->cw > pw->dirty.r) pw->dirty.r = w->wx + w->cw;
                    if (w->wy + w->ch > pw->dirty.b) pw->dirty.b = w->wy + w->ch;
                }
            }
            present_root(w);
            return 0;
        }
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
        case CTL_TREEVIEW: {
            /* click selects a category (TVN_SELCHANGED -> putty rebuilds
             * the panel); clicking a node's +/- box toggles expansion. */
            tv_data *tv = tv_of(w);
            int my = (int)(int16_t)((uint64_t)lp >> 16);
            int mx = (int)(int16_t)((uint64_t)lp & 0xFFFF);
            int rh = ctl_row_h() + 2;
            int vis[512];
            int n = tv_walk_visible(tv, vis, 512);
            int row = (my - 1) / rh;
            if (row < 0 || row >= n)
                return 0;
            int idx = vis[row];
            int level = 0;
            for (int p = tv->nodes[idx].parent; p >= 0;
                 p = tv->nodes[p].parent)
                level++;
            int box_x = 4 + level * 18;
            if (tv_has_children(tv, idx) && mx >= box_x &&
                mx < box_x + 11) {
                tv->nodes[idx].state ^= TVIS_EXPANDED_;
                ctl_repaint(w);
                return 0;
            }
            tv_select(w, idx, 1);
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
    /* --- SysTreeView32 messages (TVM_*) --- */
    case TVM_INSERTITEMA_:
    case TVM_INSERTITEMW_:
        return tv_insert(w, (const uint8_t *)(uintptr_t)lp,
                         msg == TVM_INSERTITEMW_);
    case TVM_GETITEMA_:
    case TVM_GETITEMW_:
        if ((uint64_t)lp >= TVI_ROOT_H)
            return 0;
        return (uint64_t)tv_get_item(w, (uint8_t *)(uintptr_t)lp,
                                     msg == TVM_GETITEMW_);
    case TVM_SETITEMA_:
        /* v1: only state (expand) changes matter to real clients */
        if (lp) {
            const uint8_t *it = (const uint8_t *)(uintptr_t)lp;
            uint32_t mask = *(const uint32_t *)(const void *)(it + 0);
            uint64_t hitem = *(const uint64_t *)(const void *)(it + 8);
            tv_data *tv = tv_of(w);
            if (hitem && hitem <= (uint64_t)tv->count && (mask & 0x8)) {
                uint32_t st = *(const uint32_t *)(const void *)(it + 16);
                uint32_t smask = *(const uint32_t *)(const void *)(it + 20);
                tv->nodes[hitem - 1].state =
                    (tv->nodes[hitem - 1].state & ~smask) |
                    (st & smask);
                ctl_repaint(w);
                return 1;
            }
        }
        return 0;
    case TVM_GETNEXTITEM_: {
        int r = tv_get_next(w, (uint32_t)wp, (uint64_t)lp);
        return r >= 0 ? (uint64_t)r + 1 : 0;
    }
    case TVM_SELECTITEM_:
        if (wp == 9 /*TVGN_CARET*/) {
            if ((uint64_t)lp == 0 || (uint64_t)lp >= TVI_ROOT_H)
                return (uint64_t)tv_select(w, -1, 1);
            return (uint64_t)tv_select(w, (int)lp - 1, 1);
        }
        return 0;
    case TVM_EXPAND_: {
        tv_data *tv = tv_of(w);
        if (!lp || (uint64_t)lp >= TVI_ROOT_H || (uint64_t)lp > (uint64_t)tv->count)
            return 0;
        tv_node *nd = &tv->nodes[lp - 1];
        if (!tv_has_children(tv, (int)lp - 1))
            return 0;
        if (wp == 2 /*TVE_EXPAND*/)
            nd->state |= TVIS_EXPANDED_;
        else if (wp == 1 /*TVE_COLLAPSE*/)
            nd->state &= ~TVIS_EXPANDED_;
        else if (wp == 3 /*TVE_TOGGLE*/)
            nd->state ^= TVIS_EXPANDED_;
        ctl_repaint(w);
        return 1;
    }
    case TVM_GETCOUNT_: {
        tv_data *tv = tv_of(w);
        return (uint64_t)tv->count;
    }
    case TVM_DELETEITEM_:
        /* v1: only the whole tree (TVI_ROOT) is cleared, which is what
         * real apps do when rebuilding; selective unlink is TODO. */
        tv_free(w);
        ctl_repaint(w);
        return 1;
    case TVM_GETITEMRECT_: {
        tv_data *tv = tv_of(w);
        if (!lp)
            return 0;
        int32_t *rc = (int32_t *)(uintptr_t)lp;
        int32_t hitem = rc[0];            /* macro stores hItem in left */
        if (hitem <= 0 || hitem > tv->count)
            return 0;
        int vis[512];
        int n = tv_walk_visible(tv, vis, 512);
        int rh = ctl_row_h() + 2;
        for (int i = 0; i < n; i++) {
            if (vis[i] == hitem - 1) {
                rc[0] = 0;
                rc[1] = 1 + i * rh;
                rc[2] = w->cw;
                rc[3] = 1 + (i + 1) * rh;
                return 1;
            }
        }
        return 0;
    }
    case TVM_ENSUREVISIBLE_: return 1;
    case TVM_SETITEMHEIGHT_: return 0;
    case TVM_GETITEMHEIGHT_: return (uint64_t)(ctl_row_h() + 2);
    case WN_WM_KEYDOWN: {
        /* tree view keyboard navigation (arrows move selection like
         * Windows; putty drives the config tree with them) */
        if (k != CTL_TREEVIEW)
            return 0;
        tv_data *tv = tv_of(w);
        int vis[512];
        int n = tv_walk_visible(tv, vis, 512);
        int cur = -1;
        for (int i = 0; i < n; i++)
            if (vis[i] == tv->sel)
                cur = i;
        uint32_t vk = (uint32_t)wp;
        if (vk == 0x28 /*VK_DOWN*/ && n) {
            tv_select(w, vis[cur < 0 ? 0 : (cur + 1 < n ? cur + 1 : cur)], 1);
        } else if (vk == 0x26 /*VK_UP*/ && n) {
            tv_select(w, vis[cur <= 0 ? 0 : cur - 1], 1);
        } else if (vk == 0x27 /*VK_RIGHT*/ && tv->sel >= 0 &&
                   tv_has_children(tv, tv->sel)) {
            tv->nodes[tv->sel].state |= TVIS_EXPANDED_;
            ctl_repaint(w);
        } else if (vk == 0x25 /*VK_LEFT*/ && tv->sel >= 0 &&
                   tv_has_children(tv, tv->sel) &&
                   (tv->nodes[tv->sel].state & TVIS_EXPANDED_)) {
            tv->nodes[tv->sel].state &= ~TVIS_EXPANDED_;
            ctl_repaint(w);
        }
        return 0;
    }
    default:
        return 0;
    }
}

/* Register a builtin control class on first use. */
static wn_wndclass *builtin_control_class(const char *name)
{
    static const char *known[] = { "Button", "Edit", "Static", "ListBox",
                                   "ComboBox", "ScrollBar", "SysTreeView32",
                                   "#32770", NULL };
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

/* Char walk: C locale has no DBCS lead bytes (see _ismbblead), so a char is
 * one byte (A) / one UTF-16 unit (W). Returning NULL from the old stubs
 * crashed Inno's string parsing immediately. */
static WN_API char *u32_CharNextA(const char *ptr)
{
    if (!ptr || !*ptr)
        return (char *)(uintptr_t)ptr;
    return (char *)(uintptr_t)ptr + 1;
}

static WN_API char *u32_CharPrevA(const char *start, const char *cur)
{
    if (!cur)
        return (char *)(uintptr_t)start;
    if (cur <= start)
        return (char *)(uintptr_t)cur;
    return (char *)(uintptr_t)cur - 1;
}

static WN_API uint16_t *u32_CharNextW(const uint16_t *ptr)
{
    if (!ptr || !*ptr)
        return (uint16_t *)(uintptr_t)ptr;
    return (uint16_t *)(uintptr_t)ptr + 1;
}

static WN_API uint16_t *u32_CharPrevW(const uint16_t *start, const uint16_t *cur)
{
    if (!cur)
        return (uint16_t *)(uintptr_t)start;
    if (cur <= start)
        return (uint16_t *)(uintptr_t)cur;
    return (uint16_t *)(uintptr_t)cur - 1;
}

/* LoadString: RT_STRING table block (uID/16+1) of 16 length-prefixed UTF-16
 * strings; the wanted entry is uID%16. Inno/Delphi and countless installers
 * pull ALL of their UI text through this one API. */
static const uint16_t *load_string_lookup(wn_abiword hinst, uint32_t uid,
                                          uint16_t *len_out)
{
    extern WN_API uint64_t k32_FindResourceA(uint64_t, const char *,
                                             const char *);
    extern WN_API void *k32_LockResource(uint64_t);
    char rid[16];
    snprintf(rid, sizeof rid, "%u", (unsigned)(uid / 16) + 1);
    uint64_t hres = k32_FindResourceA(hinst, rid,
                                      (const char *)(uintptr_t)6 /*RT_STRING*/);
    if (!hres)
        return NULL;
    const uint16_t *p = k32_LockResource(hres);
    if (!p)
        return NULL;
    unsigned idx = uid & 15;
    for (unsigned i = 0; i < 16; i++) {
        uint16_t len = *p++;
        if (i == idx) {
            *len_out = len;
            return len ? p : NULL;
        }
        p += len;
    }
    return NULL;
}

static WN_API int32_t u32_LoadStringW(wn_abiword hinst, uint32_t uid,
                                      uint16_t *buf, int32_t cch_max)
{
    uint16_t len = 0;
    const uint16_t *s = load_string_lookup(hinst, uid, &len);
    if (!s)
        return 0;
    if (!buf)
        return (int32_t)(uintptr_t)s;   /* Windows: read-only pointer back */
    if (cch_max <= 0)
        return 0;
    int32_t copy = (int32_t)len < cch_max - 1 ? (int32_t)len : cch_max - 1;
    memcpy(buf, s, (size_t)copy * 2);
    buf[copy] = 0;
    return copy;
}

static WN_API int32_t u32_LoadStringA(wn_abiword hinst, uint32_t uid,
                                      char *buf, int32_t cch_max)
{
    uint16_t len = 0;
    const uint16_t *s = load_string_lookup(hinst, uid, &len);
    if (!s)
        return 0;
    if (!buf)
        return 0;   /* ANSI variant has no direct resource pointer to return */
    if (cch_max <= 0)
        return 0;
    char *a = wn_utf16_to_utf8(s, len);
    if (!a)
        return 0;
    int32_t n = (int32_t)strlen(a);
    int32_t copy = n < cch_max - 1 ? n : cch_max - 1;
    memcpy(buf, a, (size_t)copy);
    buf[copy] = 0;
    free(a);
    return copy;
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

    /* DS_SETFONT templates carry a font section AFTER the title that must
     * be skipped before the items, or every item parse misaligns (putty's
     * About box rendered only 2 of its controls and NO text until this
     * was fixed): DLGTEMPLATE: WORD pointsize + WCHAR fontname[];
     * DLGTEMPLATEEX: WORD pointsize + WORD weight + BYTE italic +
     * BYTE charset + WCHAR fontname[]. */
    if (style & 0x40 /* DS_SETFONT */) {
        p += is_ex ? 3 : 1;              /* pointsize(+weight/italic/charset) */
        while (p < end && *p)            /* fontname (NUL-terminated UTF-16) */
            p++;
        p++;                             /* the NUL */
        p = (const uint16_t *)dlg_dword_align(p);
    }

    /* dialog window itself: class #32770, a TOP-LEVEL owned popup (the
     * WS_CHILD bit is never set for dialogs). Template coordinates are
     * dialog units relative to the OWNER's client origin unless
     * DS_ABSALIGN (0x80) — matching Windows' dialog manager. */
    int dx = DLG_X(x), dy = DLG_Y(y);
    if (!(style & 0x80 /*DS_ABSALIGN*/) && parent) {
        wn_window *ow = win_from_hwnd(parent);
        if (ow) {
            dx += ow->wx;
            dy += ow->wy;
        }
    }
    uint64_t hwnd = u32_CreateWindowExA(ex_style, "#32770", title,
                                        style | (force_visible ? 0x10000000u : 0),
                                        dx, dy,
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
        typedef WN_API wn_abiword_s (*dlgproc_fn)(
            wn_abiword, uint32_t, wn_abiword, wn_abiword_s);
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
 * TWO-ARG contract: IsDialogMessage(hDlg, lpMsg) — RCX is the dialog HWND,
 * RDX the MSG*. An earlier one-arg version dereferenced RCX (the handle)
 * as the MSG and faulted (found via putty's message loop).
 * Tab/Shift-Tab cycle WS_TABSTOP children; Enter -> IDOK; Esc -> IDCANCEL;
 * arrows move radio selection within a WS_GROUP run. MSG x64:
 * hwnd@0(8), message@8(4), wParam@0x10(8), lParam@0x18(8). */
static int32_t u32_IsDialogMessage_impl(uint64_t hdlg, const uint8_t *msg)
{
    if (!msg)
        return 0;
    wn_abiword hwnd = *(const wn_abiword *)(const void *)(msg + WN_MSG_HOFF);
    uint32_t message = *(const uint32_t *)(const void *)(msg + WN_MSG_MSGOFF);
    wn_abiword wp = *(const wn_abiword *)(const void *)(msg + WN_MSG_WPOFF);
    (void)hdlg;
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

static WN_API int32_t u32_IsDialogMessageA(wn_abiword hdlg, const void *msg)
{
    return u32_IsDialogMessage_impl(hdlg, (const uint8_t *)msg);
}

static WN_API int64_t u32_DialogBoxParamA(wn_abiword hinst, const void *tmpl,
                                          wn_abiword parent, wn_abiword dlgproc,
                                          wn_abiword param)
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
    uint8_t msgbuf[0x30];   /* guest MSG layout; wn_msg is smaller! */
    while (!dw->dlg_done) {
        int32_t r = u32_GetMessageA(msgbuf, 0, 0, 0);
        if (r <= 0)
            break;
        if (!u32_IsDialogMessageA(hwnd, msgbuf))
            u32_DispatchMessageA(msgbuf);
    }
    user32_set_focus_internal(0);
    u32_SetActiveWindow(parent ? parent : 0);
    int64_t result = dw->dlg_result;
    u32_DestroyWindow(hwnd);
    return result;
}

static WN_API uint64_t u32_CreateDialogParamA(wn_abiword hinst, const void *tmpl,
                                              wn_abiword parent, wn_abiword dlgproc,
                                              wn_abiword param)
{
    return create_dialog_from_template(hinst, tmpl, parent, dlgproc, param, 0);
}

static WN_API void u32_EndDialog(wn_abiword hwnd, wn_abiword_s result)
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

static WN_API int32_t u32_SetDlgItemTextA(wn_abiword hwnd, int32_t id,
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

static WN_API int32_t u32_SetWindowTextA(wn_abiword hwnd, const char *text)
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

static WN_API int32_t u32_GetWindowTextA(wn_abiword hwnd, char *buf, int32_t max)
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
    /* MAKEINTRESOURCE: values below 0x10000 ARE the id (IDC_ARROW is
     * 32512 = 0x7f00 — dereferencing it as a string faults; found via
     * putty's WNDCLASS.hCursor = LoadCursor(NULL, IDC_ARROW)). */
    if ((uintptr_t)name < 0x10000)
        return (uint32_t)(uintptr_t)name;
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

static WN_API wn_handle u32_LoadCursorA(wn_abiword hinst, const char *name)
{
    (void)hinst;   /* process-defined cursors: not yet (documented gap) */
    uint32_t id = res_name_to_id(name, g_idc_names, 32512 /*IDC_ARROW base*/);
    if (!id && (uintptr_t)name >= 0x10000)
        wn_log(WN_LOG_WARN, "user32: LoadCursorA('%s') unknown", name);
    return res_handle(id, 0);
}

static WN_API wn_handle u32_LoadCursorW(wn_abiword hinst, const uint16_t *name)
{
    if ((uintptr_t)name < 0x10000)   /* MAKEINTRESOURCEW */
        return u32_LoadCursorA(hinst, (const char *)(uintptr_t)name);
    char *a = name ? wn_utf16_to_utf8(name, 256) : NULL;
    wn_handle h = u32_LoadCursorA(hinst, a);
    free(a);
    return h;
}

static WN_API wn_handle u32_LoadIconA(wn_abiword hinst, const char *name)
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

static WN_API wn_handle u32_LoadIconW(wn_abiword hinst, const uint16_t *name)
{
    if ((uintptr_t)name < 0x10000)   /* MAKEINTRESOURCEW */
        return u32_LoadIconA(hinst, (const char *)(uintptr_t)name);
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

/* ========================================================================== */
/* EnableWindow, MessageBeep, monitor/DPI, coordinate, and interaction batch  */
/* ========================================================================== */

/* WS_DISABLED = 0x08000000. Windows: EnableWindow returns the PREVIOUS state
 * (nonzero = was enabled). putty disables its config box for every modal
 * child; the old stub returned 0 ("it WAS disabled"), which apps read as
 * failure — and our input path then fed clicks into the "disabled" window. */
static WN_API int32_t u32_EnableWindow(wn_abiword hwnd, int32_t enable)
{
    wn_window *w = win_from_hwnd(hwnd);
    if (!w)
        return 0;
    int was = !(w->style & 0x08000000u);
    if (enable)
        w->style &= ~0x08000000u;
    else {
        w->style |= 0x08000000u;
        /* A disabled window cannot keep focus. */
        if (g_focus_hwnd == hwnd)
            user32_set_focus_internal(0);
    }
    if (w->parent && w->visible)
        ctl_repaint(w);
    else if (w->visible) {
        w->dirty.l = 0; w->dirty.t = 0;
        w->dirty.r = w->cw; w->dirty.b = w->ch;
    }
    return was;
}

static WN_API int32_t u32_IsWindowEnabled(wn_abiword hwnd)
{
    wn_window *w = win_from_hwnd(hwnd);
    return w ? !(w->style & 0x08000000u) : 0;
}

/* MessageBeep: ring the backend's bell (XBell on X11); success by contract. */
static WN_API int32_t u32_MessageBeep(uint32_t type)
{
    const wn_backend *be = wn_backend_get();
    if (be && be->beep)
        be->beep();
    (void)type;
    return 1;
}

/* --- screen origin + rectangles ------------------------------------------------ */

/* Absolute screen origin of a window (walks the parent chain; top-level
 * wx/wy are tracked from backend ConfigureNotify/move ops). */
static void win_screen_origin(wn_window *w, int *x, int *y)
{
    *x = 0;
    *y = 0;
    while (w) {
        *x += w->wx;
        *y += w->wy;
        w = w->parent ? win_from_hwnd(w->parent) : NULL;
    }
}

static WN_API int32_t u32_GetWindowRect(wn_abiword hwnd, void *rect)
{
    wn_window *w = win_from_hwnd(hwnd);
    if (!w || !rect)
        return 0;
    int x, y;
    win_screen_origin(w, &x, &y);
    int32_t *r = rect;
    r[0] = x;
    r[1] = y;
    r[2] = x + w->cw;
    r[3] = y + w->ch;
    wn_log(WN_LOG_TRACE, "user32: GetWindowRect(0x%llx) -> %d,%d %dx%d",
           (unsigned long long)hwnd, r[0], r[1], r[2] - r[0], r[3] - r[1]);
    return 1;
}

static WN_API int32_t u32_ScreenToClient(wn_abiword hwnd, void *pt)
{
    wn_window *w = win_from_hwnd(hwnd);
    if (!w || !pt)
        return 0;
    int x, y;
    win_screen_origin(w, &x, &y);
    int32_t *p = pt;
    p[0] -= x;
    p[1] -= y;
    return 1;
}

static WN_API int32_t u32_ClientToScreen(wn_abiword hwnd, void *pt)
{
    wn_window *w = win_from_hwnd(hwnd);
    if (!w || !pt)
        return 0;
    int x, y;
    win_screen_origin(w, &x, &y);
    int32_t *p = pt;
    p[0] += x;
    p[1] += y;
    return 1;
}

static WN_API uint64_t u32_GetParent(wn_abiword hwnd)
{
    wn_window *w = win_from_hwnd(hwnd);
    if (!w)
        return 0;
    /* Windows: WS_CHILD -> parent; WS_POPUP (dialogs) -> owner. */
    return w->is_child ? w->parent : w->owner;
}

static WN_API int32_t u32_OffsetRect(void *rect, int32_t dx, int32_t dy)
{
    if (!rect)
        return 0;
    int32_t *r = rect;
    r[0] += dx; r[1] += dy; r[2] += dx; r[3] += dy;
    return 1;
}

/* --- metrics / monitors / DPI ---------------------------------------------------
 * One virtual monitor covering the whole screen (single X screen). That is
 * enough for apps to place dialogs ON screen — putty positioned its config
 * box at y=-104 when these were stubs. */

static void screen_dims(int *w, int *h)
{
    const wn_backend *be = wn_backend_get();
    if (be && be->screen_size) {
        be->screen_size(w, h);
        return;
    }
    *w = 800;
    *h = 600;
}

static WN_API int32_t u32_GetSystemMetrics(int32_t idx)
{
    int w, h;
    screen_dims(&w, &h);
    switch (idx) {
    case 0:  return w;          /* SM_CXSCREEN */
    case 1:  return h;          /* SM_CYSCREEN */
    case 2:  return 17;         /* SM_CXVSCROLL */
    case 3:  return 17;         /* SM_CYHSCROLL */
    case 4:  return 22;         /* SM_CYCAPTION */
    case 5:  return 1;          /* SM_CXBORDER */
    case 6:  return 1;          /* SM_CYBORDER */
    case 7:  return 3;          /* SM_CXDLGFRAME */
    case 8:  return 3;          /* SM_CYDLGFRAME */
    case 9:  return 17;         /* SM_CYVTHUMB */
    case 10: return 17;         /* SM_CXHTHUMB */
    case 11: return 32;         /* SM_CXICON */
    case 12: return 32;         /* SM_CYICON */
    case 13: return 32;         /* SM_CXCURSOR */
    case 14: return 32;         /* SM_CYCURSOR */
    case 15: return 20;         /* SM_CYMENU */
    case 16: return w;          /* SM_CXFULLSCREEN (work area) */
    case 17: return h;          /* SM_CYFULLSCREEN */
    case 19: return 1;          /* SM_MOUSEPRESENT */
    case 20: return 17;         /* SM_CYVSCROLL */
    case 21: return 17;         /* SM_CXHSCROLL */
    case 23: return 0;          /* SM_SWAPBUTTON */
    case 28: return 112;        /* SM_CXMIN */
    case 29: return 27;         /* SM_CYMIN */
    case 30: return 18;         /* SM_CXSIZE (caption buttons) */
    case 31: return 18;         /* SM_CYSIZE */
    case 32: return 4;          /* SM_CXFRAME */
    case 33: return 4;          /* SM_CYFRAME */
    case 34: return 112;        /* SM_CXMINTRACK */
    case 35: return 27;         /* SM_CYMINTRACK */
    case 42: return 0;          /* SM_SHOWSOUNDS */
    case 43: return 3;          /* SM_CMOUSEBUTTONS */
    case 54: return 0;          /* SM_MIDEASTENABLED */
    case 67: return 6;          /* SM_CXSMICON */
    case 68: return 6;          /* SM_CYSMICON */
    case 76: return 0;          /* SM_REMOTESESSION */
    default:
        wn_log(WN_LOG_DEBUG, "user32: GetSystemMetrics(%d) -> 0", idx);
        return 0;
    }
}

/* MONITORINFO x64: cbSize@0(4) rcMonitor@4(16) rcWork@0x14(16) dwFlags@0x24. */
static WN_API int32_t u32_GetMonitorInfoA(wn_abiword hmon, void *mi)
{
    (void)hmon;
    if (!mi)
        return 0;
    int w, h;
    screen_dims(&w, &h);
    int32_t *r = mi;
    uint32_t cb = (uint32_t)r[0];
    memset(r, 0, cb < 40 ? 40 : (cb > 72 ? 72 : cb));
    r[0] = cb ? (int32_t)cb : 40;
    r[1] = 0; r[2] = 0; r[3] = w; r[4] = h;      /* rcMonitor */
    r[5] = 0; r[6] = 0; r[7] = w; r[8] = h;      /* rcWork (no taskbar) */
    r[9] = 1;                                    /* MONITORINFOF_PRIMARY */
    if (cb >= 72)
        snprintf((char *)mi + 40, 32, "DISPLAY");
    return 1;
}

static WN_API int32_t u32_GetMonitorInfoW(wn_abiword hmon, void *mi)
{
    if (!mi)
        return 0;
    int32_t *r = mi;
    uint32_t cb = (uint32_t)r[0];
    if (cb >= 72) {
        /* wide device name at offset 40 */
        static const uint16_t dev[7] = { 'D','I','S','P','L','A','Y' };
        uint16_t *dst = (uint16_t *)((uint8_t *)mi + 40);
        for (int i = 0; i < 32; i++)
            dst[i] = i < 7 ? dev[i] : 0;
    }
    return u32_GetMonitorInfoA(hmon, mi);
}

static WN_API uint64_t u32_MonitorFromWindow(wn_abiword hwnd, uint32_t flags)
{
    int w, h;
    screen_dims(&w, &h);
    if (hwnd) {
        wn_window *win = win_from_hwnd(hwnd);
        if (win) {
            int x, y;
            win_screen_origin(win, &x, &y);
            if (x + win->cw > 0 && y + win->ch > 0 && x < w && y < h)
                return 1;   /* intersects the virtual screen */
        }
    }
    if (flags & 2 /*MONITOR_DEFAULTTOPRIMARY*/ || flags & 1 /*TONEAREST*/)
        return 1;
    return 0;
}

static WN_API uint64_t u32_MonitorFromRect(const void *rect, uint32_t flags)
{
    (void)rect;
    return (flags & 3) ? 1 : 0;
}

/* MonitorFromPoint takes POINT BY VALUE: an 8-byte struct arrives packed
 * in RCX under the MS x64 ABI (x=low dword, y=high dword) — declaring it
 * as (x, y, flags) reads y out of RDX and flags out of R8. Same ABI trap
 * class as the IsDialogMessage bug. */
static WN_API uint64_t u32_MonitorFromPoint(wn_abiword point, uint32_t flags)
{
#if defined(__x86_64__)
    int32_t x = (int32_t)(point & 0xFFFFFFFF);
    int32_t y = (int32_t)(point >> 32);
#else
    /* i386: POINT by value packs into one dword (y<<16 | x). */
    int32_t x = (int32_t)(point & 0xFFFF);
    int32_t y = (int32_t)((point >> 16) & 0xFFFF);
#endif
    int w, h;
    screen_dims(&w, &h);
    if (x >= 0 && y >= 0 && x < w && y < h)
        return 1;
    return (flags & 3) ? 1 : 0;
}

typedef WN_API int32_t (*mon_enum_cb)(wn_abiword, wn_abiword, const void *,
                                      wn_abiword_s);
static WN_API int32_t u32_EnumDisplayMonitors(wn_abiword hdc, const void *clip,
                                              mon_enum_cb cb, wn_abiword_s lparam)
{
    (void)hdc;
    (void)clip;
    if (!cb)
        return 0;
    int w, h;
    screen_dims(&w, &h);
    int32_t rc[4] = { 0, 0, w, h };
    cb(1, 0, rc, lparam);
    return 1;
}

/* SystemParametersInfoA: the values apps actually read at startup. */
static WN_API int32_t u32_SystemParametersInfoA(uint32_t action, uint32_t uparam,
                                                void *pv, uint32_t winini)
{
    (void)uparam; (void)winini;
    switch (action) {
    case 48: {    /* SPI_GETWORKAREA */
        if (!pv)
            return 0;
        int w, h;
        screen_dims(&w, &h);
        int32_t *r = pv;
        r[0] = 0; r[1] = 0; r[2] = w; r[3] = h;
        return 1;
    }
    default:
        wn_log(WN_LOG_DEBUG, "user32: SystemParametersInfoA(0x%x) -> TRUE "
               "(accepted, no side effect)", action);
        return 1;
    }
}

static WN_API int32_t u32_SystemParametersInfoW(uint32_t a, uint32_t b,
                                                void *c, uint32_t d)
{
    return u32_SystemParametersInfoA(a, b, c, d);
}

static WN_API int32_t u32_SetProcessDPIAware(void)
{
    return 1;   /* we render at native pixels; DPI-aware by construction */
}

static WN_API uint32_t u32_GetDpiForWindow(wn_abiword hwnd)
{
    (void)hwnd;
    return 96;   /* system DPI until per-monitor support lands */
}

static WN_API uint32_t u32_GetDpiForSystem(void)
{
    return 96;
}

/* --- invalidation ------------------------------------------------------------ */

static WN_API int32_t u32_InvalidateRect(wn_abiword hwnd, const void *rect,
                                         int32_t erase)
{
    (void)erase;
    if (!hwnd) {
        for (int i = 0; i < g_hwnd_count; i++) {
            wn_window *w = g_hwnds[i].win;
            if (w && w->visible && !w->in_destroy) {
                w->dirty.l = 0; w->dirty.t = 0;
                w->dirty.r = w->cw; w->dirty.b = w->ch;
            }
        }
        return 1;
    }
    wn_window *w = win_from_hwnd(hwnd);
    if (!w)
        return 0;
    if (rect) {
        const int32_t *r = rect;
        if (w->dirty.l < 0) {
            w->dirty.l = r[0]; w->dirty.t = r[1];
            w->dirty.r = r[2]; w->dirty.b = r[3];
        } else {
            if (r[0] < w->dirty.l) w->dirty.l = r[0];
            if (r[1] < w->dirty.t) w->dirty.t = r[1];
            if (r[2] > w->dirty.r) w->dirty.r = r[2];
            if (r[3] > w->dirty.b) w->dirty.b = r[3];
        }
    } else {
        w->dirty.l = 0; w->dirty.t = 0;
        w->dirty.r = w->cw; w->dirty.b = w->ch;
    }
    return 1;
}

static WN_API int32_t u32_ValidateRect(wn_abiword hwnd, const void *rect)
{
    (void)rect;   /* precise validation: later; full-window for now */
    wn_window *w = hwnd ? win_from_hwnd(hwnd) : NULL;
    if (w) {
        w->dirty.l = -1;
        w->paint_pending = 0;
    }
    return 1;
}

/* --- system colors (classic palette to match control painting) ---------------- */

static const uint32_t g_sys_colors[31] = {
    0x00D4D0C8, /* 0 SCROLLBAR */
    0x008A6E3A, /* 1 BACKGROUND (desktop) */
    0x0099B4D1, /* 2 ACTIVECAPTION */
    0x00DBCD9F, /* 3 INACTIVECAPTION */
    0x00F0F0F0, /* 4 MENU */
    0x00FFFFFF, /* 5 WINDOW */
    0x00646464, /* 6 WINDOWFRAME */
    0x00000000, /* 7 MENUTEXT */
    0x00000000, /* 8 WINDOWTEXT */
    0x00000000, /* 9 CAPTIONTEXT */
    0x00B4B4B4, /* 10 ACTIVEBORDER */
    0x00E8E8E8, /* 11 INACTIVEBORDER */
    0x00ABABAB, /* 12 APPWORKSPACE */
    0x00D47800, /* 13 HIGHLIGHT (BGR) */
    0x00FFFFFF, /* 14 HIGHLIGHTTEXT */
    0x00D4D0C8, /* 15 BTNFACE */
    0x00A0A0A0, /* 16 BTNSHADOW */
    0x00808080, /* 17 GRAYTEXT */
    0x00000000, /* 18 BTNTEXT */
    0x00DBCD9F, /* 19 INACTIVECAPTIONTEXT */
    0x00FFFFFF, /* 20 BTNHIGHLIGHT */
    0x00808080, /* 21 3DDKSHADOW */
    0x00F0F0F0, /* 22 3DLIGHT */
    0x00F0F0F0, /* 23 INFOTEXT ... */
    0x00FFFFE1, /* 24 INFOBK */
    0x00D4D0C8, /* 25 BUTTONHILIGHT */
    0x00D4D0C8, /* 26 BUTTONFACE alias */
    0x00A0A0A0, /* 27 BUTTONSHADOW alias */
    0x00000000, /* 28 GRAYTEXT alias */
    0x00D4D0C8, /* 29 BUTTONFACE alt */
    0x00000000, /* 30 DESKTOP */
};

static WN_API uint32_t u32_GetSysColor(int32_t idx)
{
    if (idx < 0 || idx > 30)
        return 0;
    return g_sys_colors[idx];
}

static WN_API wn_handle u32_GetSysColorBrush(int32_t idx)
{
    static wn_handle cache[31];
    if (idx < 0 || idx > 30)
        return (wn_handle)0;
    if (!cache[idx]) {
        extern WN_API wn_handle g32_CreateSolidBrush(uint32_t);
        cache[idx] = g32_CreateSolidBrush(g_sys_colors[idx]);
    }
    return cache[idx];
}

/* --- misc interaction states ---------------------------------------------------- */

static int g_cursor_count;       /* ShowCursor counter */
static WN_API int32_t u32_ShowCursor(int32_t show)
{
    g_cursor_count += show ? 1 : -1;
    return g_cursor_count;
}

static WN_API int32_t u32_GetCursorPos(void *pt)
{
    if (!pt)
        return 0;
    int32_t *p = pt;
    p[0] = g_mouse_x < 0 ? 0 : g_mouse_x;
    p[1] = g_mouse_y < 0 ? 0 : g_mouse_y;
    return 1;
}

static WN_API int32_t u32_GetKeyboardState(uint8_t *state)
{
    if (!state)
        return 0;
    memcpy(state, g_key_state, 256);
    return 1;
}

static WN_API int32_t u32_SetKeyboardState(const uint8_t *state)
{
    if (!state)
        return 0;
    memcpy(g_key_state, state, 256);
    return 1;
}

static WN_API uint64_t u32_GetKeyboardLayout(uint32_t id)
{
    (void)id;
    return 0x04090409;   /* en-US */
}

static WN_API uint32_t u32_GetDoubleClickTime(void)  { return 500; }
static WN_API uint32_t u32_GetCaretBlinkTime(void)   { return 530; }

static WN_API uint32_t u32_GetMessageTime(void)      { return g_last_msg_time; }

static WN_API uint32_t u32_GetQueueStatus(uint32_t flags)
{
    (void)flags;
    return g_q_count ? (0x08 /*QS_POSTMESSAGE*/ | 0x40 /*QS_INPUT*/) : 0;
}

static WN_API int32_t u32_IsIconic(wn_abiword hwnd)
{
    (void)hwnd;
    return 0;
}

static WN_API int32_t u32_IsZoomed(wn_abiword hwnd)
{
    (void)hwnd;
    return 0;
}

static WN_API int32_t u32_FlashWindow(wn_abiword hwnd, int32_t invert)
{
    (void)hwnd; (void)invert;
    return 0;
}

static WN_API int32_t u32_SetForegroundWindow(wn_abiword hwnd)
{
    if (!win_from_hwnd(hwnd))
        return 0;
    u32_SetActiveWindow(hwnd);
    return 1;
}

/* WINDOWPLACEMENT x64: length@0 flags@4 showCmd@8 ptMin@0xC ptMax@0x14
 * rcNormal@0x1C — 44 bytes. */
static WN_API int32_t u32_GetWindowPlacement(wn_abiword hwnd, void *wp)
{
    wn_window *w = win_from_hwnd(hwnd);
    if (!w || !wp)
        return 0;
    int32_t *p = wp;
    uint32_t cb = (uint32_t)p[0];
    memset(p, 0, cb < 44 ? 44 : cb);
    p[0] = 44;
    p[1] = 0;               /* flags */
    p[2] = 1;               /* showCmd = SW_SHOWNORMAL */
    int x, y;
    win_screen_origin(w, &x, &y);
    p[7] = x; p[8] = y; p[9] = x + w->cw; p[10] = y + w->ch;
    return 1;
}

static WN_API int32_t u32_SetWindowPlacement(wn_abiword hwnd, const void *wp)
{
    wn_window *w = win_from_hwnd(hwnd);
    if (!w || !wp)
        return 0;
    const int32_t *p = wp;
    int x = p[7], y = p[8], x2 = p[9], y2 = p[10];
    if (x2 > x && y2 > y)
        u32_MoveWindow(hwnd, x, y, x2 - x, y2 - y, 1);
    return 1;
}

/* --- W-variant message APIs + dialog text ---------------------------------------- */

static WN_API int32_t u32_PeekMessageW(void *out, wn_abiword hwnd, uint32_t min,
                                       uint32_t max, uint32_t remove)
{
    return u32_PeekMessageA(out, hwnd, min, max, remove);
}

static WN_API int32_t u32_GetMessageW(void *out, wn_abiword hwnd, uint32_t min,
                                      uint32_t max)
{
    return u32_GetMessageA(out, hwnd, min, max);
}

static WN_API uint64_t u32_DispatchMessageW(const void *msg)
{
    return u32_DispatchMessageA(msg);
}

static WN_API uint64_t u32_DefWindowProcW(wn_abiword hwnd, uint32_t msg,
                                          wn_abiword wp, wn_abiword_s lp)
{
    return u32_DefWindowProcA(hwnd, msg, wp, lp);
}

static WN_API uint64_t u32_SendMessageW(wn_abiword hwnd, uint32_t msg,
                                        wn_abiword wp, wn_abiword_s lp)
{
    return u32_SendMessageA(hwnd, msg, wp, lp);
}

static WN_API int32_t u32_PostMessageW(wn_abiword hwnd, uint32_t msg,
                                       wn_abiword wp, wn_abiword_s lp)
{
    return u32_PostMessageA(hwnd, msg, wp, lp);
}

static WN_API int32_t u32_SetWindowTextW(wn_abiword hwnd, const uint16_t *text)
{
    char *a = text ? wn_utf16_to_utf8(text, 4096) : NULL;
    int32_t r = u32_SetWindowTextA(hwnd, a ? a : "");
    free(a);
    return r;
}

static WN_API int32_t u32_GetWindowTextW(wn_abiword hwnd, uint16_t *buf,
                                         int32_t max)
{
    wn_window *w = win_from_hwnd(hwnd);
    if (!w || !buf || max <= 0)
        return 0;
    size_t i = 0;
    while (w->wtext[i] && (int)i + 1 < max) {
        buf[i] = w->wtext[i];
        i++;
    }
    buf[i] = 0;
    return (int32_t)i;
}

static WN_API int32_t u32_GetWindowTextLengthA(wn_abiword hwnd)
{
    wn_window *w = win_from_hwnd(hwnd);
    if (!w)
        return 0;
    return (int32_t)strlen(w->title);
}

static WN_API int32_t u32_GetWindowTextLengthW(wn_abiword hwnd)
{
    wn_window *w = win_from_hwnd(hwnd);
    if (!w)
        return 0;
    size_t n = 0;
    while (w->wtext[n])
        n++;
    return (int32_t)n;
}

static WN_API int32_t u32_SetDlgItemTextW(wn_abiword hwnd, int32_t id,
                                          const uint16_t *text)
{
    uint64_t c = u32_GetDlgItem(hwnd, id);
    if (!c)
        return 0;
    return (int32_t)u32_SendMessageW(c, WN_WM_SETTEXT, 0,
                                     (int64_t)(uintptr_t)text);
}

static WN_API uint32_t u32_GetDlgItemTextA(wn_abiword hdlg, int32_t id,
                                           char *buf, uint32_t max)
{
    uint64_t c = u32_GetDlgItem(hdlg, id);
    if (!c || !buf || !max)
        return 0;
    uint64_t r = u32_SendMessageA(c, WN_WM_GETTEXT, max,
                                  (int64_t)(uintptr_t)buf);
    return (uint32_t)r;
}

static WN_API uint32_t u32_GetDlgItemTextW(wn_abiword hdlg, int32_t id,
                                           uint16_t *buf, uint32_t max)
{
    uint64_t c = u32_GetDlgItem(hdlg, id);
    if (!c || !buf || !max)
        return 0;
    if (max > 4096)
        max = 4096;
    char tmp[4096];
    uint64_t r = u32_SendMessageA(c, WN_WM_GETTEXT, sizeof tmp,
                                  (int64_t)(uintptr_t)tmp);
    size_t n = 0;
    while (n + 1 < max && tmp[n]) {
        buf[n] = (uint16_t)(unsigned char)tmp[n];   /* Latin-1 fold */
        n++;
    }
    buf[n] = 0;
    (void)r;
    return (uint32_t)n;
}

static WN_API int64_t u32_SendDlgItemMessageA(wn_abiword hdlg, int32_t id,
                                              uint32_t msg, wn_abiword wp,
                                              wn_abiword_s lp)
{
    uint64_t c = u32_GetDlgItem(hdlg, id);
    if (!c)
        return 0;
    return (int64_t)u32_SendMessageA(c, msg, wp, lp);
}

static WN_API int64_t u32_SendDlgItemMessageW(wn_abiword hdlg, int32_t id,
                                              uint32_t msg, wn_abiword wp,
                                              wn_abiword_s lp)
{
    return u32_SendDlgItemMessageA(hdlg, id, msg, wp, lp);
}

static WN_API int64_t u32_DefDlgProcA(wn_abiword hwnd, uint32_t msg, wn_abiword wp,
                                      wn_abiword_s lp)
{
    /* our #32770 proc already implements DefDlgProc semantics; dialogs with
     * an explicit DefDlgProc call get the same behavior */
    return ctl_proc(hwnd, msg, wp, lp);
}

static WN_API int32_t u32_MessageBoxIndirectW(wn_abiword hwnd, const void *params)
{
    /* MSGBOXPARAMSW: cbSize@0, hwndOwner@8, hInstance@0x10, lpszText@0x18,
     * lpszCaption@0x20, dwStyle@0x28, ... */
    const uint8_t *p = params;
    const uint16_t *text = params ? *(const uint16_t **)(const void *)(p + 0x18) : NULL;
    const uint16_t *cap = params ? *(const uint16_t **)(const void *)(p + 0x20) : NULL;
    return u32_MessageBoxW(hwnd, text, cap,
                           params ? *(const uint32_t *)(const void *)(p + 0x28) : 0);
}

static WN_API uint64_t u32_FindWindowA(const char *cls, const char *title)
{
    for (int i = 0; i < g_hwnd_count; i++) {
        wn_window *w = g_hwnds[i].win;
        if (!w || !w->cls)
            continue;
        if (cls && *cls && !wn_strcaseeq(w->cls->name, cls))
            continue;
        if (title && *title && strcmp(w->title, title))
            continue;
        return (uint64_t)(uintptr_t)g_hwnds[i].h;
    }
    return 0;
}

static WN_API wn_handle u32_LoadImageA(wn_abiword hinst, const char *name,
                                       uint32_t type, int32_t cx, int32_t cy,
                                       uint32_t load)
{
    (void)cx; (void)cy; (void)load;
    if (type == 1 /*IMAGE_ICON*/)
        return u32_LoadIconA(hinst, name);
    wn_log(WN_LOG_WARN, "user32: LoadImageA(type=%u '%s') bitmaps not "
           "supported yet", type, (name && (uintptr_t)name >= 0x10000) ? name : "#int");
    return (wn_handle)0;
}

static WN_API int32_t u32_DestroyIcon(wn_handle icon)
{
    if (!icon)
        return 0;
    wn_handle_close(icon);
    return 1;
}

/* --- caret (single global caret, drawn by the focused Edit) --------------------- */

static struct {
    uint64_t hwnd;
    int w, h, x, y;
    int visible;
    int count;        /* ShowCaret/HideCaret counter */
} g_caret;

static WN_API int32_t u32_CreateCaret(wn_abiword hwnd, wn_abiword bmp,
                                      int32_t w, int32_t h)
{
    (void)bmp;
    g_caret.hwnd = hwnd;
    g_caret.w = w > 0 ? w : 1;
    g_caret.h = h > 0 ? h : 16;
    g_caret.visible = 0;
    g_caret.count = 0;
    return 1;
}

static WN_API int32_t u32_DestroyCaret(void)
{
    g_caret.hwnd = 0;
    g_caret.visible = 0;
    return 1;
}

static WN_API int32_t u32_ShowCaret(wn_abiword hwnd)
{
    if (g_caret.hwnd && hwnd && g_caret.hwnd != hwnd)
        return 0;
    g_caret.count++;
    g_caret.visible = g_caret.count >= 0;
    return 1;
}

static WN_API int32_t u32_HideCaret(wn_abiword hwnd)
{
    if (g_caret.hwnd && hwnd && g_caret.hwnd != hwnd)
        return 0;
    g_caret.count--;
    g_caret.visible = g_caret.count >= 0;
    return 1;
}

static WN_API int32_t u32_SetCaretPos(int32_t x, int32_t y)
{
    g_caret.x = x;
    g_caret.y = y;
    return 1;
}

/* --- MsgWaitForMultipleObjects (queue-aware approximation) ---------------------- */

static WN_API uint32_t u32_MsgWaitForMultipleObjects(uint32_t count,
                                                     const uint64_t *handles,
                                                     uint32_t wait_all,
                                                     uint32_t ms,
                                                     uint32_t wake_mask)
{
    (void)wait_all; (void)wake_mask;
    uint64_t t0 = wn_monotonic_ns() / 1000000;
    for (;;) {
        if (g_q_count)
            return count;          /* WAIT_OBJECT_0 + n: message arrived */
        /* Probe the handles with a zero timeout through the sync engine. */
        if (count) {
            extern uint32_t wn_wait_multiple(uint32_t, const wn_handle *,
                                             int, uint32_t);
            uint32_t wr = wn_wait_multiple(count,
                                           (const wn_handle *)handles,
                                           (int)wait_all, 0);
            if (wr != 0xFFFFFFFF /*FAILED*/ && wr != 0x102 /*TIMEOUT*/ &&
                wr != 0x80 /*ABANDONED*/)
                return wr & 0xFF;     /* WAIT_OBJECT_0 + index */
        }
        uint64_t now = wn_monotonic_ns() / 1000000;
        if (ms != 0xFFFFFFFFu && (uint32_t)(now - t0) >= ms)
            return 258;            /* WAIT_TIMEOUT */
        struct pollfd pfd = { .fd = g_msg_fd, .events = POLLIN };
        poll(&pfd, 1, 5);
        if (g_msg_fd >= 0) {
            uint64_t v;
            (void)!read(g_msg_fd, &v, 8);
        }
        pump_once();
    }
}

/* --- export table ----------------------------------------------------------------- */


/* MessageBox: no dialog engine yet, so the box is PRINTED (loudly) and we
 * answer IDOK. This keeps apps running and makes their complaints visible
 * in the log - a deliberate diagnostic aid, not a fake window. */
static WN_API int32_t u32_MessageBoxA(wn_abiword hwnd, const char *text,
                                      const char *caption, uint32_t type)
{
    (void)hwnd;
    (void)type;
    wn_log(WN_LOG_ERR, "MSGBOX '%s': %s",
           caption ? caption : "", text ? text : "");
    return 1;   /* IDOK */
}

static WN_API int32_t u32_MessageBoxW(wn_abiword hwnd, const uint16_t *text,
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

/* --- wsprintf family ---------------------------------------------------------- */

/* user32's own printf: no size parameter by design (MSDN caps the output
 * at 1024 chars); we hard-bound at 4 KiB and always NUL-terminate. %s
 * follows the A/W direction, %S is the flip side; the engine is
 * wn_vformat() (shared with msvcrt). No floating point per MSDN. */
#define WN_WSPRINTF_CAP 4096

static WN_CRTAPI int32_t u32_wsprintfA(char *dst, const char *fmt, ...)
{
    if (!dst)
        return -1;
    wn_ms_va ap;
    WN_VA_START(ap, fmt);
    int64_t r = wn_wsprintf_buf(dst, WN_WSPRINTF_CAP, fmt, (char *)ap, 0);
    WN_VA_END(ap);
    return (int32_t)r;
}

static WN_CRTAPI int32_t u32_wvsprintfA(char *dst, const char *fmt, char *ap)
{
    if (!dst)
        return -1;
    return (int32_t)wn_wsprintf_buf(dst, WN_WSPRINTF_CAP, fmt, ap, 0);
}

/* W side: convert the format to UTF-8, format with wide-direction args,
 * convert the result back to UTF-16. */
static int32_t wsprintf_w_impl(uint16_t *dst, const uint16_t *fmt, char *ap)
{
    *dst = 0;
    if (!fmt)
        return -1;
    size_t l16 = 0;
    while (fmt[l16])
        l16++;
    char *fmt8 = wn_utf16_to_utf8(fmt, l16);
    if (!fmt8)
        return -1;
    char *buf = wn_xmalloc(WN_WSPRINTF_CAP);
    int64_t r = wn_wsprintf_buf(buf, WN_WSPRINTF_CAP, fmt8, ap, 1);
    free(fmt8);
    if (r < 0) {
        free(buf);
        return -1;
    }
    uint16_t *w = wn_utf8_to_utf16(buf, NULL);
    free(buf);
    size_t n = 0;
    if (w) {
        while (w[n] && n < WN_WSPRINTF_CAP - 1) {
            dst[n] = w[n];
            n++;
        }
        free(w);
    }
    dst[n] = 0;
    return (int32_t)n;
}

static WN_CRTAPI int32_t u32_wsprintfW(uint16_t *dst, const uint16_t *fmt, ...)
{
    if (!dst)
        return -1;
    wn_ms_va ap;
    WN_VA_START(ap, fmt);
    int32_t r = wsprintf_w_impl(dst, fmt, (char *)ap);
    WN_VA_END(ap);
    return r;
}

static WN_CRTAPI int32_t u32_wvsprintfW(uint16_t *dst, const uint16_t *fmt,
                                     char *ap)
{
    if (!dst)
        return -1;
    return wsprintf_w_impl(dst, fmt, ap);
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
    { "SetWindowPos", u32_SetWindowPos },
    { "ShowWindow", u32_ShowWindow },
    { "MoveWindow", u32_MoveWindow },
    { "SetCapture", u32_SetCapture },
    { "ReleaseCapture", u32_ReleaseCapture },
    { "GetCapture", u32_GetCapture },
    { "RegisterWindowMessageA", u32_RegisterWindowMessageA },
    { "RegisterWindowMessageW", u32_RegisterWindowMessageW },
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
    { "LoadStringA", u32_LoadStringA },
    { "LoadStringW", u32_LoadStringW },
    { "CharNextA", u32_CharNextA },
    { "CharNextW", u32_CharNextW },
    { "CharPrevA", u32_CharPrevA },
    { "CharPrevW", u32_CharPrevW },
    { "MessageBoxIndirectW", u32_MessageBoxIndirectW },
    { "EnableWindow", u32_EnableWindow },
    { "IsWindowEnabled", u32_IsWindowEnabled },
    { "MessageBeep", u32_MessageBeep },
    { "GetMonitorInfoA", u32_GetMonitorInfoA },
    { "GetMonitorInfoW", u32_GetMonitorInfoW },
    { "MonitorFromWindow", u32_MonitorFromWindow },
    { "MonitorFromRect", u32_MonitorFromRect },
    { "MonitorFromPoint", u32_MonitorFromPoint },
    { "EnumDisplayMonitors", u32_EnumDisplayMonitors },
    { "GetSystemMetrics", u32_GetSystemMetrics },
    { "SystemParametersInfoA", u32_SystemParametersInfoA },
    { "SystemParametersInfoW", u32_SystemParametersInfoW },
    { "SetProcessDPIAware", u32_SetProcessDPIAware },
    { "GetDpiForWindow", u32_GetDpiForWindow },
    { "GetDpiForSystem", u32_GetDpiForSystem },
    { "ScreenToClient", u32_ScreenToClient },
    { "ClientToScreen", u32_ClientToScreen },
    { "GetParent", u32_GetParent },
    { "OffsetRect", u32_OffsetRect },
    { "InvalidateRect", u32_InvalidateRect },
    { "ValidateRect", u32_ValidateRect },
    { "GetSysColor", u32_GetSysColor },
    { "GetSysColorBrush", u32_GetSysColorBrush },
    { "ShowCursor", u32_ShowCursor },
    { "GetCursorPos", u32_GetCursorPos },
    { "GetKeyboardState", u32_GetKeyboardState },
    { "SetKeyboardState", u32_SetKeyboardState },
    { "GetKeyboardLayout", u32_GetKeyboardLayout },
    { "GetDoubleClickTime", u32_GetDoubleClickTime },
    { "GetCaretBlinkTime", u32_GetCaretBlinkTime },
    { "GetMessageTime", u32_GetMessageTime },
    { "GetQueueStatus", u32_GetQueueStatus },
    { "IsIconic", u32_IsIconic },
    { "IsZoomed", u32_IsZoomed },
    { "FlashWindow", u32_FlashWindow },
    { "SetForegroundWindow", u32_SetForegroundWindow },
    { "GetWindowPlacement", u32_GetWindowPlacement },
    { "SetWindowPlacement", u32_SetWindowPlacement },
    { "PeekMessageW", u32_PeekMessageW },
    { "GetMessageW", u32_GetMessageW },
    { "DispatchMessageW", u32_DispatchMessageW },
    { "DefWindowProcW", u32_DefWindowProcW },
    { "DefDlgProcA", u32_DefDlgProcA },
    { "SendMessageW", u32_SendMessageW },
    { "PostMessageW", u32_PostMessageW },
    { "SetWindowTextW", u32_SetWindowTextW },
    { "GetWindowTextW", u32_GetWindowTextW },
    { "GetWindowTextLengthA", u32_GetWindowTextLengthA },
    { "GetWindowTextLengthW", u32_GetWindowTextLengthW },
    { "SetDlgItemTextW", u32_SetDlgItemTextW },
    { "GetDlgItemTextA", u32_GetDlgItemTextA },
    { "GetDlgItemTextW", u32_GetDlgItemTextW },
    { "SendDlgItemMessageA", u32_SendDlgItemMessageA },
    { "SendDlgItemMessageW", u32_SendDlgItemMessageW },
    { "FindWindowA", u32_FindWindowA },
    { "LoadImageA", u32_LoadImageA },
    { "DestroyIcon", u32_DestroyIcon },
    { "CreateCaret", u32_CreateCaret },
    { "DestroyCaret", u32_DestroyCaret },
    { "ShowCaret", u32_ShowCaret },
    { "HideCaret", u32_HideCaret },
    { "SetCaretPos", u32_SetCaretPos },
    { "MsgWaitForMultipleObjects", u32_MsgWaitForMultipleObjects },
    { "wsprintfA", u32_wsprintfA },
    { "wsprintfW", u32_wsprintfW },
    { "wvsprintfA", u32_wvsprintfA },
    { "wvsprintfW", u32_wvsprintfW },
    { NULL, NULL },
};
