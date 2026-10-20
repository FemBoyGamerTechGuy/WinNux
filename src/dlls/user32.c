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
#include "wn_wow64.h"

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
    uint32_t proc32;          /* wow64: raw i386 wndproc (never call .proc) */
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
    uint32_t proc32;         /* wow64: raw i386 timer proc (never call .proc) */
    int active;
} wn_timer;

typedef struct wn_window {
    wn_bwin *bwin;            /* backend window (top-level) or child surface */
    wn_wndclass *cls;
    uint64_t hinstance;
    uint64_t userdata;
    char title[128];          /* UTF-8 mirror of the window text */
    uint16_t *wtext;           /* canonical text (UTF-16, NUL-terminated,
                                 DYNAMIC) for WM_GETTEXT(W)/paint; licenses
                                 stream 20KB+ through EM_STREAMIN — the old
                                 fixed 512-char cell showed only the head */
    int visible;
    int zero_sized;            /* created 0x0 (VCL TApplication owner):
                                 Windows shows nothing for a pixel-less
                                 window, but a mapped 1x1 gains a WM frame
                                 + taskbar entry under X11 — stay unmapped
                                 until it actually grows */
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
    /* per-window scroll state (V and H bars): classic SCROLLINFO
     * min/max/pos/page. Edits reuse top_item as first-visible LINE. */
    int sb_min[2], sb_max[2], sb_pos[2], sb_page[2];   /* [0]=V [1]=H */
    uint8_t sb_on[2];         /* WS_VSCROLL/HSCROLL actually shown */
    /* control state (Button/Edit/ListBox/ComboBox/ScrollBar + comctl32) */
    uint32_t check;           /* BST_ state */
    int caret;                /* edit: caret position (chars) */
    int sel;                  /* list/combo/tree: selected index/item */
    int top_item;             /* list: first visible row */
    char **items;             /* list/combo: strings (malloc'd) */
    int n_items, items_cap;
    uint64_t *item_data;      /* list/combo: LB_/CB_ per-item data (VCL's
                              * TCheckListBox stores its state objects here;
                              * NULL = all zero) */
    uint8_t *sel_bits;        /* list: multi-select state (LB_SETSEL/GETSEL) */
    void *ctl_priv;           /* comctl32 private data (tree nodes etc.) */
    uint8_t ctl_priv_kind;    /* WHICH payload ctl_priv is: a control-type
                               * blind DestroyWindow interpreted a msgbox
                               * ctx as treeview nodes and freed wild
                               * pointers (teardown SIGSEGV, rc=139). */
#define CTL_PRIV_NONE   0
#define CTL_PRIV_TV     1
#define CTL_PRIV_MSGBOX 2
    /* dialog support */
    int is_dialog;
    int dlg_done;
    int64_t dlg_result;
    uint64_t dlgproc;
    uint32_t dlgproc32;     /* wow64: raw i386 dlgproc (never call dlgproc) */
    uint64_t dlg_param;
    /* subclassing (SetWindowLong/GWLP_WNDPROC): the NEW proc; messages go
     * here first, the class proc becomes DefWindowProc-ish fallback. */
    uint64_t subclass;
    uint32_t subclass32;    /* wow64: raw i386 subclass proc */
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
static void u32_dirty_window_tree(uint64_t hwnd);
static void win_screen_origin(wn_window *w, int *x, int *y);
static int64_t ctl_get_text(wn_window *w, char *out, size_t cap);
static int64_t ctl_get_text_w(wn_window *w, uint16_t *out, size_t cap16);
static WN_API wn_abiword ctl_proc(wn_abiword hwnd, uint32_t msg,
                                  wn_abiword wp, wn_abiword_s lp);

/* window text messages (also re-listed with the control messages later) */
#ifndef WN_WM_SETTEXT
#define WN_WM_SETTEXT_FIRST    0x000C
#define WN_WM_SETTEXT          0x000C
#define WN_WM_GETTEXT          0x000D
#define WN_WM_GETTEXTLENGTH    0x000E
#endif
static WN_API uint64_t u32_SendMessageA(wn_abiword hwnd, uint32_t msg,
                                        wn_abiword wp, wn_abiword_s lp);
static WN_API int32_t u32_MessageBoxW(wn_abiword hwnd, const uint16_t *text,
                                     const uint16_t *caption, uint32_t type);
static WN_API int32_t u32_MessageBoxA(wn_abiword hwnd, const char *text,
                                     const char *caption, uint32_t type);

/* MessageBox engine (defined late in this file; ctl_proc's host-dialog
 * branch needs the context type early). */
#define WN_IDOK       1
#define WN_IDCANCEL   2
#define WN_IDABORT    3
#define WN_IDRETRY    4
#define WN_IDIGNORE   5
#define WN_IDYES      6
#define WN_IDNO       7
typedef struct msgbox_ctx {
    int32_t  result;
    int      done;
    uint32_t type;
    int      icon_kind;      /* 0 none, 1 error, 2 question, 3 warn, 4 info */
    int      n_buttons;
    int      ids[3];
    char     labels[3][20];
    char     mnem[3];        /* Alt+letter mnemonic (0 = none) */
    int      default_idx;
    int      icon_x, icon_y;
    uint64_t owner;
} msgbox_ctx;
static void msgbox_paint_icon(wn_handle hdc, msgbox_ctx *m);
static void msgbox_draw_glyph(wn_handle hdc, char c, int x, int y,
                              int w, int h);
static int  msgbox_has_cancel(msgbox_ctx *m);
static int  msgbox_close_answer(msgbox_ctx *m);

/* GUEST arch layout query: every layout-sensitive struct read/write in this
 * file must follow the GUEST'S architecture, not the host build. The x86-64
 * host runs i386 guests in-process (wow64), so compile-time #if is wrong;
 * wn_wow64_guest32() answers for the current builtin call. The i386 host
 * build (winnux32) is always 32-bit. (Systemic bug found via the Inno
 * Setup installer: RegisterClassA read the 32-bit guest's WNDCLASSA with
 * x64 offsets and registered a garbage class name -> "class does not
 * exist" -> Delphi exception.) */
static int u32_guest32(void)
{
#if defined(__x86_64__)
    return wn_wow64_guest32();
#else
    return 1;
#endif
}

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
/* GetKeyState semantics: low byte = TOGGLED (Caps/Num/Scroll/Insert),
 * high byte = DOWN. Toggles flip on each key press of those keys. */
static uint8_t g_key_toggle[256];
/* GetAsyncKeyState: bit0 = "pressed since the last GetAsyncKeyState". */
static uint8_t g_key_async_edge[256];
static uint32_t g_last_msg_time;

/* Is VK one of the Windows toggle keys? (0x14 VK_CAPITAL, 0x90
 * VK_NUMLOCK, 0x91 VK_SCROLL, 0x2D VK_INSERT, 0x46 'F', 0x2C
 * VK_SNAPSHOT keep their GetKeyState low-byte semantics on Windows
 * only for the classic four; we flip the classic set.) */
static int vk_is_toggle(uint32_t vk)
{
    return vk == 0x14 || vk == 0x90 || vk == 0x91 || vk == 0x2D;
}

/* X11 modifier mask -> VK down-state reconcile (XKeyEvent.state bits:
 * Shift=1, Lock=2, Control=4, Mod1=8). Dispatched by the backend
 * whenever the mask CHANGES, so a modifier held before our launch
 * (or eaten by a WM grab) is still reported truthfully. */
static void key_reconcile_mods(int mask)
{
    static const struct { int xbit; uint32_t vk; } map[] = {
        { 1, 0x10 /*VK_SHIFT*/ }, { 4, 0x11 /*VK_CONTROL*/ },
        { 8, 0x12 /*VK_MENU*/ },
    };
    for (unsigned i = 0; i < sizeof map / sizeof map[0]; i++) {
        int down = (mask & map[i].xbit) != 0;
        if (down)
            g_key_state[map[i].vk / 8] |= (uint8_t)(1u << (map[i].vk % 8));
        else
            g_key_state[map[i].vk / 8] &= (uint8_t)~(1u << (map[i].vk % 8));
    }
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
    case 0xFFE5: return 0x14;             /* CapsLock -> VK_CAPITAL */
    case 0xFF7F: return 0x90;             /* NumLock -> VK_NUMLOCK */
    case 0xFF14: return 0x91;             /* ScrollLock -> VK_SCROLL */
    case 0xFF61: return 0x2C;             /* PrintScreen (sysreq) */
    case 0xFFE7: case 0xFFE8: return 0x5B;/* Super -> LWIN */
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
        /* X11 WM_DELETE_WINDOW == the title-bar X / Alt+F4. Windows
         * delivers WM_SYSCOMMAND(SC_CLOSE) and DefWindowProc derives
         * WM_CLOSE from it; apps that intercept (Inno's Exit-Setup
         * confirm) see exactly one close request. */
        deliver_now(h, 0x0112 /*WM_SYSCOMMAND*/, 0xF060 /*SC_CLOSE*/, 0);
        break;
    case WN_BEV_KEYMODS:
        key_reconcile_mods(ev->val);
        break;
    case WN_BEV_KEY:
    case WN_BEV_KEYUP: {
        uint32_t vk = wn_user32_vk_from_keysym((uint32_t)ev->val);
        if (vk) {
            /* keyboard-state tracking for GetKeyboardState/GetKeyState:
             * down bit for every key, toggle flip + async edge on
             * press (GetKeyState low byte, GetAsyncKeyState bit0). */
            if (vk < 256) {
                if (ev->type == WN_BEV_KEY) {
                    g_key_state[vk / 8] |= (uint8_t)(1u << (vk % 8));
                    g_key_async_edge[vk / 8] |= (uint8_t)(1u << (vk % 8));
                    if (vk_is_toggle(vk))
                        g_key_toggle[vk / 8] ^= (uint8_t)(1u << (vk % 8));
                } else {
                    g_key_state[vk / 8] &= (uint8_t)~(1u << (vk % 8));
                }
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
        else if (ev->val2 == 4 || ev->val2 == 5 || ev->val2 == 6 ||
                 ev->val2 == 7) {
            /* X11 wheel buttons. Windows: WM_MOUSEWHEEL goes to the
             * window under the cursor, wParam = delta<<16 | keys,
             * lParam = signed screen coords. */
            if (!ev->val)   /* only on press; X11 wheel has no release */
                break;
            int up = (ev->val2 == 4 || ev->val2 == 6);
            uint32_t delta = up ? 120u : 0xFF88u;   /* +-120 */
            uint32_t hmsg = (ev->val2 == 6 || ev->val2 == 7);
            uint32_t keys = 0;
            if (g_key_state[0x10 / 8] & (1u << (0x10 % 8))) keys |= 4;
            if (g_key_state[0x11 / 8] & (1u << (0x11 % 8))) keys |= 8;
            uint32_t wheel_msg = hmsg ? 0x020E /*WM_MOUSEHWHEEL*/
                                      : 0x020A /*WM_MOUSEWHEEL*/;
            /* deepest visible child under the cursor, like clicks */
            uint64_t target = h;
            int mx = (int)(int16_t)ev->x, my = (int)(int16_t)ev->y;
            for (int depth = 0; depth < 8; depth++) {
                uint64_t next = 0;
                for (int i = 0; i < g_hwnd_count; i++) {
                    wn_window *c = g_hwnds[i].win;
                    if (!c || c->parent != target || !c->visible ||
                        c->in_destroy)
                        continue;
                    if (mx >= c->wx && my >= c->wy &&
                        mx < c->wx + c->cw && my < c->wy + c->ch) {
                        next = (uint64_t)(uintptr_t)g_hwnds[i].h;
                        break;
                    }
                }
                if (!next)
                    break;
                target = next;
            }
            int ox, oy;
            wn_window *tw = win_from_hwnd(target);
            if (tw) {
                win_screen_origin(tw, &ox, &oy);
            } else {
                ox = oy = 0;
            }
            post_msg(target, wheel_msg,
                     ((uint64_t)keys << 16) | (delta & 0xFFFF),
                     (int64_t)(((uint64_t)(uint16_t)(ox + mx)) |
                       ((uint64_t)(uint16_t)(oy + my) << 16)));
            break;
        }
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
     * bwin crashed on priv=NULL — the putty About-box segfault).
     *
     * SW_HIDE must UNMAP — and must NEVER map: the old code called
     * win_show unconditionally, so a hidden-to-be window (Delphi's
     * TApplication owner window, Inno's hidden MainForm) got MAPPED by
     * the very call that asked to hide it. Under a real WM every one of
     * those became a framed toplevel: the user's "two windows" report,
     * with the hidden owner painted white beside the wizard. */
    if (!w->parent && be) {
        if (cmd == 0 /* SW_HIDE */) {
            if (w->bwin->mapped && be->win_hide)
                be->win_hide(w->bwin);
        } else if (w->zero_sized && w->cw <= 1 && w->ch <= 1) {
            /* Zero-sized window (created 0x0, still 1x1): Windows shows
             * NOTHING for it; mapping under X11 gives it a WM frame +
             * taskbar entry — the ghost 1x1 "Setup" window report. */
        } else if (be->win_show) {
            be->win_show(w->bwin);
        }
    }
    w->visible = (cmd != 0);
    if (w->parent && w->visible)
        compose_child(w);
    if (cmd != 0)
        u32_dirty_window_tree((uint64_t)hwnd);   /* shown: invalidate subtree */
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
            /* a zero-sized window that GREW becomes a real, mappable
             * window (Windows would show it from now on) */
            if (win->zero_sized && (w > 1 || h > 1)) {
                win->zero_sized = 0;
                if (win->visible && !win->bwin->mapped && be &&
                    be->win_show)
                    be->win_show(win->bwin);
            }
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
    /* full-surface damage: the pump will synthesize ONE WM_PAINT — and the
     * resized SUBTREE needs one too (children hold their own offscreen
     * surfaces and see no X events; see u32_dirty_window_tree). */
    win->dirty.l = 0;
    win->dirty.t = 0;
    win->dirty.r = win->cw;
    win->dirty.b = win->ch;
    if (do_size)
        u32_dirty_window_tree(hwnd);
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
    }
    /* NO early return: VCL shows child controls with SWP flags 0x57
     * (NOSIZE|NOMOVE|NOZORDER|NOACTIVATE|FRAMECHANGED|SHOWWINDOW). An early
     * `return 1` on the no-size/no-move path swallowed SWP_SHOWWINDOW, so
     * the wizard's entire control tree stayed invisible=0 → never dirty →
     * never painted (white wizard with nothing but the form's bevels). */
    if (flags & 0x0040 /* SWP_SHOWWINDOW */)
        u32_ShowWindow(hwnd, 5);
    else if (flags & 0x0080 /* SWP_HIDEWINDOW */)
        u32_ShowWindow(hwnd, 0);
    return 1;
}

/* --- ScrollWindow / ScrollWindowEx ------------------------------------------
 * VCL scrolls client areas with ScrollWindowEx (TWinControl.ScrollBy and
 * the checklist paths); the returning-0 stub left the wizard with
 * GetLastError=ERROR_CALL_NOT_IMPLEMENTED and a stale checklist. Real
 * semantics on the surface model: shift the window's own bwin pixels by
 * (-dx,-dy) inside the scroll rect (clipped by prcClip), invalidate the
 * exposed strips so the guest repaints them through the normal WM_PAINT
 * pipeline, and report the exposed region's complexity like Windows:
 *   NULLREGION(1) / SIMPLEREGION(2) / COMPLEXREGION(3), 0 = error.
 * SW_SCROLLCHILDREN moves intersecting children (parent coords); children
 * keep their own surfaces, so the scroll itself only touches pixels.
 * SW_SMOOTHSCROLL is honored as an immediate scroll (no animation). */
#define WN_SW_SCROLLCHILDREN 0x0001u
#define WN_SW_INVALIDATE      0x0002u
#define WN_SW_ERASE           0x0004u   /* repaint path erases anyway */
#define WN_SW_SMOOTHSCROLL    0x0010u

static void u32_dirty_union(wn_window *w, int l, int t, int r, int b)
{
    if (r <= l || b <= t)
        return;
    if (w->dirty.l < 0) {
        w->dirty.l = l;
        w->dirty.t = t;
        w->dirty.r = r;
        w->dirty.b = b;
    } else {
        if (l < w->dirty.l) w->dirty.l = l;
        if (t < w->dirty.t) w->dirty.t = t;
        if (r > w->dirty.r) w->dirty.r = r;
        if (b > w->dirty.b) w->dirty.b = b;
    }
}

/* Mark a window and every descendant as fully dirty (one full WM_PAINT
 * each). Windows invalidates the whole newly-visible subtree on show and
 * the whole resized subtree on SetWindowPos; our child windows have NO X
 * window events (offscreen surfaces composed by their parents), so without
 * this they NEVER became dirty and NEVER painted — the wizard showed only
 * the form's own bevel lines while every child control stayed invisible
 * (white). */
static void u32_dirty_window_tree(uint64_t hwnd)
{
    for (int i = 0; i < g_hwnd_count; i++) {
        wn_window *w = g_hwnds[i].win;
        if (!w || w->in_destroy)
            continue;
        uint64_t cur = (uint64_t)(uintptr_t)g_hwnds[i].h;
        int depth = 0;
        int in_tree = 0;
        while (cur && depth++ < 64) {
            if (cur == hwnd) {
                in_tree = 1;
                break;
            }
            wn_window *cw = win_from_hwnd(cur);
            if (!cw)
                break;
            cur = cw->parent;
        }
        if (!in_tree)
            continue;
        if (w->cw > 0 && w->ch > 0) {
            w->dirty.l = 0;
            w->dirty.t = 0;
            w->dirty.r = w->cw;
            w->dirty.b = w->ch;
        }
    }
}

static uint32_t scroll_window_ex(uint64_t hwnd, int dx, int dy,
                                 const int32_t *prc_scroll,
                                 const int32_t *prc_clip, void *prc_update,
                                 uint32_t flags)
{
    wn_window *w = win_from_hwnd(hwnd);
    if (!w || !w->bwin || !w->bwin->pixels) {
        wn_last_error_set(WN_ERR_INVALID_HANDLE);
        return 0;   /* ERROR */
    }
    int W = w->bwin->width, H = w->bwin->height;
    /* Guest RECT is 4 x LONG (4 bytes) — identical on every arch. */
    int l = 0, t = 0, r = W, b = H;
    if (prc_scroll) {
        l = prc_scroll[0]; t = prc_scroll[1];
        r = prc_scroll[2]; b = prc_scroll[3];
    }
    if (prc_clip) {
        if (prc_clip[0] > l) l = prc_clip[0];
        if (prc_clip[1] > t) t = prc_clip[1];
        if (prc_clip[2] < r) r = prc_clip[2];
        if (prc_clip[3] < b) b = prc_clip[3];
    }
    if (l < 0) l = 0;
    if (t < 0) t = 0;
    if (r > W) r = W;
    if (b > H) b = H;
    if (r <= l || b <= t) {
        wn_last_error_set(WN_ERR_SUCCESS);
        return 1;   /* NULLREGION: nothing to scroll */
    }
    if (dx == 0 && dy == 0) {
        wn_last_error_set(WN_ERR_SUCCESS);
        return 2;   /* SIMPLEREGION, nothing exposed */
    }

    /* Shift the surface: new(x,y) = old(x+dx, y+dy), both inside [l,t,r,b).
     * Iterate destination rows in the safe order (memmove for horizontal
     * overlap; vertical overlap handled by direction). */
    {
        int stride = w->bwin->stride;
        uint8_t *px = w->bwin->pixels;
        int y = t, yend = b, ystep = 1;
        if (dy < 0) { y = b - 1; yend = t - 1; ystep = -1; }
        for (; y != yend; y += ystep) {
            int sy = y + dy;
            if (sy < t || sy >= b)
                continue;               /* row revealed by the scroll */
            int dst_l = l, dst_r = r;
            if (dx > 0) {
                dst_l = l + dx;          /* left edge revealed */
                if (dst_l > r) dst_l = r;
            } else {
                dst_r = r + dx;          /* right edge revealed */
                if (dst_r < l) dst_r = l;
            }
            if (dst_r <= dst_l)
                continue;
            memmove(px + (size_t)y * stride + (size_t)dst_l * 4,
                    px + (size_t)sy * stride + (size_t)(dst_l + dx) * 4,
                    (size_t)(dst_r - dst_l) * 4);
        }
    }

    /* Exposed strips (client coordinates) → dirty; prcUpdate gets the
     * bounding box of the uncovered area. Two independent strips, unioned:
     *   dy > 0 -> bottom strip [l, b-dy, r, b]   dy < 0 -> top strip
     *   dx > 0 -> right strip  [r-dx, t, r, b]   dx < 0 -> left strip     */
    int ex_l = 0x7FFFFFFF, ex_t = 0x7FFFFFFF, ex_r = -1, ex_b = -1;
    int both_axes = (dx != 0 && dy != 0);
    int s_l = 0, s_t = 0, s_r = 0, s_b = 0;
    if (dy != 0) {
        s_l = l; s_r = r;
        if (dy > 0) { s_t = b - dy; s_b = b; }
        else        { s_t = t;      s_b = t - dy; }
        u32_dirty_union(w, s_l, s_t, s_r, s_b);
        if (s_l < ex_l) ex_l = s_l;
        if (s_t < ex_t) ex_t = s_t;
        if (s_r > ex_r) ex_r = s_r;
        if (s_b > ex_b) ex_b = s_b;
    }
    if (dx != 0) {
        s_t = t; s_b = b;
        if (dx > 0) { s_l = r - dx; s_r = r; }
        else        { s_l = l;      s_r = l - dx; }
        u32_dirty_union(w, s_l, s_t, s_r, s_b);
        if (s_l < ex_l) ex_l = s_l;
        if (s_t < ex_t) ex_t = s_t;
        if (s_r > ex_r) ex_r = s_r;
        if (s_b > ex_b) ex_b = s_b;
    }
    if (flags & WN_SW_INVALIDATE)
        u32_dirty_union(w, l, t, r, b);   /* whole scroll region */
    if (prc_update) {
        int32_t *u = prc_update;
        if (ex_r > ex_l && ex_b > ex_t) {
            u[0] = ex_l; u[1] = ex_t; u[2] = ex_r; u[3] = ex_b;
        } else {
            u[0] = 0; u[1] = 0; u[2] = 0; u[3] = 0;
        }
    }

    /* SW_SCROLLCHILDREN: Windows moves every child intersecting the scroll
     * rect by (-dx,-dy) (coordinates only — no resize, no z-change). */
    if (flags & WN_SW_SCROLLCHILDREN) {
        for (int i = 0; i < g_hwnd_count; i++) {
            wn_window *c = g_hwnds[i].win;
            if (!c || c->parent != hwnd)
                continue;
            if (c->wx < r && c->wy < b && c->wx + c->cw > l &&
                c->wy + c->ch > t) {
                c->wx -= dx;
                c->wy -= dy;
            }
        }
    }

    /* Push the shifted pixels to the parent/root chain immediately; the
     * dirty region schedules the guest repaint of the exposed strips. */
    if (w->parent && w->visible)
        compose_child(w);
    else if (!w->parent && w->visible)
        present_root(w);

    wn_last_error_set(WN_ERR_SUCCESS);
    return both_axes ? 3u /* COMPLEXREGION */ : 2u /* SIMPLEREGION */;
}

static WN_API uint32_t u32_ScrollWindowEx(wn_abiword hwnd, int32_t dx,
                                         int32_t dy, const void *prc_scroll,
                                         const void *prc_clip,
                                         wn_abiword hrgn_update,
                                         void *prc_update, uint32_t flags)
{
    /* HRGN updates are not modeled: the invalidation rect (prcUpdate)
     * carries the same damage information for our painting model. */
    (void)hrgn_update;
    return scroll_window_ex((uint64_t)hwnd, dx, dy,
                            (const int32_t *)prc_scroll,
                            (const int32_t *)prc_clip, prc_update, flags);
}

static WN_API int32_t u32_ScrollWindow(wn_abiword hwnd, int32_t dx,
                                      int32_t dy, const void *prc_scroll,
                                      const void *prc_clip)
{
    return scroll_window_ex((uint64_t)hwnd, dx, dy,
                            (const int32_t *)prc_scroll,
                            (const int32_t *)prc_clip, NULL, 0) != 0;
}

/* --- focus, activation, desktop --------------------------------------------- */

/* Canonical UTF-16 text storage for every window (controls round-trip it). */
static void user32_set_wtext_utf8(wn_window *w, const char *s)
{
    uint16_t *t = wn_utf8_to_utf16_n(s ? s : "", s ? strlen(s) : 0);
    if (!t) {
        /* allocation failure: keep a safe empty buffer for readers */
        free(w->wtext);
        w->wtext = wn_xmalloc(sizeof(uint16_t));
        w->wtext[0] = 0;
        return;
    }
    free(w->wtext);
    w->wtext = t;
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
    user32_set_wtext_utf8(win, "");   /* dynamic wtext: never NULL */
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
        /* Real subclassing: return the CURRENT proc (subclass if set,
         * else the class proc — the raw i386 address for a 32-bit guest's
         * class; Delphi stores it and later calls it via CallWindowProc).
         * BUILTIN control classes have only a HOST proc — never hand a
         * host pointer to a 32-bit guest (it jumps to the pointer's low
         * 32 bits and dies; found via the Inno outer instance calling
         * CallWindowProc(OldProc) after WM_DESTROY). */
        if (w->subclass32)
            return (int64_t)(uint64_t)w->subclass32;
        if (w->subclass)
            return (int64_t)w->subclass;
        if (w->cls && w->cls->proc32)
            return (int64_t)(uint64_t)w->cls->proc32;
        if (u32_guest32())
            return 0;          /* builtin/host proc: not expressible */
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
    if (idx == GWLP_WNDPROC) {
        /* Install the subclass proc (the raw i386 address for a 32-bit
         * guest). Messages now go to it first; the guest forwards to the
         * class proc via CallWindowProc. */
        if (u32_guest32()) {
            w->subclass32 = (uint32_t)(uint64_t)v;
            w->subclass = 0;
        } else {
            w->subclass = (uint64_t)v;
            w->subclass32 = 0;
        }
        wn_log(WN_LOG_DEBUG, "user32: subclassed hwnd=%llx -> 0x%x/0x%llx",
               (unsigned long long)(uintptr_t)hwnd_of_window(w),
               (unsigned)w->subclass32, (unsigned long long)w->subclass);
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
     * hInstance@0x10, ..., lpszClassName@0x24 (40-byte struct).
     * WOW64: the guest is i386 while this code is x86-64 — runtime key. */
    const uint8_t *p = wc;
    int g32 = u32_guest32();
    const char *name = g32 ? *(const char **)(const void *)(p + 0x24)
                           : *(const char **)(const void *)(p + 0x40);
    WN_API wn_abiword (*proc)(wn_abiword, uint32_t, wn_abiword,
                              wn_abiword_s) =
        (WN_API wn_abiword (*)(wn_abiword, uint32_t, wn_abiword,
                               wn_abiword_s))
        (g32 ? *(const void **)(const void *)(p + 4)
             : *(const void **)(const void *)(p + 8));
    uint32_t cb_wnd_extra = g32 ? *(const uint32_t *)(const void *)(p + 0xC)
                                : *(const uint32_t *)(const void *)(p + 0x14);
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
            if (g32) {
                /* wow64: the wndproc is a raw i386 address — must re-enter
                 * 32-bit mode; never store it as a callable host pointer. */
                g_classes[i].proc = NULL;
                g_classes[i].proc32 = (uint32_t)(uintptr_t)proc;
            } else {
                g_classes[i].proc = proc;
                g_classes[i].proc32 = 0;
            }
            g_classes[i].style = *(const uint32_t *)(const void *)p;
            g_classes[i].cb_wnd_extra = cb_wnd_extra;
            g_classes[i].used = 1;
            wn_log(WN_LOG_DEBUG, "user32: class '%s' registered (proc %p)"
                   " 32-bit guest proc 0x%x", name, (void *)proc, (unsigned)g_classes[i].proc32);
            return 0xC000 + (uint64_t)i;
        }
    }
    wn_last_error_set(WN_ERR_NOT_ENOUGH_MEMORY);
    return 0;
}

static WN_API uint64_t u32_RegisterClassW(const void *wc)
{
    /* WNDCLASSW: same shape as the A struct but the name pointer at
     * 0x40(x64)/0x24(i386) is LPCWSTR. WOW64: runtime layout key. */
    const uint8_t *p = wc;
    int g32 = u32_guest32();
    const uint16_t *wname = g32
        ? *(const uint16_t **)(const void *)(p + 0x24)
        : *(const uint16_t **)(const void *)(p + 0x40);
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
    wcA.proc = g32 ? *(void **)(const void *)(p + 4)
                   : *(void **)(const void *)(p + 8);
    wcA.hinst = g32 ? *(const uint64_t *)(const void *)(p + 0x10)
                    : *(const uint64_t *)(const void *)(p + 0x18);
    wcA.name = name;
    return u32_RegisterClassA(&wcA);
}

/* --- GetClassInfo + char translation (the Inno Setup class path) ------------
 * Inno's flow is GetModuleFileName -> OemToChar -> CharLower -> GetClassInfo
 * -> RegisterClass; every one of these was a returning-0 stub, which Delphi
 * read as a NULL string / "class missing" and raised an exception. */
static wn_wndclass *builtin_control_class(const char *name);

static WN_API int32_t u32_GetClassInfoA(wn_abiword hinst, const char *name,
                                        void *out)
{
    if (!name || !out)
        return 0;
    wn_wndclass *cls = NULL;
    for (int i = 0; i < 32; i++)
        if (g_classes[i].used && wn_strcaseeq(g_classes[i].name, name))
            cls = &g_classes[i];
    if (!cls)
        cls = builtin_control_class(name);
    if (!cls) {
        wn_last_error_set(1407 /* ERROR_CLASS_DOES_NOT_EXIST */);
        return 0;
    }
    /* WNDCLASSA: x64 style@0(4) proc@8(8) cbCls@0x10 cbWnd@0x14 hinst@0x18
     * ... name@0x40 (0x48 bytes); i386 all-dword, proc@4, name@0x24. */
    uint8_t *o = out;
    int g32 = u32_guest32();
    memset(o, 0, g32 ? 0x28 : 0x48);
    if (g32) {
        *(uint32_t *)(void *)(o + 0x00) = cls->style;
        *(uint32_t *)(void *)(o + 0x04) = cls->proc32;
        *(uint32_t *)(void *)(o + 0x0C) = cls->cb_wnd_extra;
        *(uint32_t *)(void *)(o + 0x10) = (uint32_t)hinst;
        *(uint32_t *)(void *)(o + 0x24) = (uint32_t)(uintptr_t)name;
    } else {
        *(uint32_t *)(void *)(o + 0x00) = cls->style;
        *(uint64_t *)(void *)(o + 0x08) =
            cls->proc32 ? (uint64_t)cls->proc32 : (uint64_t)(uintptr_t)cls->proc;
        *(uint32_t *)(void *)(o + 0x14) = cls->cb_wnd_extra;
        *(uint64_t *)(void *)(o + 0x18) = hinst;
        *(uint64_t *)(void *)(o + 0x40) = (uint64_t)(uintptr_t)name;
    }
    return 1;
}

static WN_API int32_t u32_GetClassInfoW(wn_abiword hinst, const uint16_t *wname,
                                        void *out)
{
    if (!wname || !out)
        return 0;
    char *name = wn_utf16_to_utf8(wname, 256);
    if (!name)
        return 0;
    wn_wndclass *cls = NULL;
    for (int i = 0; i < 32; i++)
        if (g_classes[i].used && wn_strcaseeq(g_classes[i].name, name))
            cls = &g_classes[i];
    if (!cls)
        cls = builtin_control_class(name);
    if (!cls) {
        free(name);
        wn_last_error_set(1407 /* ERROR_CLASS_DOES_NOT_EXIST */);
        return 0;
    }
    /* fill the W-layout struct ourselves: same offsets as the A struct,
     * but lpszClassName@0x40(x64)/0x24(i386) is the guest's LPCWSTR. */
    uint8_t *o = out;
    int g32 = u32_guest32();
    memset(o, 0, g32 ? 0x28 : 0x48);
    if (g32) {
        *(uint32_t *)(void *)(o + 0x00) = cls->style;
        *(uint32_t *)(void *)(o + 0x04) = cls->proc32;
        *(uint32_t *)(void *)(o + 0x0C) = cls->cb_wnd_extra;
        *(uint32_t *)(void *)(o + 0x10) = (uint32_t)hinst;
        *(uint32_t *)(void *)(o + 0x24) = (uint32_t)(uintptr_t)wname;
    } else {
        *(uint32_t *)(void *)(o + 0x00) = cls->style;
        *(uint64_t *)(void *)(o + 0x08) =
            cls->proc32 ? (uint64_t)cls->proc32 : (uint64_t)(uintptr_t)cls->proc;
        *(uint32_t *)(void *)(o + 0x14) = cls->cb_wnd_extra;
        *(uint64_t *)(void *)(o + 0x18) = hinst;
        *(uint64_t *)(void *)(o + 0x40) = (uint64_t)(uintptr_t)wname;
    }
    free(name);
    return 1;
}

/* CharLower/CharUpper: lowercase/uppercase IN PLACE and return the pointer
 * (the return value IS a string pointer — returning 0 turned Delphi's
 * class-name into NULL). Buff variants take a length and return it. */
static WN_API uint64_t u32_CharLowerA(wn_abiword s)
{
    char *p = (char *)(uintptr_t)s;
    if (!p)
        return 0;
    for (; *p; p++)
        if (*p >= 'A' && *p <= 'Z')
            *p += 32;
    return s;
}

static WN_API uint64_t u32_CharUpperA(wn_abiword s)
{
    char *p = (char *)(uintptr_t)s;
    if (!p)
        return 0;
    for (; *p; p++)
        if (*p >= 'a' && *p <= 'z')
            *p -= 32;
    return s;
}

static WN_API uint64_t u32_CharLowerW(wn_abiword s)
{
    uint16_t *p = (uint16_t *)(uintptr_t)s;
    if (!p)
        return 0;
    for (; *p; p++)
        if (*p >= 'A' && *p <= 'Z')
            *p += 32;
        else if (*p >= 0xC380 && *p <= 0xC39A)   /* Latin-1 caps */
            *p += 32;
    return s;
}

static WN_API uint64_t u32_CharUpperW(wn_abiword s)
{
    uint16_t *p = (uint16_t *)(uintptr_t)s;
    if (!p)
        return 0;
    for (; *p; p++)
        if (*p >= 'a' && *p <= 'z')
            *p -= 32;
        else if (*p >= 0xC3A0 && *p <= 0xC3B6)
            *p -= 32;
    return s;
}

static WN_API uint32_t u32_CharLowerBuffA(char *s, uint32_t len)
{
    for (uint32_t i = 0; i < len; i++)
        if (s[i] >= 'A' && s[i] <= 'Z')
            s[i] += 32;
    return len;
}

static WN_API uint32_t u32_CharUpperBuffA(char *s, uint32_t len)
{
    for (uint32_t i = 0; i < len; i++)
        if (s[i] >= 'a' && s[i] <= 'z')
            s[i] -= 32;
    return len;
}

static WN_API uint32_t u32_CharLowerBuffW(uint16_t *s, uint32_t len)
{
    for (uint32_t i = 0; i < len; i++)
        if (s[i] >= 'A' && s[i] <= 'Z')
            s[i] += 32;
    return len;
}

static WN_API uint32_t u32_CharUpperBuffW(uint16_t *s, uint32_t len)
{
    for (uint32_t i = 0; i < len; i++)
        if (s[i] >= 'a' && s[i] <= 'z')
            s[i] -= 32;
    return len;
}

/* OemToChar/CharToOem: OEM and ANSI overlap for the printable ASCII range
 * (everything installers pass through them), so a byte copy is the right
 * v1 semantics. W variants widen via UTF-8. In-place use is common
 * (src == dst) — memmove covers it. */
static WN_API int32_t u32_OemToCharA(const char *src, char *dst)
{
    if (!src || !dst)
        return 0;
    memmove(dst, src, strlen(src) + 1);
    return 1;
}

static WN_API int32_t u32_CharToOemA(const char *src, char *dst)
{
    return u32_OemToCharA(src, dst);
}

static WN_API int32_t u32_OemToCharBuffA(const char *src, char *dst,
                                         uint32_t len)
{
    if (!src || !dst || !len)
        return 0;
    memmove(dst, src, len);
    return 1;
}

static WN_API int32_t u32_CharToOemBuffA(const char *src, char *dst,
                                         uint32_t len)
{
    return u32_OemToCharBuffA(src, dst, len);
}

static WN_API int32_t u32_OemToCharW(const char *src, uint16_t *dst)
{
    if (!src || !dst)
        return 0;
    /* OEM(ANSI) -> UTF-16 */
    uint16_t *w = wn_utf8_to_utf16_n(src, strlen(src) + 1);
    if (!w)
        return 0;
    size_t n16 = 0;
    while (w[n16])
        n16++;
    memcpy(dst, w, (n16 + 1) * 2);
    free(w);
    return 1;
}

static WN_API int32_t u32_CharToOemW(const uint16_t *src, char *dst)
{
    if (!src || !dst)
        return 0;
    char *a = wn_utf16_to_utf8(src, 4096);
    if (!a)
        return 0;
    memmove(dst, a, strlen(a) + 1);
    free(a);
    return 1;
}

static wn_wndclass *builtin_control_class(const char *name);
static void compose_child(wn_window *child);
static WN_API int32_t u32_DestroyWindow(wn_abiword hwnd);

/* Invoke a window proc with the right width. The window's subclass
 * (SetWindowLong/GWLP_WNDPROC) runs first; 32-bit (wow64) procs are raw
 * i386 addresses that must re-enter 32-bit mode — calling them as host
 * functions would execute i386 code in 64-bit mode. On the i386 build
 * (and for host builtin classes) .proc is native and called directly. */
static uint64_t call_guest_wndproc(const wn_window *w, uint64_t hwnd,
                                   uint32_t msg, uint64_t wp, int64_t lp)
{
    if (w->subclass32)
        return wn_wow64_call_wndproc32(w->subclass32, (uint32_t)hwnd, msg,
                                       (uint32_t)wp, (uint32_t)lp);
    if (w->subclass) {
        typedef WN_API uint64_t (*p4)(wn_abiword, uint32_t, wn_abiword,
                                      wn_abiword_s);
        return ((p4)(uintptr_t)w->subclass)((wn_abiword)hwnd, msg,
                                            (wn_abiword)wp,
                                            (wn_abiword_s)lp);
    }
    const wn_wndclass *cls = w->cls;
    if (!cls)
        return 0;
    if (cls->proc32)
        return wn_wow64_call_wndproc32(cls->proc32, (uint32_t)hwnd, msg,
                                       (uint32_t)wp, (uint32_t)lp);
    if (!cls->proc)
        return 0;
    return cls->proc((wn_abiword)hwnd, msg, (wn_abiword)wp,
                     (wn_abiword_s)lp);
}

/* Invoke a guest dlgproc (same rules as call_guest_wndproc; w->dlgproc32
 * is set at dialog creation when the caller is a 32-bit guest). */
static int64_t call_guest_dlgproc(const wn_window *w, uint64_t hwnd,
                                  uint32_t msg, uint64_t wp, int64_t lp)
{
    if (w->dlgproc32)
        return (int64_t)wn_wow64_call_wndproc32(w->dlgproc32, (uint32_t)hwnd,
                                               msg, (uint32_t)wp,
                                               (uint32_t)lp);
    typedef WN_API wn_abiword_s (*dlgproc_fn)(wn_abiword, uint32_t,
                                              wn_abiword, wn_abiword_s);
    return ((dlgproc_fn)(uintptr_t)w->dlgproc)((wn_abiword)hwnd, msg,
                                               (wn_abiword)wp,
                                               (wn_abiword_s)lp);
}

/* Windows sends the create-message sequence (WM_NCCREATE, WM_NCCALCSIZE,
 * WM_CREATE) synchronously INSIDE CreateWindowEx, before the handle is
 * returned — never through the queue (posting WM_CREATE made Inno Setup's
 * pump dispatch it with lp=NULL forever, and starved the queue of the
 * messages that actually matter). Delphi/VCL and installer frameworks
 * hook their per-window data via lpCreateParams inside exactly this
 * window. The CREATESTRUCT/RECT are laid out for the GUEST arch (wow64:
 * i386 shapes in low memory) and freed after delivery.
 * Returns 0 when the proc rejected creation (-1), else 1. */
static int send_create_msgs(uint64_t hwnd, uint64_t hinst, uint64_t menu,
                            uint64_t parent, int x, int y, int cw, int ch,
                            uint32_t style, uint32_t ex_style,
                            uint64_t lp_create_params,
                            uint64_t lpsz_name, uint64_t lpsz_class)
{
    int g32 = u32_guest32();
    size_t cs_sz = g32 ? 0x30 : 0x50;
    size_t rect_off = cs_sz;            /* RECT right after CREATESTRUCT */
    size_t blk_sz = rect_off + 16;
    uint8_t *blk;
#if defined(__x86_64__)
    blk = g32 ? wn_low_malloc(blk_sz) : wn_xmalloc(blk_sz);
#else
    blk = wn_xmalloc(blk_sz);           /* 32-bit host: guest reads host VA */
#endif
    memset(blk, 0, blk_sz);
    uint32_t *rc = (uint32_t *)(void *)(blk + rect_off);
    rc[0] = (uint32_t)x; rc[1] = (uint32_t)y;
    rc[2] = (uint32_t)(x + cw); rc[3] = (uint32_t)(y + ch);
    if (g32) {
        uint32_t *cs = (uint32_t *)(void *)blk;
        cs[0]  = (uint32_t)lp_create_params;
        cs[1]  = (uint32_t)hinst;
        cs[2]  = (uint32_t)menu;
        cs[3]  = (uint32_t)parent;
        cs[4]  = (uint32_t)ch;         /* cy */
        cs[5]  = (uint32_t)cw;         /* cx */
        cs[6]  = (uint32_t)y;
        cs[7]  = (uint32_t)x;
        cs[8]  = style;
        cs[9]  = (uint32_t)lpsz_name;
        cs[10] = (uint32_t)lpsz_class;
        cs[11] = ex_style;
    } else {
        uint64_t *q = (uint64_t *)(void *)blk;
        q[0] = lp_create_params; q[1] = hinst;
        q[2] = menu;            q[3] = parent;
        *(uint32_t *)(void *)(blk + 0x20) = (uint32_t)ch;
        *(uint32_t *)(void *)(blk + 0x24) = (uint32_t)cw;
        *(uint32_t *)(void *)(blk + 0x28) = (uint32_t)y;
        *(uint32_t *)(void *)(blk + 0x2C) = (uint32_t)x;
        *(uint32_t *)(void *)(blk + 0x30) = style;
        q[7] = lpsz_name;        /* blk + 0x38 */
        q[8] = lpsz_class;       /* blk + 0x40 */
        *(uint32_t *)(void *)(blk + 0x48) = ex_style;
    }
    uint64_t r;
    r = u32_SendMessageA((wn_abiword)hwnd, 0x0081 /* WM_NCCREATE */, 0,
                         (wn_abiword_s)(int64_t)(uintptr_t)blk);
    if (r == (uint64_t)-1)
        goto fail;
    /* wParam = FALSE: lParam points at a RECT the proc may shrink. */
    u32_SendMessageA((wn_abiword)hwnd, 0x0083 /* WM_NCCALCSIZE */, 0,
                     (wn_abiword_s)(int64_t)(uintptr_t)(blk + rect_off));
    r = u32_SendMessageA((wn_abiword)hwnd, WN_WM_CREATE, 0,
                         (wn_abiword_s)(int64_t)(uintptr_t)blk);
    if (r == (uint64_t)-1)
        goto fail;
#if defined(__x86_64__)
    if (g32) wn_low_free(blk); else free(blk);
#else
    free(blk);
#endif
    return 1;
fail:
#if defined(__x86_64__)
    if (g32) wn_low_free(blk); else free(blk);
#else
    free(blk);
#endif
    return 0;
}

static const void *g_last_create_caller;   /* guest site of CreateWindowEx* */

/* Core creation path. lpsz_class_orig / lpsz_name_orig are the GUEST's
 * original class/title pointers (CreateWindowExA: the char* args;
 * CreateWindowExW: the guest's UTF-16 pointers) handed back inside the
 * CREATESTRUCT. Internal callers (dialog engine) pass 0 — their strings
 * are host-side and must not be shown to a 32-bit guest. */
static uint64_t create_window_core(uint32_t ex_style, const char *cls_name,
                                   const char *title,
                                   uint64_t lpsz_class_orig,
                                   uint64_t lpsz_name_orig,
                                   uint32_t style, int x, int y, int w, int h,
                                   wn_abiword parent, wn_abiword menu,
                                   wn_abiword hinst, void *param)
{
    if (ensure_gui() != 0 && !parent) {
        wn_log(WN_LOG_WARN, "user32: CreateWindow('%s') failed: no backend "
               "for a top-level window", cls_name ? cls_name : "?");
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
            wn_log(WN_LOG_WARN, "user32: CreateWindow('%s') failed: class "
                   "not registered (RegisterClassA missing?)",
                   cls_name ? cls_name : "?");
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
            char gsite[96];
            wn_module_describe_addr(g_last_create_caller, gsite,
                                    sizeof gsite);
            wn_log(WN_LOG_WARN, "user32: CreateWindow('%s') failed: parent "
                   "hwnd 0x%llx is not a live window (guest site %s)",
                   cls_name ? cls_name : "?", (unsigned long long)parent,
                   gsite);
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
        if (!send_create_msgs((uint64_t)(uintptr_t)hwnd, hinst, menu, parent,
                              x, y, win->cw, win->ch, style, ex_style,
                              (uint64_t)(uintptr_t)param,
                              lpsz_name_orig, lpsz_class_orig)) {
            wn_log(WN_LOG_WARN, "user32: CreateWindow('%s') failed: the "
                   "wndproc rejected creation (WM_CREATE verdict -1)",
                   cls_name ? cls_name : "?");
            u32_DestroyWindow((wn_abiword)(uintptr_t)hwnd);
            wn_last_error_set(WN_ERR_NOT_SUPPORTED);
            return 0;
        }
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
    /* Created 0x0? (Delphi's hidden TApplication owner is a WS_POPUP 0x0
     * tool window — under Windows it covers no pixels, but VCL still creates
     * it WS_VISIBLE.) Mark it: it must never be MAPPED while it stays
     * pixel-less, or a real WM frames it as a ghost toplevel. */
    win->zero_sized = (w <= 0 || h <= 0);
    /* Windows size contract: w/h of 0 means a ZERO-sized window (Delphi's
     * hidden TApplication owner is exactly that — a WS_POPUP 0x0 tool
     * window; inflating it to 640x480 made it a visible framed toplevel:
     * the "two windows" field report). Creation with x = CW_USEDEFAULT
     * keeps the historical default sizing for apps relying on it. */
    if (x == (int32_t)0x80000000u /* CW_USEDEFAULT */) {
        if (w <= 0) w = 640;
        if (h <= 0) h = 480;
    } else {
        if (w <= 0) w = 1;
        if (h <= 0) h = 1;
    }
    win->cw = w;                     /* canonical size (cw/ch, not just bwin) */
    win->ch = h;
    win->bwin = be->win_create(w, h, win->title, win);
    if (!win->bwin) {
        free(win);
        wn_log(WN_LOG_WARN, "user32: CreateWindow('%s') failed: backend "
               "win_create returned NULL", cls_name ? cls_name : "?");
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

    /* Windows order: WM_NCCREATE/WM_NCCALCSIZE/WM_CREATE (sent inside
     * CreateWindowEx), THEN the show sequence. */
    if (!send_create_msgs((uint64_t)(uintptr_t)hwnd, hinst, menu, parent,
                          x, y, w, h, style, ex_style,
                          (uint64_t)(uintptr_t)param,
                          lpsz_name_orig, lpsz_class_orig)) {
        wn_log(WN_LOG_WARN, "user32: CreateWindow('%s') failed: the wndproc "
               "rejected creation (WM_CREATE verdict -1)",
               cls_name ? cls_name : "?");
        u32_DestroyWindow((wn_abiword)(uintptr_t)hwnd);
        wn_last_error_set(WN_ERR_NOT_SUPPORTED);
        return 0;
    }

    if (style & 0x10000000 /* WS_VISIBLE */)
        u32_ShowWindow((uint64_t)(uintptr_t)hwnd, 5);

    wn_log(WN_LOG_DEBUG, "user32: CreateWindow('%s') hwnd=0x%llx %dx%d",
           cls_name, (unsigned long long)(uintptr_t)hwnd, w, h);
    return (uint64_t)(uintptr_t)hwnd;
}

static WN_API uint64_t u32_CreateWindowExA(uint32_t ex_style, const char *cls_name,
                                           const char *title, uint32_t style,
                                           int x, int y, int w, int h,
                                           wn_abiword parent, wn_abiword menu,
                                           wn_abiword hinst, void *param)
{
    g_last_create_caller = __builtin_return_address(0);
    return create_window_core(ex_style, cls_name, title,
                              (uint64_t)(uintptr_t)cls_name,
                              (uint64_t)(uintptr_t)title,
                              style, x, y, w, h, parent, menu, hinst, param);
}

static WN_API uint64_t u32_CreateWindowExW(uint32_t ex, const uint16_t *cls,
                                           const uint16_t *title, uint32_t style,
                                           int x, int y, int w, int h,
                                           wn_abiword parent, wn_abiword menu,
                                           wn_abiword hinst, void *param)
{
    char *c = cls ? wn_utf16_to_utf8(cls, 256) : NULL;
    char *t = title ? wn_utf16_to_utf8(title, 256) : NULL;
    /* The CREATESTRUCT must carry the guest's ORIGINAL UTF-16 pointers. */
    uint64_t r = create_window_core(ex, c ? c : "", t ? t : "",
                                    (uint64_t)(uintptr_t)cls,
                                    (uint64_t)(uintptr_t)title,
                                    style, x, y, w, h, parent, menu, hinst,
                                    param);
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
    {
        /* Forensics (DEBUG): the guest call site of every DestroyWindow —
         * VCL teardown vs RecreateWnd vs an app path are different sites. */
        char where[96];
        wn_module_describe_addr(__builtin_return_address(0), where,
                                sizeof where);
        wn_log(WN_LOG_DEBUG, "user32: DestroyWindow(0x%llx '%s') from %s",
               (unsigned long long)hwnd,
               w->title[0] ? w->title : (w->cls ? w->cls->name : "?"),
               where);
    }
    /* Destroy children first (Windows order). */
    for (int i = 0; i < g_hwnd_count; i++) {
        wn_window *c = g_hwnds[i].win;
        if (c && c->parent == hwnd && !c->in_destroy)
            u32_DestroyWindow((uint64_t)(uintptr_t)g_hwnds[i].h);
    }
    /* WM_DESTROY goes through the proc directly (in-order with calls). */
    if (w->cls && (w->cls->proc || w->cls->proc32 || w->subclass ||
                   w->subclass32)) {
        call_guest_wndproc(w, hwnd, WN_WM_DESTROY, 0, 0);
        /* Windows sends WM_NCDESTROY (0x82) AFTER WM_DESTROY; VCL zeroes
         * FHandle in its WMNCDestroy handler. Skipping it left every
         * destroyed window's FHandle stale on the guest side — the Inno
         * recreate flow then built pages under dead parents and died with
         * EOutOfResources('Error creating window'). */
        call_guest_wndproc(w, hwnd, 0x82 /*WM_NCDESTROY*/, 0, 0);
    }
    /* control payloads: DISPATCH ON THE TAG — ctl_priv has more than
     * one owner now (treeview nodes, msgbox ctx). The old unconditional
     * tv_free() walked a msgbox_ctx as tv_data and freed wild pointers:
     * the wizard answered Yes, then teardown SIGSEGV'd (rc=139). */
    if (w->ctl_priv) {
        if (w->ctl_priv_kind == CTL_PRIV_TV)
            tv_free(w);
        else if (w->ctl_priv_kind == CTL_PRIV_MSGBOX) {
            free(w->ctl_priv);
            w->ctl_priv = NULL;
        }
        /* unknown tag: leak on purpose — never free blind */
    }
    for (int i = 0; i < w->n_items; i++)
        free(w->items[i]);
    free(w->items);
    w->items = NULL;
    w->n_items = w->items_cap = 0;
    free(w->wtext);                  /* dynamic canonical text */
    w->wtext = NULL;
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
        if (g_timers[i].proc32) {
            wn_wow64_call_wndproc32(g_timers[i].proc32,
                                   (uint32_t)g_timers[i].hwnd, WN_WM_TIMER,
                                   (uint32_t)g_timers[i].id, 0);
        } else if (g_timers[i].proc) {
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

/* Guest MSG layout (winuser.h): x64 = 48 bytes (hwnd@0, message@8,
 * wParam@0x10, lParam@0x18, time@0x20, pt@0x24), i386 = 28 bytes
 * (hwnd@0, message@4, wParam@8, lParam@0xC, time@0x10, pt@0x14).
 * The layout follows the GUEST's architecture (see u32_guest32 at the
 * top): the 32-byte shape on an i386 guest smashes the caller's frame
 * and leaves garbage fields (found via the Inno Setup installer loop). */
static void fill_msg(void *msg_out, const wn_msg *m)
{
    uint8_t *o = msg_out;
    if (u32_guest32()) {
        memset(o, 0, 0x1C);
        *(uint32_t *)(void *)(o + 0x00) = (uint32_t)m->hwnd;
        *(uint32_t *)(void *)(o + 0x04) = m->message;
        *(uint32_t *)(void *)(o + 0x08) = (uint32_t)m->wparam;
        *(int32_t  *)(void *)(o + 0x0C) = (int32_t)m->lparam;
        *(uint32_t *)(void *)(o + 0x10) = m->time;
        *(int32_t  *)(void *)(o + 0x14) = m->pt_x;
        *(int32_t  *)(void *)(o + 0x18) = m->pt_y;
    } else {
        memset(o, 0, 0x30);
        *(uint64_t *)(void *)(o + 0x00) = m->hwnd;
        *(uint32_t *)(void *)(o + 0x08) = m->message;
        *(uint64_t *)(void *)(o + 0x10) = m->wparam;
        *(int64_t  *)(void *)(o + 0x18) = m->lparam;
        *(uint32_t *)(void *)(o + 0x20) = m->time;
        *(int32_t  *)(void *)(o + 0x24) = m->pt_x;
        *(int32_t  *)(void *)(o + 0x28) = m->pt_y;
    }
    g_last_msg_time = m->time;    /* GetMessageTime */
}

/* Parse a guest MSG back out (DispatchMessage/TranslateMessage read the
 * buffer PeekMessage filled a moment ago — same guest-layout rules). */
static void msg_read(const void *msg, uint64_t *hwnd, uint32_t *message,
                     uint64_t *wp, int64_t *lp)
{
    const uint8_t *p = msg;
    if (u32_guest32()) {
        *hwnd    = *(const uint32_t *)(const void *)(p + 0x00);
        *message = *(const uint32_t *)(const void *)(p + 0x04);
        *wp      = *(const uint32_t *)(const void *)(p + 0x08);
        *lp      = *(const int32_t  *)(const void *)(p + 0x0C);
    } else {
        *hwnd    = *(const uint64_t *)(const void *)(p + 0x00);
        *message = *(const uint32_t *)(const void *)(p + 0x08);
        *wp      = *(const uint64_t *)(const void *)(p + 0x10);
        *lp      = *(const int64_t  *)(const void *)(p + 0x18);
    }
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

/* WaitMessage: yield/block until something is queueable for this thread
 * WITHOUT consuming it. Delphi's TApplication.Idle calls WaitMessage when
 * there is nothing left to do; the returning-0 stub made that idle loop a
 * 100%-CPU spin (field case: LuaForWindows wizard alive and idle at 101k
 * WaitMessage/min under WinNux). Same wake sources as GetMessage: posted
 * messages, the quit flag, timer deadlines, backend input. */
static WN_API int32_t u32_WaitMessage(void)
{
    if (ensure_gui() != 0)
        return 0;
    for (;;) {
        if (g_quit_posted || g_q_count)
            return 1;
        if (pump_once())
            continue;          /* may have queued paints/timers/input */
        if (g_quit_posted || g_q_count)
            return 1;
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
        /* input or a timer deadline may have arrived — report wake */
        return 1;
    }
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
    /* wRemoveCmd: PM_NOREMOVE = 0 (leave the message queued), PM_REMOVE = 1
     * (consume it). This was INVERTED for the project's whole life: Inno
     * Setup's silent-mode pump (PeekMessage(..., PM_REMOVE)) re-peeked the
     * same message forever and the installer never progressed (the
     * "millions of PeekMessageA lines" report). */
    if (!(remove & 1 /* PM_REMOVE */)) {
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
    uint64_t hwnd;
    uint32_t message;
    uint64_t wp;
    int64_t lp;
    msg_read(msg, &hwnd, &message, &wp, &lp);
    wn_window *w = win_from_hwnd(hwnd);
    wn_log(WN_LOG_DEBUG, "dispatch: hwnd=%llx msg=%u wp=%llx lp=%llx w=%p",
           (unsigned long long)hwnd, message, (unsigned long long)wp,
           (unsigned long long)lp, (void *)w);
    if (w && ((w->cls && (w->cls->proc || w->cls->proc32)) ||
              w->subclass || w->subclass32)) {
        wn_log(WN_LOG_DEBUG, "dispatch: -> proc %p / 32-bit 0x%x subclass 0x%x",
               w->cls ? (void *)(uintptr_t)w->cls->proc : NULL,
               w->cls ? (unsigned)w->cls->proc32 : 0u,
               (unsigned)w->subclass32);
        return call_guest_wndproc(w, hwnd, message, wp, lp);
    }
    return 0;
}

static WN_API uint64_t u32_DefWindowProcA(wn_abiword hwnd, uint32_t msg,
                                          wn_abiword wp, wn_abiword_s lp)
{
    switch (msg) {
    case 0x0112 /* WM_SYSCOMMAND */: {
        /* The Windows close chain: X / Alt+F4 -> WM_SYSCOMMAND(SC_CLOSE)
         * -> DefWindowProc sends WM_CLOSE -> DestroyWindow. SC_MINIMIZE
         * / SC_MAXIMIZE / SC_RESTORE go through ShowWindow so an app
         * posting system commands (VCL system menus) behaves. */
        switch (wp & 0xFFF0) {
        case 0xF060 /*SC_CLOSE*/:
            return u32_SendMessageA(hwnd, WN_WM_CLOSE, 0, 0);
        case 0xF020 /*SC_MINIMIZE*/:
            u32_ShowWindow(hwnd, 6 /*SW_MINIMIZE*/);
            return 0;
        case 0xF030 /*SC_MAXIMIZE*/:
            u32_ShowWindow(hwnd, 3 /*SW_MAXIMIZE*/);
            return 0;
        case 0xF120 /*SC_RESTORE*/:
            u32_ShowWindow(hwnd, 9 /*SW_RESTORE*/);
            return 0;
        default:
            return 0;   /* SC_MOVE/SC_SIZE: WM owns geometry */
        }
    }
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
    case 0x0081 /* WM_NCCREATE */:
        /* DefWindowProc returns TRUE to let creation proceed. */
        return 1;
    case WN_WM_SETTEXT: {
        /* VCL sets form captions through Perform(WM_SETTEXT) —
         * TControl.SetTextBuf — NOT the SetWindowText API. Without this
         * branch the Inno wizard stayed titleless under the WM (the
         * "(Window without title)" field report) while the hidden
         * TApplication owner — whose title arrives via the API — showed
         * as the ghost "Setup" window. */
        wn_window *w = win_from_hwnd(hwnd);
        if (!w)
            return 0;
        char *a = NULL;
        const char *src = "";
        if (w->is_uni) {
            const uint16_t *ws = (const uint16_t *)(uintptr_t)lp;
            size_t n16 = 0;
            if (ws)
                while (n16 < 65536 && ws[n16])
                    n16++;
            a = ws ? wn_utf16_to_utf8(ws, n16) : NULL;
            src = a ? a : "";
        } else {
            src = (const char *)(uintptr_t)lp;
        }
        snprintf(w->title, sizeof w->title, "%s", src ? src : "");
        user32_set_wtext_utf8(w, src ? src : "");
        if (!w->parent) {
            const wn_backend *be = wn_backend_get();
            if (be && be->win_set_title && w->bwin)
                be->win_set_title(w->bwin, w->title);
        }
        if (w->parent && w->visible)
            compose_child(w);
        free(a);
        return 1;
    }
    case WN_WM_GETTEXT: {
        wn_window *w = win_from_hwnd(hwnd);
        if (!w || !lp || wp == 0)
            return 0;
        if (w->is_uni)
            return ctl_get_text_w(w, (uint16_t *)(uintptr_t)lp, (size_t)wp);
        return ctl_get_text(w, (char *)(uintptr_t)lp, (size_t)wp);
    }
    case WN_WM_GETTEXTLENGTH: {
        wn_window *w = win_from_hwnd(hwnd);
        if (!w)
            return 0;
        size_t n = 0;
        while (w->wtext[n])
            n++;
        return (int64_t)n;
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
    if (!w && hwnd) {
        /* stale-handle counter: a message to a destroyed hwnd means the
         * guest kept a dead FHandle (the Inno recreate flow's crash
         * class). Deduped: the (hwnd, msg) pair logs ONCE (the
         * installer's 0x496-to-0xac1 spam buried real errors); the
         * answer contract is unchanged — DefWindowProc returns 0. */
        static struct { uint64_t hwnd; uint32_t msg; uint32_t hits; }
            dead_note[8];
        int slot = -1;
        for (int i = 0; i < 8; i++) {
            if (dead_note[i].hwnd == hwnd && dead_note[i].msg == msg) {
                slot = i;
                break;
            }
            if (dead_note[i].hits == 0 && slot < 0)
                slot = i;
        }
        if (slot >= 0) {
            if (dead_note[slot].hits)
                dead_note[slot].hits++;
            else {
                dead_note[slot].hwnd = hwnd;
                dead_note[slot].msg = msg;
                dead_note[slot].hits = 1;
                wn_log(WN_LOG_WARN, "user32: SendMessageA(msg=%u) to DEAD"
                       " hwnd 0x%llx — handled by DefWindowProc"
                       " (further hits deduped)",
                       msg, (unsigned long long)hwnd);
            }
        }
    }
    if (w && ((w->cls && (w->cls->proc || w->cls->proc32)) ||
              w->subclass || w->subclass32))
        return call_guest_wndproc(w, (uint64_t)hwnd, msg,
                                  (uint64_t)wp, (int64_t)lp);
    /* Builtin-class window (a guest-registered class ALWAYS carries a
     * proc; a NULL proc marks OURS): ctl_proc IS the class proc — that
     * is where BM_/EM_/LB_/CB_ semantics and the painting live. Windows'
     * SendMessage reaches the control's wndproc; routing these to
     * DefWindowProc silently swallowed control messages (EM_STREAMIN
     * never ran on bare builtin richedits). */
    if (w && w->cls && !w->cls->proc && !w->cls->proc32)
        return ctl_proc(hwnd, msg, wp, lp);
    return u32_DefWindowProcA(hwnd, msg, wp, lp);
}

/* CallWindowProc: subclass chains forward to the ORIGINAL proc through
 * this. The proc argument is the value GetWindowLong returned — a raw
 * i386 address for 32-bit guests, callable only via the wow64 bridge. */
static WN_API uint64_t u32_CallWindowProcA(wn_abiword proc, wn_abiword hwnd,
                                          uint32_t msg, wn_abiword wp,
                                          wn_abiword_s lp)
{
    if (!proc)
        return u32_DefWindowProcA(hwnd, msg, wp, lp);   /* NULL = default */
    if (u32_guest32())
        return wn_wow64_call_wndproc32((uint32_t)(uint64_t)proc,
                                       (uint32_t)(uint64_t)hwnd, msg,
                                       (uint32_t)(uint64_t)wp,
                                       (uint32_t)(uint64_t)lp);
    typedef WN_API uint64_t (*p4)(wn_abiword, uint32_t, wn_abiword,
                                  wn_abiword_s);
    return ((p4)(uintptr_t)proc)(hwnd, msg, wp, lp);
}

static WN_API uint64_t u32_CallWindowProcW(wn_abiword proc, wn_abiword hwnd,
                                          uint32_t msg, wn_abiword wp,
                                          wn_abiword_s lp)
{
    return u32_CallWindowProcA(proc, hwnd, msg, wp, lp);
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
            /* wow64: a 32-bit guest's TIMERPROC is a raw i386 address. */
            g_timers[i].proc32 = (proc && u32_guest32())
                ? (uint32_t)(uintptr_t)proc : 0;
            if (g_timers[i].proc32)
                g_timers[i].proc = NULL;
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
extern WN_API wn_handle g32_BeginPaint(wn_abiword hwnd, void *ps);
extern WN_API int32_t g32_EndPaint(wn_abiword hwnd, const void *ps);
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

/* Post-paint compose for GUEST-class child windows (VCL panels, the Inno
 * checklist...). ctl_proc composes builtin controls itself, but a child
 * window painted by the GUEST's WM_PAINT path ends at g32_EndPaint, which
 * can only present the child's own offscreen bwin (no X window). Without
 * walking the parent chain, everything the guest painted on a child was
 * invisible. */
void wn_user32_compose_if_child(uint64_t hwnd)
{
    wn_window *w = win_from_hwnd(hwnd);
    while (w && w->parent && !w->in_destroy) {
        wn_window *p = win_from_hwnd(w->parent);
        if (!p)
            break;
        compose_child(w);       /* blit w onto its parent (+ root present) */
        w = p;
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

/* --- builtin control procs: Button, Edit, Static, ListBox, ComboBox, ScrollBar ---
 *
 * Each control owns its state in wn_window (check/caret/sel/items). Painting
 * goes to the control surface then composes onto the parent. Notifications
 * ride WM_COMMAND (buttons, lists, edits) as Windows does.
 */

typedef enum { CTL_BUTTON, CTL_STATIC, CTL_EDIT, CTL_LISTBOX, CTL_COMBO,
               CTL_SCROLLBAR, CTL_TREEVIEW } ctl_kind;


/* case-insensitive substring test for VCL subclass class-name matching */
static int u32_cls_has(const char *cls, const char *tok)
{
    size_t lt = strlen(tok);
    for (; *cls; cls++) {
        size_t i = 0;
        while (i < lt && cls[i] && tok[i] &&
               ((cls[i] >= 'A' && cls[i] <= 'Z' ? cls[i] + 32 : cls[i]) ==
                (tok[i] >= 'A' && tok[i] <= 'Z' ? tok[i] + 32 : tok[i])))
            i++;
        if (i == lt)
            return 1;
    }
    return 0;
}

static ctl_kind ctl_kind_of(const char *cls)
{
    if (!cls || !cls[0])
        return CTL_SCROLLBAR;
    if (wn_strcaseeq(cls, "Button"))         return CTL_BUTTON;
    if (wn_strcaseeq(cls, "Static"))         return CTL_STATIC;
    if (wn_strcaseeq(cls, "Edit"))           return CTL_EDIT;
    /* RichEdit 1.0/2.0/3.0/4.0/5.0 class names (riched32/riched20/
     * riched30/msftedit). Installers use them as read-only text viewers
     * (Inno TRichEditViewer): memo semantics are exactly Edit. */
    if (wn_strcaseprefix(cls, "RichEdit"))   return CTL_EDIT;
    if (wn_strcaseeq(cls, "ListBox"))        return CTL_LISTBOX;
    if (wn_strcaseeq(cls, "ComboBox"))       return CTL_COMBO;
    if (wn_strcaseeq(cls, "SysTreeView32"))  return CTL_TREEVIEW;
    /* Delphi VCL registers each TWinControl subclass under its OWN class
     * name (CreateSubClass: 'TNewRadioButton' wraps the original BUTTON
     * proc — the session-17 proc32 contract). Exact-name matching sent
     * them all to the generic branch: raw TextOutA captions with a
     * literal '&', no check glyph, no 3D frames, no wrapping — the
     * "(&accept)" field report. Token matching (most specific first)
     * restores the ORIGINAL standard control's semantics. */
    if (u32_cls_has(cls, "RadioButton"))   return CTL_BUTTON;
    if (u32_cls_has(cls, "CheckBox"))      return CTL_BUTTON;
    if (u32_cls_has(cls, "GroupBox"))      return CTL_BUTTON;
    if (u32_cls_has(cls, "CheckListBox"))  return CTL_LISTBOX;
    if (u32_cls_has(cls, "ListBox"))       return CTL_LISTBOX;
    if (u32_cls_has(cls, "ComboBox"))      return CTL_COMBO;
    if (u32_cls_has(cls, "TreeView"))      return CTL_TREEVIEW;
    if (u32_cls_has(cls, "StaticText"))    return CTL_STATIC;
    if (u32_cls_has(cls, "RichEdit"))      return CTL_EDIT;
    if (u32_cls_has(cls, "Memo"))          return CTL_EDIT;
    if (u32_cls_has(cls, "Edit"))          return CTL_EDIT;
    if (u32_cls_has(cls, "Button"))        return CTL_BUTTON;
    return CTL_SCROLLBAR;
}

#define WN_WM_COMMAND    0x0111
#define WN_WM_SETTEXT    0x000C
#define WN_WM_GETTEXT    0x000D
#define WN_WM_GETTEXTLENGTH 0x000E

extern WN_API int32_t g32_DrawTextA(wn_handle hdc, const char *s,
                                    int32_t count, void *rect, uint32_t fmt);
extern WN_API int32_t g32_DrawTextW(wn_handle hdc, const uint16_t *s,
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
#define EM_STREAMIN   0x0449          /* WM_USER+73: SF_TEXT/SF_RTF stream */
#define WN_SF_TEXT    0x0001u
#define WN_SF_RTF     0x0002u
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
#define LB_SETITEMDATA   0x019A
#define LB_GETITEMDATA   0x0199
#define LB_SETSEL        0x0185
#define LB_GETSEL        0x0187
#define LB_GETSELCOUNT   0x0190
#define LB_FINDSTRING    0x018F
#define LB_GETTOPINDEX   0x018E
#define CB_SETITEMDATA   0x0151
#define CB_GETITEMDATA   0x0150
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

/* --- scroll geometry + painting + input ------------------------------- */
#define WN_SBW 17                        /* SM_CXVSCROLL classic width */
#define WN_WM_HSCROLL 0x0114
#define WN_WM_VSCROLL 0x0115
#define WN_WM_MOUSEWHEEL 0x020A
/* SB_ codes (wparam low word) */
#define SB_LINEUP       0
#define SB_LINEDOWN     1
#define SB_PAGEUP       2
#define SB_PAGEDOWN     3
#define SB_THUMBPOSITION 4
#define SB_THUMBTRACK   5
#define SB_ENDSCROLL    7
/* SCROLLINFO fields (all DWORD — guest-layout independent) */
#define SIF_RANGE  0x1
#define SIF_PAGE   0x2
#define SIF_POS    0x4
#define SIF_ALL    0x17

/* clamp the bar's position into [min, max-page+1] */
static void sb_clamp(wn_window *w, int bar)
{
    int span = w->sb_max[bar] - w->sb_min[bar];
    int lim = span > w->sb_page[bar] ? w->sb_max[bar] - (w->sb_page[bar] - 1)
                                     : w->sb_min[bar];
    if (w->sb_pos[bar] < w->sb_min[bar])
        w->sb_pos[bar] = w->sb_min[bar];
    if (w->sb_pos[bar] > lim)
        w->sb_pos[bar] = lim;
}

/* thumb rect for bar[0]=V / [1]=H inside a WxH control */
static void sb_thumb_rect(wn_window *w, int bar, int W, int H,
                          int *tx, int *ty, int *tw, int *th)
{
    if (bar == 0) {
        int track = H - 2 * WN_SBW;
        int span = w->sb_max[0] - w->sb_min[0];
        int movable = span > w->sb_page[0] ? span - (w->sb_page[0] - 1) : 1;
        int tlen = w->sb_page[0] > 0 && span > 0
                     ? (track * w->sb_page[0]) / (span + 1) : WN_SBW;
        if (tlen < 8) tlen = 8;
        if (tlen > track) tlen = track;
        int tpos = movable > 1
                     ? ((w->sb_pos[0] - w->sb_min[0]) * (track - tlen))
                        / movable : 0;
        *tx = W - WN_SBW; *ty = WN_SBW + tpos; *tw = WN_SBW; *th = tlen;
    } else {
        int track = W - 2 * WN_SBW;
        int span = w->sb_max[1] - w->sb_min[1];
        int movable = span > w->sb_page[1] ? span - (w->sb_page[1] - 1) : 1;
        int tlen = w->sb_page[1] > 0 && span > 0
                     ? (track * w->sb_page[1]) / (span + 1) : WN_SBW;
        if (tlen < 8) tlen = 8;
        if (tlen > track) tlen = track;
        int tpos = movable > 1
                     ? ((w->sb_pos[1] - w->sb_min[1]) * (track - tlen))
                        / movable : 0;
        *tx = WN_SBW + tpos; *ty = H - WN_SBW; *tw = tlen; *th = WN_SBW;
    }
}

/* paint one scrollbar strip inside (0,0,W,H); bar 0 = V (right edge),
 * bar 1 = H (bottom edge). Arrows are drawn as pixel triangles. */
static void sb_paint(wn_handle hdc, wn_window *w, int bar, int W, int H)
{
    uint32_t track_rgb = 0x00D4D0C8 /*COLOR_SCROLLBAR*/, btn = 0x00D4D0C8;
    int l, t, r, b;
    if (bar == 0) {
        l = W - WN_SBW; t = 0; r = W; b = H;
    } else {
        l = 0; t = H - WN_SBW; r = W; b = H;
    }
    int32_t rect[4] = { l, t, r, b };
    wn_handle tb = g32_CreateSolidBrush(track_rgb);
    g32_FillRect(hdc, rect, tb);
    wn_handle_close(tb);
    /* arrow triangles: two filled rects narrowing to a point */
    int ax0 = l + 2, ax1 = r - 2;
    if (bar == 0) {
        int ay0 = t + 2, ay1 = t + WN_SBW - 2;
        wn_handle ab = g32_CreateSolidBrush(0);
        for (int i = 0; i < 6; i++) {
            int32_t tri[4] = { ax0 + i, ay0 + i, ax1 - i,
                               ay0 + i + 1 };
            g32_FillRect(hdc, tri, ab);
            int32_t tri2[4] = { ax0 + i, ay1 - i, ax1 - i,
                                 ay1 - i + 1 };
            g32_FillRect(hdc, tri2, ab);
        }
        wn_handle_close(ab);
    } else {
        int ax = l + 2, bx = l + WN_SBW - 2;
        wn_handle ab = g32_CreateSolidBrush(0);
        for (int i = 0; i < 6; i++) {
            int32_t tri[4] = { ax + i, t + 2 + i, ax + i + 1,
                               b - 2 - i };
            g32_FillRect(hdc, tri, ab);
            int32_t tri2[4] = { bx - i, t + 2 + i, bx - i + 1,
                                b - 2 - i };
            g32_FillRect(hdc, tri2, ab);
        }
        wn_handle_close(ab);
    }
    (void)btn;
    /* thumb */
    int tx, ty, tw, th;
    sb_thumb_rect(w, bar, W, H, &tx, &ty, &tw, &th);
    int32_t tr[4] = { tx, ty, tx + tw, ty + th };
    wn_handle hb = g32_CreateSolidBrush(0x00A0A0A0);
    g32_FillRect(hdc, tr, hb);
    wn_handle_close(hb);
    int32_t fr[4] = { tx + 1, ty + 1, tx + tw - 1, ty + th - 1 };
    wn_handle fb = g32_CreateSolidBrush(0x00E8E8E8);
    g32_FillRect(hdc, fr, fb);
    wn_handle_close(fb);
}

/* apply an SB_ code to a window's own scroll state (V only here);
 * returns the new position or -1 when nothing changed. */
static int sb_apply(wn_window *w, int bar, uint32_t sb)
{
    int before = w->sb_pos[bar];
    switch (sb) {
    case SB_LINEUP:   w->sb_pos[bar] -= 1; break;
    case SB_LINEDOWN: w->sb_pos[bar] += 1; break;
    case SB_PAGEUP:   w->sb_pos[bar] -= (w->sb_page[bar] > 0
                                           ? w->sb_page[bar] : 1); break;
    case SB_PAGEDOWN: w->sb_pos[bar] += (w->sb_page[bar] > 0
                                           ? w->sb_page[bar] : 1); break;
    case SB_THUMBPOSITION:
    case SB_THUMBTRACK:
        break;                       /* pos already set by the drag */
    default:
        return -1;
    }
    sb_clamp(w, bar);
    if (w->sb_pos[bar] == before)
        return -1;
    return w->sb_pos[bar];
}

/* does this window paint a scrollbar strip? (style-driven) */
static int sb_bar_visible(wn_window *w, int bar)
{
    if (w->sb_on[bar])
        return 1;
    uint32_t bit = bar == 0 ? 0x00200000u /*WS_VSCROLL*/ : 0x00100000u;
    return (w->style & bit) != 0;
}

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
        w->ctl_priv_kind = CTL_PRIV_TV;
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
    uint64_t *nd = realloc(w->item_data, (size_t)cap * sizeof(uint64_t));
    if (!nd) {
        if (!w->item_data)
            w->items = ni;   /* keep the strings; data stays NULL */
        return -1;
    }
    memset(nd + w->n_items, 0,
           (size_t)(cap - w->n_items) * sizeof(uint64_t));
    w->item_data = nd;
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

/* LB_INSERTSTRING: insert at index, shifting item_data too (VCL's
 * TCheckListBox inserts items at positions and keeps its state array
 * aligned with the list). */
static int ctl_items_insert(wn_window *w, int idx, const char *s)
{
    if (idx < 0 || idx > w->n_items)
        return -1;
    if (ctl_items_reserve(w, w->n_items + 1) != 0)
        return -1;
    memmove(&w->items[idx], &w->items[idx + 1],
            (size_t)(w->n_items - idx) * sizeof(char *));
    if (w->item_data)
        memmove(&w->item_data[idx], &w->item_data[idx + 1],
                (size_t)(w->n_items - idx) * sizeof(uint64_t));
    w->items[idx] = wn_xstrdup(s ? s : "");
    w->n_items++;
    if (w->sel >= idx)
        w->sel++;
    return idx;
}

static void ctl_items_clear(wn_window *w)
{
    for (int i = 0; i < w->n_items; i++)
        free(w->items[i]);
    free(w->items);
    free(w->item_data);
    free(w->sel_bits);
    w->items = NULL;
    w->item_data = NULL;
    w->sel_bits = NULL;
    w->n_items = w->items_cap = 0;
    w->sel = -1;
    w->top_item = 0;
}

/* UTF-16 text -> control storage (SETTEXT/GETTEXT core) */
static void ctl_set_text(wn_window *w, const char *utf8)
{
    const char *s = utf8 ? utf8 : "";
    snprintf(w->title, sizeof w->title, "%s", s);
    /* FULL text into wtext (dynamic) — title stays a 127-char display
     * mirror, but multi-line viewers (Inno's license memo via WM_SETTEXT,
     * the richedit viewer via EM_STREAMIN) hold 20KB+; truncating through
     * title cut the license to its head. */
    user32_set_wtext_utf8(w, s);
    size_t n = 0;
    while (w->wtext[n])
        n++;
    w->caret = (int)(n < 511 ? n : 511);
}

static int64_t ctl_get_text(wn_window *w, char *out, size_t cap)
{
    /* canonical UTF-16 text first: it carries the FULL multi-line payload
     * (title is a 127-char mirror — WM_GETTEXT on the license memo must
     * round-trip the whole text, not its truncated head). */
    if (w->wtext[0]) {
        size_t n16 = 0;
        while (w->wtext[n16])
            n16++;
        char *a = wn_utf16_to_utf8(w->wtext, n16);
        if (a) {
            snprintf(out, cap, "%s", a);
            free(a);
            return (int64_t)strlen(out);
        }
    }
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
    if (w->caret < 0 || (size_t)w->caret > n)
        w->caret = (int)n;
    /* dynamic growth: one char at a time is rare (typing); realloc up */
    uint16_t *grown = wn_xrealloc(w->wtext, (n + 2) * sizeof(uint16_t));
    if (!grown)
        return;
    w->wtext = grown;
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

/* --- RTF -> plain text (EM_STREAMIN, SF_RTF) ---------------------------------
 * Inno Setup feeds the license page through EM_STREAMIN+SF_RTF: the guest
 * installs an EDITSTREAM callback and Windows PULLS the RTF bytes through
 * it. The message was silently ignored before, so the license body never
 * rendered ("the license text is invisible" report). The stripper keeps
 * the visible text: drops destination groups ({\fonttbl}, {\colortbl},
 * {\generator}...), decodes \par/\line to newlines, \'hh bytes, \uN,
 * escaped braces; converts the CP1252 result to UTF-8 for wtext. */
typedef struct { unsigned char *p; size_t n, cap; } rtf_buf;

static int rtf_put(rtf_buf *b, int c)
{
    if (b->n + 1 >= b->cap) {
        size_t nc = b->cap ? b->cap * 2 : 8192;
        unsigned char *np = wn_xrealloc(b->p, nc);
        if (!np)
            return 0;
        b->p = np;
        b->cap = nc;
    }
    b->p[b->n++] = (unsigned char)c;
    return 1;
}

static int rtf_hex4(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* control words whose whole GROUP carries no visible content */
static int rtf_is_destination(const unsigned char *w, size_t wl)
{
    static const char *skip[] = { "fonttbl", "colortbl", "stylesheet",
        "generator", "info", "pict", "object", "header", "footer",
        "headerl", "headerr", "headerf", "footnote", "filetbl",
        "listtable", "listoverridetable", "rsidtbl", "latentstyles",
        "datastore", "xmlnstbl", "theme", "colorschememapping",
        "mmathPr", "wgrffmtfilter", "listpicture", "panose", "fname",
        "company", "title", "subject", "author", "operator", "keywords",
        "comment", "doccomm", "creatim", "revtim", "printim", "buptim",
        "version", "nofchars", "nofwords", "edmins", "id", "hlinkbase",
        "cchs", "vern", NULL };
    for (int i = 0; skip[i]; i++) {
        size_t sl = strlen(skip[i]);
        if (wl == sl && memcmp(w, skip[i], sl) == 0)
            return 1;
    }
    return 0;
}

/* CP1252 bytes -> UTF-8 (RTF body bytes are ANSI/CP1252). */
static char *rtf_cp1252_to_utf8(const unsigned char *in, size_t n)
{
    char *out = wn_xmalloc(n * 3 + 4);
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        uint32_t c = in[i];
        if (c >= 0x80 && c <= 0x9F) {
            /* the CP1252 specials (0x80..0x9F); unmapped holes keep U+FFFD */
            static const uint16_t hi[32] = {
                0x20AC, 0x81, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021,
                0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0x8D, 0x017D, 0x8F,
                0x90, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014,
                0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x9D, 0x017E, 0x0178
            };
            c = hi[c - 0x80];
        }
        if (c == 0x81 || c == 0x8D || c == 0x8F || c == 0x90 || c == 0x9D)
            c = 0xFFFD;
        if (c < 0x80) {
            out[o++] = (char)c;
        } else if (c < 0x800) {
            out[o++] = (char)(0xC0 | (c >> 6));
            out[o++] = (char)(0x80 | (c & 0x3F));
        } else {
            out[o++] = (char)(0xE0 | (c >> 12));
            out[o++] = (char)(0x80 | ((c >> 6) & 0x3F));
            out[o++] = (char)(0x80 | (c & 0x3F));
        }
    }
    out[o] = 0;
    return out;
}

/* RTF bytes -> malloc'd UTF-8 plain text (NULL on OOM). */
static char *rtf_to_text(const unsigned char *in, size_t in_n)
{
    rtf_buf o = { NULL, 0, 0 };
    /* per-group skip flags (destination groups swallow their content) */
    int skip[128];
    int depth = 0;
    skip[0] = 0;
    size_t i = 0;
    if (!in || !in_n)
        return wn_xstrdup("");
    if (!rtf_put(&o, 0))     /* ensure a buffer exists */
        return NULL;
    o.n = 0;
    while (i < in_n && depth >= 0) {
        unsigned char c = in[i];
        if (c == '{') {
            if (depth < 126) { depth++; skip[depth] = skip[depth - 1]; }
            i++;
            continue;
        }
        if (c == '}') {
            if (depth > 0) depth--;
            i++;
            continue;
        }
        if (c == '\\') {
            if (i + 1 >= in_n)
                break;
            unsigned char d = in[i + 1];
            if (d == '\\' || d == '{' || d == '}') {   /* escaped literal */
                if (!skip[depth]) rtf_put(&o, d);
                i += 2;
                continue;
            }
            if (d == '~') { if (!skip[depth]) rtf_put(&o, ' '); i += 2; continue; }
            if (d == '*') { skip[depth] = 1; i += 2; continue; }  /* \* dest */
            if (d == '-' || d == '_') { i += 2; continue; }        /* soft hyph */
            if (d == '\'') {                                       /* \'hh */
                int h1 = (i + 2 < in_n) ? rtf_hex4(in[i + 2]) : -1;
                int h2 = (i + 3 < in_n) ? rtf_hex4(in[i + 3]) : -1;
                if (h1 >= 0 && h2 >= 0) {
                    if (!skip[depth]) rtf_put(&o, (h1 << 4) | h2);
                    i += 4;
                    continue;
                }
                i += 2;
                continue;
            }
            /* control word: \word[+-]?digits?  [one optional space] */
            i++;
            size_t ws = i;
            while (i < in_n && ((in[i] >= 'a' && in[i] <= 'z') ||
                                (in[i] >= 'A' && in[i] <= 'Z')))
                i++;
            size_t wl = i - ws;
            long num = 0;
            int have_num = 0;
            size_t ds = i;
            if (i < in_n && in[i] == '-') i++;
            if (i < in_n && in[i] >= '0' && in[i] <= '9') {
                size_t ns = i;
                while (i < in_n && in[i] >= '0' && in[i] <= '9') i++;
                for (size_t k = ns; k < i; k++)
                    num = num * 10 + (in[k] - '0');
                have_num = 1;
            }
            if (i < in_n && in[i] == ' ')
                i++;
            (void)ds;
            if (wl && rtf_is_destination(in + ws, wl)) {
                skip[depth] = 1;
                continue;
            }
            if (skip[depth])
                continue;
            if (wl == 3 && memcmp(in + ws, "par", 3) == 0)
                rtf_put(&o, '\n');
            else if (wl == 4 && memcmp(in + ws, "line", 4) == 0)
                rtf_put(&o, '\n');
            else if (wl == 4 && memcmp(in + ws, "sect", 4) == 0)
                rtf_put(&o, '\n');
            else if (wl == 4 && memcmp(in + ws, "page", 4) == 0)
                rtf_put(&o, '\n');
            else if (wl == 3 && memcmp(in + ws, "tab", 3) == 0)
                rtf_put(&o, '\t');
            else if (wl == 1 && in[ws] == 'u' && have_num) {
                /* \uN: one UTF-16 code unit. Surrogate pairs are rare in
                 * license text — lone surrogates become U+FFFD. */
                uint32_t cp = (uint32_t)num;
                if (cp >= 0xD800 && cp <= 0xDFFF)
                    cp = 0xFFFD;
                if (cp < 0x80) {
                    rtf_put(&o, (int)cp);
                } else if (cp < 0x800) {
                    rtf_put(&o, (int)(0xC0 | (cp >> 6)));
                    rtf_put(&o, (int)(0x80 | (cp & 0x3F)));
                } else {
                    rtf_put(&o, (int)(0xE0 | (cp >> 12)));
                    rtf_put(&o, (int)(0x80 | ((cp >> 6) & 0x3F)));
                    rtf_put(&o, (int)(0x80 | (cp & 0x3F)));
                }
                /* the substitution byte(s) after \uN (\uc default 1):
                 * drop the next raw char if it is a plain literal */
                if (i < in_n && in[i] != '\\' && in[i] != '{' && in[i] != '}')
                    i++;
            }
            continue;
        }
        if (c == '\r' || c == '\n') {   /* raw CR/LF: RTF layout only */
            i++;
            continue;
        }
        if (!skip[depth])
            rtf_put(&o, c);
        i++;
    }
    if (!o.p)
        return NULL;
    char *utf8 = rtf_cp1252_to_utf8(o.p, o.n);
    free(o.p);
    return utf8;
}

static WN_API wn_abiword ctl_proc(wn_abiword hwnd, uint32_t msg,
                                  wn_abiword wp, wn_abiword_s lp)
{
    wn_window *w = win_from_hwnd(hwnd);
    if (!w)
        return 0;
    /* HOST-managed dialog (is_dialog with NO guest dlgproc): the
     * MessageBox engine's box. Same DefDlgProc paint semantics (face +
     * children), plus: WM_COMMAND(BN_CLICKED) records the answer,
     * WM_CLOSE/SC_CLOSE answer with Cancel/OK. ctl_priv carries the
     * msgbox context. (ctx type + helpers defined later in this file;
     * declared at the top.) */
    if (w->is_dialog && !w->dlgproc && !w->dlgproc32 && w->ctl_priv) {
        msgbox_ctx *m = w->ctl_priv;
        switch (msg) {
        case WN_WM_PAINT: {
            wn_handle hdc = g32_GetDC(hwnd);
            if (hdc) {
                int32_t rect[4] = { 0, 0, w->cw, w->ch };
                wn_handle bg = g32_CreateSolidBrush(0x00C8D0D4 /*face*/);
                g32_FillRect(hdc, rect, bg);
                wn_handle_close(bg);
                msgbox_paint_icon(hdc, m);
            }
            compose_children_of(hwnd);
            const wn_backend *be = wn_backend_get();
            if (be && be->present && w->bwin)
                be->present(w->bwin);
            w->dirty.l = -1;
            w->paint_pending = 0;
            return 0;
        }
        case WN_WM_COMMAND: {
            uint32_t code = (uint32_t)((uint64_t)wp >> 16);
            uint32_t id = (uint32_t)((uint64_t)wp & 0xFFFF);
            if (code == 0 /*BN_CLICKED*/) {
                for (int i = 0; i < m->n_buttons; i++) {
                    if (m->ids[i] == (int)id) {
                        m->result = m->ids[i];
                        m->done = 1;
                        post_msg(hwnd, 0, 0, 0);   /* wake the modal loop */
                        break;
                    }
                }
            }
            return 0;
        }
        case WN_WM_CLOSE:
            m->result = msgbox_close_answer(m);
            m->done = 1;
            post_msg(hwnd, 0, 0, 0);
            return 0;
        case 0x0112 /*WM_SYSCOMMAND*/:
            if (((uint32_t)wp & 0xFFF0) == 0xF060 /*SC_CLOSE*/) {
                m->result = msgbox_close_answer(m);
                m->done = 1;
                post_msg(hwnd, 0, 0, 0);
                return 0;
            }
            return 0;
        default:
            return u32_DefWindowProcA(hwnd, msg, wp, lp);
        }
    }
    /* #32770 dialog: every message goes to the guest dlgproc (WM_COMMAND
     * from child controls, WM_CLOSE, ...). Without this the dialog was a
     * black hole: clicks produced WM_COMMANDs that vanished in ctl_proc's
     * default case. WM_PAINT is special: DefDlgProc's job is erasing the
     * background and composing children — the guest dlgproc never paints
     * the face color itself (found via putty: dialog went black after the
     * routing fix). */
    if (w->is_dialog && (w->dlgproc || w->dlgproc32)) {
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
        int64_t r = call_guest_dlgproc(w, hwnd, msg, wp, lp);
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
        int has_v = sb_bar_visible(w, 0) && k != CTL_BUTTON &&
                    k != CTL_STATIC;
        int has_h = sb_bar_visible(w, 1) && k != CTL_BUTTON &&
                    k != CTL_STATIC;
        if (has_v)
            W -= WN_SBW;             /* content never under the strip */
        if (has_h)
            H -= WN_SBW;
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
            /* Rich edits and memos are MULTI-LINE BY CLASS (VCL may omit
             * the ES_MULTILINE style bit — Inno's TRichEditViewer renders
             * through TEdit). Style-bit OR class-name decides; falling
             * back to the single-line branch drew the 127-char title
             * mirror instead of the streamed license (one clipped line).*/
            int is_memo = (w->style & 0x4) != 0 ||
                          u32_cls_has(cls, "RichEdit") ||
                          u32_cls_has(cls, "Memo");
            if (is_memo) {
                /* scroll: top_item = first visible LINE; the text is
                 * drawn shifted up by that many rows (per-pixel clip
                 * keeps the window bounds). */
                int sy = (w->top_item > 0 ? w->top_item : 0) * rh;
                int32_t mr[4] = { 4, 2 - sy, W - 4, H - 2 - sy };
                g32_DrawTextW(hdc, w->wtext, -1, mr,
                              0x10 /*DT_WORDBREAK*/ | 0x100 /*DT_NOPREFIX*/);
            } else {
                int32_t tr[4] = { 3, 0, W - 3, H };
                g32_DrawTextA(hdc, w->title, -1, tr, 0x20 | 0x100 | 0x24);
                if (focused) {   /* caret after text */
                    int cx = 3 + w->caret * 8;
                    int32_t cr[4] = { cx, (H - rh) / 2, cx + 1, (H - rh) / 2 + rh };
                    wn_handle cb = g32_CreateSolidBrush(0);
                    g32_FillRect(hdc, cr, cb);
                    wn_handle_close(cb);
                }
            }
            break;
        }
        case CTL_STATIC: {
            uint32_t ss = w->style & 0x1F;
            if (ss == 0x1 /*SS_ICON*/ || ss == 0x3 /*SS_BITMAP*/) {
                /* resource painting handled via STM_SETIMAGE later */
            } else {
                int32_t tr[4] = { 4, 0, W - 4, H };
                /* Windows statics WRAP by default (no DT_SINGLELINE): the
                 * wizard's long instruction labels need their 2nd line.
                 * Top-align: VCENTER would clip BOTH lines when the block
                 * grows taller than the control. */
                uint32_t fmt = 0x10 /*WORDBREAK|LEFT|TOP*/;
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
            /* real 'ScrollBar' controls paint the whole bar; unknown
             * VCL classes (mapped here by ctl_kind_of's fallback) keep
             * the old default face+frame. */
            if (w->cls && wn_strcaseeq(w->cls->name, "ScrollBar")) {
                sb_paint(hdc, w, (w->style & 2 /*SBS_HORZ*/) ? 1 : 0,
                         w->cw, w->ch);
                break;
            }
            /* FALLTHROUGH */
        default:
            if (w->title[0])
                g32_TextOutA(hdc, 4, (H - rh) / 2, w->title, -1);
            break;
        }
        /* window-style adornment bars (Edit/RichEdit/ListBox/...) —
         * painted while the DC is still LIVE (after this comes
         * ReleaseDC; the first placement used the released handle and
         * silently painted nothing). */
        if ((has_v || has_h) && k != CTL_SCROLLBAR) {
            int W2 = w->cw, H2 = w->ch;
            if (has_v)
                sb_paint(hdc, w, 0, W2, has_h ? H2 - WN_SBW : H2);
            if (has_h)
                sb_paint(hdc, w, 1, has_v ? W2 - WN_SBW : W2, H2);
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
        g32_SetTextColor(hdc, 0);
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
    case WN_WM_MOUSEMOVE: {
        /* thumb drag: the captured scrollbar tracks the pointer */
        if (g_capture_hwnd == (uint64_t)(uintptr_t)hwnd_of_window(w) &&
            sb_bar_visible(w, 0)) {
            int my = (int)(int16_t)((uint64_t)lp >> 16);
            int tx, ty, tw, th;
            sb_thumb_rect(w, 0, w->cw, w->ch, &tx, &ty, &tw, &th);
            int tracklo = WN_SBW, trackhi = w->ch - WN_SBW;
            int span = w->sb_max[0] - w->sb_min[0];
            int movable = span > w->sb_page[0]
                            ? span - (w->sb_page[0] - 1) : 1;
            int tl = trackhi - tracklo - th;
            if (tl < 1) tl = 1;
            int rel = my - tracklo - th / 2;
            if (rel < 0) rel = 0;
            if (rel > tl) rel = tl;
            w->sb_pos[0] = w->sb_min[0] +
                            (movable > 1 ? (rel * movable + tl / 2) / tl
                                         : 0);
            sb_clamp(w, 0);
            ctl_repaint(w);
            if (w->parent)
                post_msg(w->parent, WN_WM_VSCROLL,
                         SB_THUMBTRACK |
                         ((uint64_t)w->sb_pos[0] << 16),
                         (int64_t)(uintptr_t)hwnd_of_window(w));
            return 0;
        }
        return 0;
    }
    case WN_WM_LBUTTONUP: {
        if (g_capture_hwnd == (uint64_t)(uintptr_t)hwnd_of_window(w) &&
            sb_bar_visible(w, 0)) {
            u32_ReleaseCapture();
            if (w->parent)
                post_msg(w->parent, WN_WM_VSCROLL,
                         SB_ENDSCROLL, (int64_t)(uintptr_t)
                         hwnd_of_window(w));
            return 0;
        }
        return 0;
    }
    case WN_WM_MOUSEWHEEL: {
        /* wheel: 3 lines per notch (Windows default) */
        int delta = (int)(int16_t)((uint64_t)wp >> 16);
        if (delta) {
            int dir = delta > 0 ? SB_LINEUP : SB_LINEDOWN;
            int steps = (delta > 0 ? delta : -delta) / 40 + 1;
            for (int i = 0; i < steps * 3; i++)
                sb_apply(w, 0, (uint32_t)dir);
            ctl_repaint(w);
            if (w->parent)
                post_msg(w->parent, WN_WM_VSCROLL,
                         SB_THUMBPOSITION |
                         ((uint64_t)w->sb_pos[0] << 16),
                         (int64_t)(uintptr_t)hwnd_of_window(w));
        }
        return 0;
    }
    case WN_WM_VSCROLL:
    case WN_WM_HSCROLL: {
        /* the window scrolls ITSELF (edit/list adornments); scrollbar
         * CONTROL children never reach here (input goes to parent) */
        int bar = msg == WN_WM_VSCROLL ? 0 : 1;
        uint32_t code = (uint32_t)((uint64_t)wp & 0xFFFF);
        if (bar == 0 && k == CTL_EDIT) {
            /* edits scroll by LINES (internal range management) */
            int step = 1;
            if (code == SB_PAGEUP || code == SB_PAGEDOWN)
                step = w->ch > 0 ? w->ch / 16 : 5;
            int dir = (code == SB_LINEUP || code == SB_PAGEUP) ? -1 : 1;
            int before = w->top_item;
            if (code == SB_THUMBPOSITION || code == SB_THUMBTRACK)
                w->top_item = (int)(int16_t)((uint64_t)wp >> 16);
            else
                w->top_item += dir * step;
            if (w->top_item < 0)
                w->top_item = 0;
            w->sb_pos[0] = w->top_item;
            if (w->sb_max[0] > w->sb_min[0])
                sb_clamp(w, 0);
            if (w->top_item != before)
                ctl_repaint(w);
        } else if (bar == 0 && k == CTL_LISTBOX && sb_apply(w, 0, code) >= 0) {
            w->top_item = w->sb_pos[0];
            ctl_repaint(w);
        } else if (sb_apply(w, bar, code) >= 0) {
            ctl_repaint(w);
        }
        return 0;
    }
    case WN_WM_LBUTTONDOWN: {
        {
            /* scrollbar hit-test FIRST (strip of edits/lists/plain
             * windows + whole 'ScrollBar' controls): arrows = line,
             * bands = page, thumb = drag with capture. */
            int mx = (int)(int16_t)((uint64_t)lp & 0xFFFF);
            int my = (int)(int16_t)((uint64_t)lp >> 16);
            int is_sb_ctl = k == CTL_SCROLLBAR && w->cls &&
                            wn_strcaseeq(w->cls->name, "ScrollBar");
            if (is_sb_ctl || sb_bar_visible(w, 0)) {
                int bar = 0;
                int sx, sy, sw, sh;
                if (is_sb_ctl) {
                    sx = 0; sy = 0; sw = w->cw; sh = w->ch;
                    bar = (w->style & 2 /*SBS_HORZ*/) ? 1 : 0;
                    if (bar == 0) { sw = w->cw; }
                } else {
                    sx = w->cw - WN_SBW; sy = 0;
                    sw = WN_SBW; sh = w->ch;
                }
                int inside = mx >= sx && mx < sx + sw &&
                             my >= sy && my < sy + sh;
                if (bar == 1) {
                    sx = 0; sy = w->ch - WN_SBW; sw = w->cw;
                    sh = WN_SBW;
                    inside = mx >= sx && mx < sx + sw &&
                             my >= sy && my < sy + sh;
                }
                if (inside) {
                    int tx, ty, tw, th;
                    int track0 = is_sb_ctl ? 0 : WN_SBW;
                    sb_thumb_rect(w, bar, w->cw, w->ch, &tx, &ty,
                                  &tw, &th);
                    int tracklo, trackhi, poslo;
                    if (bar == 0) {
                        tracklo = (is_sb_ctl ? 0 : WN_SBW);
                        trackhi = w->ch - (is_sb_ctl ? 0 : WN_SBW);
                        poslo = my;
                    } else {
                        tracklo = (is_sb_ctl ? 0 : WN_SBW);
                        trackhi = w->cw - (is_sb_ctl ? 0 : WN_SBW);
                        poslo = mx;
                    }
                    (void)track0;
                    uint32_t code = SB_PAGEUP;
                    int on_thumb = 0;
                    if (bar == 0)
                        on_thumb = my >= ty && my < ty + th;
                    else
                        on_thumb = mx >= tx && mx < tx + tw;
                    if (on_thumb) {
                        /* begin drag: capture + track live */
                        g_capture_hwnd = (uint64_t)(uintptr_t)
                                         hwnd_of_window(w);
                        u32_SetCapture((wn_abiword)g_capture_hwnd);
                        /* trackpos: center the thumb on the pointer */
                        int span = w->sb_max[bar] - w->sb_min[bar];
                        int movable = span > w->sb_page[bar]
                            ? span - (w->sb_page[bar] - 1) : 1;
                        int tl = (bar == 0) ? (trackhi - tracklo - th)
                                             : (trackhi - tracklo - tw);
                        int rel = poslo - tracklo - ((bar == 0) ? th : tw) / 2;
                        if (rel < 0) rel = 0;
                        if (rel > tl) rel = tl;
                        w->sb_pos[bar] = w->sb_min[bar] +
                                         (movable > 1
                                            ? (rel * movable + tl / 2) / tl
                                            : 0);
                        sb_clamp(w, bar);
                        code = SB_THUMBTRACK;
                    } else if (poslo < (bar == 0 ? ty : tx)) {
                        code = SB_PAGEUP;
                    } else {
                        code = SB_PAGEDOWN;
                    }
                    /* arrow zones: first/last WN_SBW of the track */
                    if (!on_thumb) {
                        if (bar == 0) {
                            if (my < WN_SBW)
                                code = SB_LINEUP;
                            else if (my >= w->ch - WN_SBW)
                                code = SB_LINEDOWN;
                        } else {
                            if (mx < WN_SBW)
                                code = SB_LINEUP;
                            else if (mx >= w->cw - WN_SBW)
                                code = SB_LINEDOWN;
                        }
                    }
                    if (sb_apply(w, bar, code) >= 0 || on_thumb) {
                        ctl_repaint(w);
                        if (w->parent)
                            post_msg(w->parent,
                                     bar == 0 ? WN_WM_VSCROLL
                                              : WN_WM_HSCROLL,
                                     code | ((uint64_t)w->sb_pos[bar]
                                              << 16),
                                     (int64_t)(uintptr_t)
                                     hwnd_of_window(w));
                    }
                    return 0;
                }
            }
        }
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
    /* --- edit scrolling (RichEdit viewer contracts) ----------------- */
    case 0x00B6 /*EM_LINESCROLL*/: {
        if (k != CTL_EDIT)
            return 0;
        /* RichEdit semantics: wp = VERTICAL lines, lp = horizontal */
        int lines = (int32_t)(uint32_t)((uint64_t)wp & 0xFFFFFFFF);
        w->top_item += lines;
        if (w->top_item < 0)
            w->top_item = 0;
        w->sb_pos[0] = w->top_item;   /* bar thumb follows the lines */
        if (w->sb_max[0] > w->sb_min[0])
            sb_clamp(w, 0);
        ctl_repaint(w);
        return 1;
    }
    case 0x00B5 /*EM_SCROLL*/: {
        if (k != CTL_EDIT)
            return 0;
        /* line-based (internal) — no external range required */
        uint32_t code = (uint32_t)((uint64_t)wp & 0xFFFF);
        int step = 1;
        if (code == SB_PAGEUP || code == SB_PAGEDOWN)
            step = w->ch > 0 ? w->ch / 16 : 5;
        int dir = (code == SB_LINEUP || code == SB_PAGEUP) ? -1 : 1;
        w->top_item += dir * (code == SB_THUMBPOSITION ||
                              code == SB_THUMBTRACK
                              ? 0 : step);
        if (code == SB_THUMBPOSITION || code == SB_THUMBTRACK)
            w->top_item = (int)(int16_t)((uint64_t)wp >> 16);
        if (w->top_item < 0)
            w->top_item = 0;
        w->sb_pos[0] = w->top_item;
        if (w->sb_max[0] > w->sb_min[0])
            sb_clamp(w, 0);
        ctl_repaint(w);
        return (uint64_t)(uint16_t)w->sb_pos[0];
    }
    case 0x00CE /*EM_GETFIRSTVISIBLELINE*/:
        return (uint64_t)w->top_item;
    /* --- SBM_ (scrollbar CONTROL messages) --------------------------- */
    case SBM_SETPOS:
        w->sb_pos[0] = (int)(uint32_t)((uint64_t)wp);
        sb_clamp(w, 0);
        ctl_repaint(w);
        return (uint64_t)(uint32_t)w->sb_pos[0];
    case SBM_GETPOS:
        return (uint64_t)(uint32_t)w->sb_pos[0];
    case SBM_SETRANGE: {
        /* wp = min, lp = max (16-bit SBM_SETRANGE pairs) */
        int mn = (int)(int16_t)(uint64_t)wp;
        int mx = (int)(int16_t)(uint64_t)lp;
        int old = w->sb_pos[0];
        w->sb_min[0] = mn;
        w->sb_max[0] = mx;
        sb_clamp(w, 0);
        ctl_repaint(w);
        return (uint64_t)(uint32_t)old;   /* previous pos (win16 contract) */
    }
    case SBM_GETRANGE: {
        /* lp = DWORD* pair [min, max] */
        int32_t *out = (int32_t *)(uintptr_t)lp;
        if (out) {
            out[0] = w->sb_min[0];
            out[1] = w->sb_max[0];
        }
        return 1;
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
    case EM_GETLINECOUNT: {
        /* honest line count for multi-line viewers (VCL/Inno's license
         * memo layout queries it; "1" broke page setup) */
        int64_t n = 1;
        for (size_t i = 0; w->wtext[i]; i++)
            if (w->wtext[i] == '\n')
                n++;
        return n;
    }
    case EM_REPLACESEL: {
        ctl_set_text(w, (const char *)(uintptr_t)lp);
        ctl_repaint(w);
        ctl_notify(w, 0x0300 /* EN_CHANGE */);
        return 0;
    }
    case EM_STREAMIN: {
        /* The license viewer's feed: Windows PULLS bytes through the
         * guest's EDITSTREAM callback, in chunks, until it returns
         * *pcb == 0 (or an error code). Buffers must be GUEST-addressable
         * — the 32-bit callback receives them as 32-bit pointers, so they
         * come from the low heap on the x64 host. The 4-arg stdcall shape
         * matches the wndproc bridge exactly (i386 native: direct call). */
        if (k != CTL_EDIT)
            return 0;
        uint32_t flags = (uint32_t)wp;
        /* EDITSTREAM layout is GUEST-ARCH dependent:
         * i386: { u32 cookie; u32 error; u32 pfn } (12 bytes)
         * x64:  { u32 cookie; u32 error; u64 pfn } (16 bytes)
         * 32-bit guests need low-heap buffers so the callback receives
         * real 32-bit pointers; 64-bit guests are called natively. */
        int g32 = u32_guest32();
        uint8_t *chunk = NULL;
        int32_t *pcb = NULL;
        uint64_t cookie = 0, pfn = 0;
        size_t err_off = 0;
        if (g32) {
            uint32_t *es = (uint32_t *)(uintptr_t)lp;
            if (!es || !es[2])
                return 0;
            cookie = es[0];
            pfn = es[2];
            err_off = 4;
            chunk = wn_low_malloc(8192);
            pcb = wn_low_malloc(sizeof(int32_t));
        } else {
            uint32_t *eh = (uint32_t *)(uintptr_t)lp;
            if (!eh || !eh[2])
                return 0;
            cookie = eh[0];
            memcpy(&pfn, (const void *)(lp + 8), sizeof pfn);
            err_off = 4;
            chunk = wn_xmalloc(8192);
            pcb = wn_xmalloc(sizeof(int32_t));
        }
        if (!chunk || !pcb) {
            if (g32) { wn_low_free(chunk); wn_low_free(pcb); }
            else { free(chunk); free(pcb); }
            return 0;
        }
        rtf_buf acc = { NULL, 0, 0 };
        size_t total = 0;
        for (;;) {
            *pcb = 0;
            uint64_t cr;
            if (g32)
                cr = wn_wow64_call_wndproc32(
                    (uint32_t)pfn, (uint32_t)cookie,
                    (uint32_t)(uintptr_t)chunk, 8192,
                    (uint32_t)(uintptr_t)pcb);
            else
                /* x64 guest: Win64 ABI (ms_abi) — a plain host fn-pointer
                 * type would pass args in SysV registers. */
                cr = ((WN_API uint64_t (*)(uint64_t, uint64_t, uint64_t,
                                           uint64_t))
                      (uintptr_t)pfn)(cookie, (uint64_t)(uintptr_t)chunk,
                                     8192, (uint64_t)(uintptr_t)pcb);
            if (cr != 0) {
                /* Windows copies the callback's error into dwError */
                *(uint32_t *)(uintptr_t)(lp + err_off) = (uint32_t)cr;
                break;
            }
            int32_t got = *pcb;
            if (got <= 0)
                break;
            if (total + (size_t)got > (4u << 20))
                break;                      /* runaway stream: cut it off */
            while (acc.n + (size_t)got + 1 >= acc.cap) {
                size_t nc = acc.cap ? acc.cap * 2 : 16384;
                unsigned char *np = wn_xrealloc(acc.p, nc);
                if (!np)
                    break;
                acc.p = np;
                acc.cap = nc;
            }
            if (acc.n + (size_t)got + 1 >= acc.cap)
                break;                      /* OOM: stop cleanly */
            memcpy(acc.p + acc.n, chunk, (size_t)got);
            acc.n += (size_t)got;
            total += (size_t)got;
        }
        if (g32) { wn_low_free(chunk); wn_low_free(pcb); }
        else { free(chunk); free(pcb); }
        /* RichEdits auto-detect content: bytes WITHOUT the {\rtf
         * signature are PLAIN TEXT even when the caller said SF_RTF —
         * Inno streams license.txt under the SF_RTF flag and VCL relies
         * on the control's leniency. The RTF path drops raw CR/LF as
         * "layout only", which glued every paragraph of plain text
         * together ("PUC-Rio.Permission"). */
        int is_rtf = 0;
        if ((flags & WN_SF_RTF) && acc.n >= 5) {
            is_rtf = (acc.p[0] == '{' && acc.p[1] == '\\' &&
                      (acc.p[2] | 0x20) == 'r' &&
                      (acc.p[3] | 0x20) == 't' &&
                      (acc.p[4] | 0x20) == 'f');
        }
        char *text = NULL;
        if (is_rtf) {
            text = rtf_to_text(acc.p ? acc.p : (const unsigned char *)"",
                               acc.p ? acc.n : 0);
        } else {
            /* plain text: CRLF/CR -> LF, then CP1252 -> UTF-8 */
            size_t out_n = 0;
            unsigned char *tmp = wn_xmalloc(acc.n + 1);
            for (size_t q = 0; q < acc.n; q++) {
                unsigned char c = acc.p[q];
                if (c == '\r') {
                    if (q + 1 < acc.n && acc.p[q + 1] == '\n')
                        continue;                    /* CRLF -> LF */
                    tmp[out_n++] = '\n';             /* lone CR -> LF */
                    continue;
                }
                tmp[out_n++] = c;
            }
            text = rtf_cp1252_to_utf8(tmp, out_n);
            free(tmp);
        }
        free(acc.p);
        wn_log(WN_LOG_DEBUG, "user32: EM_STREAMIN(%s) %zu bytes -> %zu chars",
               is_rtf ? "rtf" : "text", total,
               text ? strlen(text) : (size_t)0);
        if (text) {
            ctl_set_text(w, text);
            free(text);
        }
        ctl_repaint(w);
        return (uint64_t)total;
    }
    case LB_INSERTSTRING: {
        char *a = (lp && (wp & 1)) ? wn_utf16_to_utf8((const uint16_t *)(uintptr_t)lp, 4096)
                                   : wn_xstrdup(lp ? (const char *)(uintptr_t)lp : "");
        int idx = ctl_items_insert(w, (int)(int32_t)wp, a);
        free(a);
        ctl_repaint(w);
        return (uint64_t)(idx >= 0 ? idx : -1);
    }
    case LB_SETITEMDATA:
    case CB_SETITEMDATA: {
        int idx = (int)(int32_t)wp;
        if (idx < 0 || idx >= w->n_items)
            return -1;            /* LB_ERR */
        if (ctl_items_reserve(w, w->n_items) != 0)
            return -1;
        w->item_data[idx] = (uint64_t)lp;
        return 0;
    }
    case LB_GETITEMDATA:
    case CB_GETITEMDATA: {
        int idx = (int)(int32_t)wp;
        if (idx < 0 || idx >= w->n_items)
            return -1;            /* LB_ERR */
        return w->item_data ? w->item_data[idx] : 0;
    }
    case LB_SETSEL: {
        /* wParam: select/deselect; lParam: index (-1 = all with wp=1) */
        int idx = (int)(int32_t)(uint32_t)lp;
        if (!w->sel_bits)
            w->sel_bits = wn_xcalloc(w->n_items > 0 ? (size_t)w->n_items : 1, 1);
        if (idx == -1) {
            if (wp)
                memset(w->sel_bits, 1, (size_t)w->n_items);
            else
                memset(w->sel_bits, 0, (size_t)w->n_items);
        } else if (idx >= 0 && idx < w->n_items) {
            w->sel_bits[idx] = (uint8_t)(wp ? 1 : 0);
        }
        ctl_repaint(w);
        return 0;
    }
    case LB_GETSEL: {
        int idx = (int)(int32_t)wp;
        if (idx < 0 || idx >= w->n_items)
            return -1;
        if (!w->sel_bits)
            return idx == w->sel ? 1 : 0;
        return w->sel_bits[idx] ? 1 : 0;
    }
    case LB_GETSELCOUNT: {
        if (!w->sel_bits)
            return (w->sel >= 0) ? 1 : 0;
        int c = 0;
        for (int i = 0; i < w->n_items; i++)
            c += w->sel_bits[i] ? 1 : 0;
        return c;
    }
    case LB_GETSELITEMS: {
        int want = (int)(int32_t)wp;
        uint32_t *out = (uint32_t *)(uintptr_t)lp;
        int n = 0;
        if (!out || want < 0)
            return -1;
        for (int i = 0; i < w->n_items && n < want; i++) {
            int on = w->sel_bits ? w->sel_bits[i] : (i == w->sel);
            if (on)
                out[n++] = (uint32_t)i;
        }
        return n;
    }
    case LB_FINDSTRING: {
        int start = (int)(int32_t)wp;
        char *a = (lp && (wp & 1)) ? wn_utf16_to_utf8((const uint16_t *)(uintptr_t)lp, 256)
                                   : wn_xstrdup(lp ? (const char *)(uintptr_t)lp : "");
        int found = -1;
        for (int fi = 1; fi <= w->n_items; fi++) {
            int i = (start + fi) % w->n_items;
            if (a && w->items[i] &&
                wn_strcaseprefix(w->items[i], a)) {
                found = i;
                break;
            }
        }
        free(a);
        return (uint64_t)(found >= 0 ? found : -1);
    }
    case LB_GETTOPINDEX: return (uint64_t)w->top_item;
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
        if (w->item_data)
            memmove(&w->item_data[idx], &w->item_data[idx + 1],
                    (size_t)(w->n_items - idx - 1) * sizeof(uint64_t));
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
                                   "#32770",
                                   /* riched32/riched20/riched30/msftedit
                                    * register these on Windows DLL load;
                                    * apps never RegisterClass them. */
                                   "RichEdit", "RichEdit20A", "RichEdit20W",
                                   "RichEdit30", "RichEdit50W", NULL };
    for (int i = 0; known[i]; i++) {
        if (!wn_strcaseeq(name, known[i]))
            continue;
        for (int c = 0; c < 32; c++) {
            if (!g_classes[c].used) {
                snprintf(g_classes[c].name, sizeof g_classes[c].name, "%s",
                         known[i]);
                g_classes[c].proc = ctl_proc;
#if defined(__i386__)
                /* Expose the builtin proc to GUESTS. On the native i386
                 * build ctl_proc IS a stdcall (WN_API) function in this
                 * process, so its plain address is a perfectly callable
                 * i386 wndproc — the guest can store it and call it back
                 * through CallWindowProc.
                 *
                 * Field case (LuaForWindows TNewCheckListBox raise "List
                 * item and state item count mismatch"): VCL's CreateSubClass
                 * asks GetClassInfo(HInstance, "LISTBOX") and installs the
                 * returned lpfnWndProc as the proc of its own superclassed
                 * control class; VCL then fetches it AGAIN via
                 * GetWindowLong(GWL_WNDPROC) (FDefWndProc) after
                 * CreateWindowEx and forwards every message it doesn't
                 * handle through CallWindowProc(FDefWndProc). With
                 * lpfnWndProc = 0 VCL rejected the class, registered
                 * 'TNewCheckListBox' with its OWN proc, and the window had
                 * zero listbox semantics: LB_ADDSTRING/LB_GETCOUNT went
                 * into the VCL proc and died, AddItem2's Items.Count-vs-
                 * FStateList.Count sanity check raised on the 2nd item.
                 * (x64/wow64 keeps 0 — a host code pointer is not
                 * expressible to a 32-bit guest there.) */
                g_classes[c].proc32 = (uint32_t)(uintptr_t)ctl_proc;
#endif
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
    extern WN_API uint64_t k32_FindResourceA(wn_abiword, const char *,
                                             const char *);
    extern WN_API void *k32_LockResource(wn_abiword);
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
        extern WN_API uint64_t k32_FindResourceA(wn_abiword, const char *,
                                                 const char *);
        extern WN_API void *k32_LockResource(wn_abiword);
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
    /* Dialog frame: internal strings are HOST copies — pass 0 origs so a
     * 32-bit guest never sees a host pointer inside the CREATESTRUCT. */
    uint64_t hwnd = create_window_core(ex_style, "#32770", title, 0, 0,
                                        style | (force_visible ? 0x10000000u : 0),
                                        dx, dy,
                                        DLG_X(cx), DLG_Y(cy),
                                        parent, 0, hinst, 0);
    if (!hwnd)
        return 0;
    wn_window *dw = win_from_hwnd(hwnd);
    dw->is_dialog = 1;
    dw->dlgproc = dlgproc;
    /* wow64: a 32-bit guest's DLGPROC is a raw i386 address. */
    dw->dlgproc32 = (dlgproc && u32_guest32())
        ? (uint32_t)(uintptr_t)dlgproc : 0;
    if (dw->dlgproc32)
        dw->dlgproc = 0;
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
        create_window_core(iex, class_name, ititle, 0, 0,
                          istyle | WN_WS_CHILD | 0x10000000u /*WS_VISIBLE*/,
                          DLG_X(ix), DLG_Y(iy), DLG_X(icx), DLG_Y(icy),
                          hwnd, iid, hinst, 0);
    }

    /* WM_INITDIALOG -> guest dlgproc */
    if (dlgproc) {
        wn_window *dw_tmp = win_from_hwnd(hwnd);
        if (dw_tmp)
            call_guest_dlgproc(dw_tmp, hwnd, WN_WM_INITDIALOG, 0,
                              (int64_t)param);
        else
            ((void)dlgproc);   /* unreachable: dw exists if hwnd does */
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
    uint64_t hwnd;
    uint32_t message;
    uint64_t wp;
    int64_t lp;
    msg_read(msg, &hwnd, &message, &wp, &lp);
    (void)lp;
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
    if (w && w->cls && (w->cls->proc || w->cls->proc32 ||
                        w->subclass || w->subclass32))
        return (int32_t)call_guest_wndproc(w, c, WN_WM_SETTEXT, 0,
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
    user32_set_wtext_utf8(w, text ? text : "");   /* canonical text too */
    /* Top-level titles live in the WM frame: push them to the backend
     * (VCL sets captions AFTER CreateWindow — without this the wizard's
     * real title never reached the window manager). */
    if (!w->parent) {
        const wn_backend *be = wn_backend_get();
        if (be && be->win_set_title && w->bwin)
            be->win_set_title(w->bwin, w->title);
    }
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

/* IsWindowVisible: the WINDOW's show state (not the WS_VISIBLE bit, not
 * "is an ancestor visible"). A zero-sized popup stays visible=TRUE — the
 * flag is the contract; the X11 backend simply never maps it. */
static WN_API int32_t u32_IsWindowVisible(wn_abiword hwnd)
{
    wn_window *w = win_from_hwnd(hwnd);
    return (w && w->visible) ? 1 : 0;
}

/* --- cursors + icons ------------------------------------------------------------
 * LoadCursor/LoadIcon return handle-backed resources; the standard IDC_/IDI_
 * names draw from built-in pixel art. Exe resource icons load through
 * kernel32's RT_GROUP_ICON/RT_ICON machinery (resource walker). */

typedef struct {
    uint32_t id;             /* numeric resource id or 0 for named */
    int is_icon;             /* 0 = cursor, 1 = icon */
    uint64_t mod_base;       /* owning module image base (0 = builtin art) */
} u32_res;

static wn_handle res_handle(uint32_t id, int is_icon)
{
    u32_res *r = wn_xcalloc(1, sizeof *r);
    r->id = id;
    r->is_icon = is_icon;
    r->mod_base = 0;
    return wn_handle_alloc(WN_HTYPE_GFX, r);
}

static wn_handle res_handle_mod(uint32_t id, int is_icon, uint64_t mod_base)
{
    u32_res *r = wn_xcalloc(1, sizeof *r);
    r->id = id;
    r->is_icon = is_icon;
    r->mod_base = mod_base;
    return wn_handle_alloc(WN_HTYPE_GFX, r);
}

/* Cross-DLL helper (see wn_dll.h): shell32's ExtractIcon/SHGetFileInfo hand
 * out the same handle shape LoadIconA does, so DestroyIcon and the drawing
 * path treat them identically. */
wn_handle wn_icon_handle_alloc(uint32_t id, int is_icon, uint64_t mod_base)
{
    return res_handle_mod(id, is_icon, mod_base);
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
    /* Numeric ids from a module: keep the module so DrawIconEx can walk the
     * real RT_GROUP_ICON/RT_ICON pixels. */
    if (id && (uintptr_t)name < 0x10000 && hinst)
        return res_handle_mod(id, 1, (uint64_t)hinst);
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

/* --- rect init/tests + WindowFromPoint ----------------------------------
 * Inno/VCL initializes TRect with SetRect/SetRectEmpty and probe the cursor
 * with PtInRect/WindowFromPoint while the wizard paints; leaving them as
 * "return 0" stubs handed VCL garbage rects (SetRectEmpty) and a 4-byte
 * stack skew (WindowFromPoint's POINT arrives BY VALUE: 8 bytes on i386
 * stdcall — the stub table's 1-word pop leaked half the frame per call and
 * the next ret jumped to dead stack; field crash: tmp+0x41458b's frame
 * returning to 0x40bdc101 "EXPFTEA" stack junk). POINT-by-value has a
 * per-arch shape: two dword args on i386, ONE packed 8-byte arg in a
 * register under ms_abi (both map to plain integer params here). */
static WN_API int32_t u32_SetRect(void *rect, int32_t l, int32_t t,
                                  int32_t rr, int32_t b)
{
    if (!rect)
        return 0;
    int32_t *r = rect;
    r[0] = l; r[1] = t; r[2] = rr; r[3] = b;
    return 1;
}

static WN_API int32_t u32_SetRectEmpty(void *rect)
{
    if (!rect)
        return 0;
    int32_t *r = rect;
    r[0] = r[1] = r[2] = r[3] = 0;
    return 1;
}

static WN_API int32_t u32_PtInRect(const void *rect
#if !defined(__x86_64__)
                                   , uint32_t px, uint32_t py
#else
                                   , wn_abiword pt_packed
#endif
                                   )
{
    if (!rect)
        return 0;
    int32_t x, y;
#if defined(__x86_64__)
    x = (int32_t)(uint32_t)pt_packed;
    y = (int32_t)(uint32_t)(pt_packed >> 32);
#else
    x = (int32_t)px;
    y = (int32_t)py;
#endif
    const int32_t *r = rect;
    /* Windows contract: left/top inclusive, right/bottom exclusive. */
    return x >= r[0] && x < r[2] && y >= r[1] && y < r[3];
}

/* Deepest visible window under a SCREEN point: same parent-relative
 * descent the mouse path uses (children hold parent-coordinate rects),
 * walking children last-to-first so the newest sibling wins like a
 * proper z-order. Top-levels hold screen coordinates in wx/wy. */
static WN_API wn_abiword u32_WindowFromPoint(
#if !defined(__x86_64__)
                                   uint32_t sx, uint32_t sy
#else
                                   wn_abiword pt_packed
#endif
                                   )
{
    int32_t x, y;
#if defined(__x86_64__)
    x = (int32_t)(uint32_t)pt_packed;
    y = (int32_t)(uint32_t)(pt_packed >> 32);
#else
    x = (int32_t)sx;
    y = (int32_t)sy;
#endif
    if (ensure_gui() != 0)
        return 0;

    uint64_t target = 0;
    wn_window *top = NULL;
    for (int i = g_hwnd_count - 1; i >= 0; i--) {
        wn_window *w = g_hwnds[i].win;
        if (!w || w->parent || !w->visible || w->in_destroy)
            continue;
        if (x >= w->wx && y >= w->wy &&
            x < w->wx + w->cw && y < w->wy + w->ch) {
            target = (uint64_t)(uintptr_t)g_hwnds[i].h;
            top = w;
            break;
        }
    }
    if (!target || !top)
        return 0;

    /* Children hold PARENT-relative coords: translate the screen point
     * into the top-level's frame first, then keep translating on each
     * descent (same as the mouse event path). */
    int mx = x - top->wx, my = y - top->wy;
    for (int depth = 0; depth < 16; depth++) {
        uint64_t next = 0;
        int nx = 0, ny = 0;
        for (int i = g_hwnd_count - 1; i >= 0; i--) {
            wn_window *c = g_hwnds[i].win;
            if (!c || c->parent != target || !c->visible ||
                c->in_destroy ||
                (c->style & 0x08000000u /*WS_DISABLED*/))
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
    return target;
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

/* --- scroll APIs -------------------------------------------------------- *
 * SCROLLINFO (guest layout, all DWORDs — arch-independent):
 *   cbSize@0 fMask@4 nMin@8 nMax@12 nPage@16 nPos@20 nTrackPos@24. */
#define SB_VERT 0
#define SB_HORZ 1
#define SB_CTL  2

static wn_window *sb_of(wn_abiword hwnd, int code, int *bar)
{
    wn_window *w = hwnd ? win_from_hwnd((uint64_t)hwnd) : NULL;
    if (!w)
        return NULL;
    /* SB_CTL: the window itself is a scrollbar control */
    if (bar)
        *bar = code == SB_CTL ? ((w->style & 2 /*SBS_HORZ*/) ? 1 : 0)
                              : (code == SB_HORZ ? 1 : 0);
    return w;
}

static WN_API int32_t u32_SetScrollInfo(wn_abiword hwnd, int32_t code,
                                        const void *info, int32_t redraw)
{
    int bar;
    wn_window *w = sb_of(hwnd, code, &bar);
    if (!w || !info)
        return 0;
    const uint32_t *si = info;
    uint32_t mask = si[1];                    /* fMask */
    if (mask & SIF_RANGE) {
        w->sb_min[bar] = (int)si[2];
        w->sb_max[bar] = (int)si[3];
    }
    if (mask & SIF_PAGE)
        w->sb_page[bar] = (int)si[4];
    if (mask & SIF_POS)
        w->sb_pos[bar] = (int)si[5];
    sb_clamp(w, bar);
    if (mask & 0x1 /*SIF_RANGE*/)
        w->sb_on[bar] = 1;                    /* managed: show the bar */
    if (redraw)
        ctl_repaint(w);
    wn_last_error_set(0);
    return (int32_t)w->sb_pos[bar];
}

static WN_API int32_t u32_GetScrollInfo(wn_abiword hwnd, int32_t code,
                                        void *info)
{
    int bar;
    wn_window *w = sb_of(hwnd, code, &bar);
    if (!w || !info)
        return 0;
    uint32_t *si = info;
    if (si[0] < 28)                           /* cbSize sanity */
        return 0;
    uint32_t mask = si[1];
    if (mask & SIF_RANGE) {
        si[2] = (uint32_t)w->sb_min[bar];
        si[3] = (uint32_t)w->sb_max[bar];
    }
    if (mask & SIF_PAGE)
        si[4] = (uint32_t)w->sb_page[bar];
    if (mask & SIF_POS) {
        si[5] = (uint32_t)w->sb_pos[bar];
        si[6] = (uint32_t)w->sb_pos[bar];    /* nTrackPos */
    }
    return 1;
}

static WN_API int32_t u32_SetScrollPos(wn_abiword hwnd, int32_t code,
                                       int32_t pos, int32_t redraw)
{
    int bar;
    wn_window *w = sb_of(hwnd, code, &bar);
    if (!w)
        return 0;
    int old = w->sb_pos[bar];
    w->sb_pos[bar] = pos;
    sb_clamp(w, bar);
    if (redraw)
        ctl_repaint(w);
    return old;
}

static WN_API int32_t u32_GetScrollPos(wn_abiword hwnd, int32_t code)
{
    int bar;
    wn_window *w = sb_of(hwnd, code, &bar);
    return w ? w->sb_pos[bar] : 0;
}

static WN_API int32_t u32_SetScrollRange(wn_abiword hwnd, int32_t code,
                                        int32_t mn, int32_t mx,
                                        int32_t redraw)
{
    int bar;
    wn_window *w = sb_of(hwnd, code, &bar);
    if (!w)
        return 0;
    w->sb_min[bar] = mn;
    w->sb_max[bar] = mx;
    sb_clamp(w, bar);
    if (redraw)
        ctl_repaint(w);
    return 1;
}

static WN_API int32_t u32_GetScrollRange(wn_abiword hwnd, int32_t code,
                                        int32_t *mn, int32_t *mx)
{
    int bar;
    wn_window *w = sb_of(hwnd, code, &bar);
    if (!w)
        return 0;
    if (mn)
        *mn = w->sb_min[bar];
    if (mx)
        *mx = w->sb_max[bar];
    return 1;
}

static WN_API int32_t u32_ShowScrollBar(wn_abiword hwnd, int32_t code,
                                        int32_t show)
{
    int bar;
    wn_window *w = sb_of(hwnd, code, &bar);
    if (!w)
        return 0;
    if (show) {
        w->style |= (bar == 0 ? 0x00200000u : 0x00100000u);
        w->sb_on[bar] = 1;
    } else {
        w->style &= ~(bar == 0 ? 0x00200000u : 0x00100000u);
        w->sb_on[bar] = 0;
    }
    ctl_repaint(w);
    return 1;
}

static WN_API int32_t u32_EnableScrollBar(wn_abiword hwnd, int32_t code,
                                          uint32_t arrows)
{
    (void)code;
    (void)arrows;
    wn_window *w = hwnd ? win_from_hwnd((uint64_t)hwnd) : NULL;
    return w ? 1 : 0;      /* v1: always enabled (ESB_ENABLE_BOTH) */
}

/* --- key state / window identity / enumeration ------------------------ */

/* GetKeyState(vk) -> SHORT: high byte = DOWN now, low byte = toggled
 * (Caps/Num/Scroll/Insert flip on each press). Real state: the X11
 * backend feeds every key event and reconciles modifier masks. */
static WN_API int16_t u32_GetKeyState(int32_t vk)
{
    if (vk < 0 || vk > 255)
        return 0;
    short r = 0;
    if (g_key_state[vk / 8] & (1u << (vk % 8)))
        r = (short)(int16_t)0xFF00u;    /* down: high bit set (0x8000) */
    if (vk_is_toggle((uint32_t)vk) &&
        (g_key_toggle[vk / 8] & (1u << (vk % 8))))
        r |= 1;
    wn_last_error_set(0);
    return r;
}

/* GetAsyncKeyState(vk) -> SHORT: 0x8000 = down at call time, bit0 =
 * pressed at least once since the LAST GetAsyncKeyState for that key. */
static WN_API int16_t u32_GetAsyncKeyState(int32_t vk)
{
    if (vk < 0 || vk > 255)
        return 0;
    short r = 0;
    if (g_key_state[vk / 8] & (1u << (vk % 8)))
        r = (short)(int16_t)0xFF00u;
    if (g_key_async_edge[vk / 8] & (1u << (vk % 8))) {
        r |= 1;
        g_key_async_edge[vk / 8] &= (uint8_t)~(1u << (vk % 8));
    }
    wn_last_error_set(0);
    return r;
}

/* GetWindowThreadProcessId: return the owning thread id (the GUI
 * thread), write the process id to the optional out slot (caller-width
 * DWORD; the in-process guest's 4-byte slot must not be widened). */
static WN_API uint32_t u32_GetWindowThreadProcessId(wn_abiword hwnd,
                                                    uint32_t *pid_out)
{
    wn_window *w = hwnd ? win_from_hwnd((uint64_t)hwnd) : NULL;
    uint32_t pid = (uint32_t)getpid();
    if (pid_out)
        *pid_out = pid;
    if (!hwnd)
        return 0;
    if (!w)
        return 0;               /* stale handle: no thread, pid written */
    /* single-GUI-thread model: the thread that owns every window */
    wn_last_error_set(0);
    return (uint32_t)getpid();  /* thread id == pid in the host model;
                                 * guests compare against
                                 * GetCurrentThreadId() which equals it */
}

/* Guest ENUM callback (2-arg stdcall: hwnd, lParam) through the wow64
 * bridge. The 4-arg bridge is safe for narrower callees: the guest pops
 * its own 8 bytes and the bridge resyncs esp from the return state. */
static int call_guest_enum_cb(uint64_t proc, uint64_t hwnd, uint64_t lp)
{
    if (!proc)
        return 0;
    if (u32_guest32())
        return wn_wow64_call_wndproc32((uint32_t)(uint64_t)proc,
                                       (uint32_t)hwnd, (uint32_t)lp, 0, 0)
               ? 1 : 0;
    typedef WN_API wn_abiword (*cb2)(wn_abiword, wn_abiword_s);
    return ((cb2)(uintptr_t)proc)((wn_abiword)hwnd, (wn_abiword_s)lp) ? 1 : 0;
}

/* EnumWindows / EnumThreadWindows: walk the live window registry.
 * v1 thread model: every window belongs to the single GUI thread, so
 * tid == current thread matches all top-level windows (the Windows
 * contract for the caller's own thread), other tids see none. */
static WN_API int32_t enum_windows_common(uint32_t tid, wn_abiword proc,
                                          wn_abiword lp, int top_only)
{
    if (!proc)
        return 0;
    uint32_t cur = (uint32_t)getpid();   /* GUI-thread id (host model) */
    if (tid && tid != cur)
        return 1;   /* nothing owned by that thread — success, zero enum */
    /* snapshot first: the callback may create/destroy windows */
    uint64_t list[WN_USER32_MAX_WINDOWS];
    int n = 0;
    for (int i = 0; i < g_hwnd_count && n < WN_USER32_MAX_WINDOWS; i++) {
        wn_window *w = g_hwnds[i].win;
        if (!w || w->in_destroy)
            continue;
        if (top_only && w->parent)
            continue;
        list[n++] = (uint64_t)(uintptr_t)g_hwnds[i].h;
    }
    for (int i = 0; i < n; i++) {
        if (!call_guest_enum_cb((uint64_t)proc, list[i], (uint64_t)lp))
            return 0;              /* callback asked to stop */
    }
    wn_last_error_set(0);
    return 1;
}

static WN_API int32_t u32_EnumWindows(wn_abiword proc, wn_abiword lp)
{
    return enum_windows_common(0, proc, lp, 1);
}

static WN_API int32_t u32_EnumThreadWindows(uint32_t tid, wn_abiword proc,
                                           wn_abiword lp)
{
    return enum_windows_common(tid, proc, lp, 1);
}

static WN_API int32_t u32_GetKeyboardType(int32_t kind)
{
    switch (kind) {
    case 0: return 4;    /* KT-enhanced */
    case 1: return 12;   /* IBM PC-AT 102-key */
    case 2: return 0;    /* no subtypes */
    default: return 2;   /* function keys count */
    }
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
    /* Windows returns the FULL text length (the window may carry a
     * multi-line payload in wtext, not the 127-char title mirror). */
    size_t n = 0;
    while (w->wtext[n])
        n++;
    return (int32_t)n;
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

static WN_API int32_t u32_MessageBoxIndirectW(const void *params)
{
    /* MessageBoxIndirectW(CONST MSGBOXPARAMSW*) - ONE parameter; the owner
     * window lives INSIDE the struct (hwndOwner@8), not on the stack. */
    const uint8_t *p = params;
    wn_abiword hwnd = params
        ? *(wn_abiword *)(const void *)(p + 0x8) : 0;
    const uint16_t *text = params ? *(const uint16_t **)(const void *)(p + 0x18) : NULL;
    const uint16_t *cap = params ? *(const uint16_t **)(const void *)(p + 0x20) : NULL;
    return u32_MessageBoxW(hwnd, text, cap,
                           params ? *(const uint32_t *)(const void *)(p + 0x28) : 0);
}

static WN_API int32_t u32_MessageBoxIndirectA(const void *params)
{
    /* MSGBOXPARAMSA: same layout as W, char* text/caption. Delphi's
     * VCL dialogs (Application.MessageBox path) use the A form. */
    const uint8_t *p = params;
    wn_abiword hwnd = params
        ? *(wn_abiword *)(const void *)(p + 0x8) : 0;
    const char *text = params ? *(const char **)(const void *)(p + 0x18) : NULL;
    const char *cap = params ? *(const char **)(const void *)(p + 0x20) : NULL;
    return u32_MessageBoxA(hwnd, text, cap,
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

static WN_API wn_handle u32_LoadBitmapA(wn_abiword hinst, const char *name);

static WN_API wn_handle u32_LoadImageA(wn_abiword hinst, const char *name,
                                       uint32_t type, int32_t cx, int32_t cy,
                                       uint32_t load)
{
    (void)cx; (void)cy; (void)load;
    if (type == 1 /*IMAGE_ICON*/)
        return u32_LoadIconA(hinst, name);
    if (type == 0 /*IMAGE_BITMAP*/)
        return u32_LoadBitmapA(hinst, name);
    wn_log(WN_LOG_WARN, "user32: LoadImageA(type=%u '%s') bitmaps not "
           "supported yet", type, (name && (uintptr_t)name >= 0x10000) ? name : "#int");
    return (wn_handle)0;
}

/* LoadBitmapA: MAKEINTRESOURCE ids are the OBM_* system bitmaps (same
 * 13x13 placeholder art — documented gap); named resources are RT_BITMAP
 * DIBs walked out of the caller's module — the Inno engine loads its
 * wizard imagery ('MAINIMAGE', 'STOPIMAGE', ...) that way. */
static WN_API wn_handle u32_LoadBitmapA(wn_abiword hinst, const char *name)
{
    if ((uintptr_t)name < 0x10000) {
        uint32_t id = (uint32_t)(uintptr_t)name;
        (void)id;   /* OBM_* ids all get the same 13x13 placeholder */
        return (wn_handle)(uintptr_t)wn_bitmap_handle_alloc(13, 13);
    }
    if (!name || !*name)
        return (wn_handle)0;
    const uint8_t *dib = NULL;
    uint32_t dsz = 0;
    if (wn_res_lookup_bytes((uint64_t)hinst, (const char *)(uintptr_t)2
                            /* RT_BITMAP */, name, &dib, &dsz)) {
        wn_handle h = wn_gdi_bitmap_from_dib(dib, dsz);
        if (h)
            return h;
        return (wn_handle)0;   /* unsupported DIB: honest failure (logged) */
    }
    wn_log(WN_LOG_WARN, "user32: LoadBitmapA('%s'): bitmap resource not "
           "found", name);
    return (wn_handle)0;
}

/* --- menus --------------------------------------------------------------------
 * Real menu objects: VCL's TMainMenu/TApplication path builds a menu with
 * CreateMenu+AppendMenu and every stubbed return made Inno abort the wizard
 * (the "Error creating window" teardown). Handles are WN_HTYPE_GFX objects
 * like every other user32 thing that must survive wn_handle_close paths. */

typedef struct {
    int      kind;        /* 0 = item, 1 = separator, 2 = popup */
    uint32_t id;          /* command id (or SC_* for system menus) */
    uint32_t flags;
    int      enabled;
    int      checked;
    wn_handle submenu;   /* popup */
    char     text[80];
} u32_menu_item;

typedef struct {
    u32_menu_item *items;
    int count, cap;
    int is_sysmenu;
} u32_menu;

static wn_handle menu_alloc(int is_sysmenu)
{
    u32_menu *m = wn_xcalloc(1, sizeof *m);
    m->is_sysmenu = is_sysmenu;
    return wn_handle_alloc(WN_HTYPE_GFX, m);
}

static u32_menu *menu_get(wn_handle h)
{
    wn_object *o = wn_handle_get(h, WN_HTYPE_GFX);
    if (!o || !o->ptr)
        return NULL;
    return o->ptr;    /* menu objects live in the GFX pool like the rest */
}

static WN_API wn_handle u32_CreateMenu(void)
{
    return menu_alloc(0);
}

static WN_API wn_handle u32_CreatePopupMenu(void)
{
    return menu_alloc(0);
}

static WN_API int32_t u32_DestroyMenu(wn_handle h)
{
    u32_menu *m = menu_get(h);
    if (!m)
        return 0;
    /* popups are owned: kill them with the parent (Windows semantics) */
    for (int i = 0; i < m->count; i++)
        if (m->items[i].kind == 2 && m->items[i].submenu)
            u32_DestroyMenu(m->items[i].submenu);
    free(m->items);
    wn_handle_close(h);
    return 1;
}

static int menu_item_push(u32_menu *m, const u32_menu_item *it)
{
    if (m->count == m->cap) {
        int ncap = m->cap ? m->cap * 2 : 16;
        u32_menu_item *ni = realloc(m->items, (size_t)ncap * sizeof *ni);
        if (!ni)
            return 0;
        m->items = ni;
        m->cap = ncap;
    }
    m->items[m->count++] = *it;
    return 1;
}

/* MF_ flags (winuser.h) */
#define MF_BYCOMMAND_ 0x0000
#define MF_GRAYED_    0x0001
#define MF_DISABLED_  0x0002
#define MF_POPUP_     0x0010
#define MF_SEPARATOR_ 0x0800
#define MF_BYPOSITION_ 0x0400

static int menu_append_core(wn_handle hmenu, uint32_t flags, uint32_t id,
                            const char *text)
{
    u32_menu *m = menu_get(hmenu);
    if (!m) {
        wn_last_error_set(WN_ERR_INVALID_HANDLE);
        return 0;
    }
    u32_menu_item it = { 0 };
    if (flags & MF_SEPARATOR_) {
        it.kind = 1;
    } else if (flags & MF_POPUP_) {
        it.kind = 2;
        it.submenu = (wn_handle)(uintptr_t)id;  /* uIDNewItem carries the submenu handle */
        if (text)
            snprintf(it.text, sizeof it.text, "%s", text);
    } else {
        it.kind = 0;
        it.id = id;
        if (text)
            snprintf(it.text, sizeof it.text, "%s", text);
    }
    it.flags = flags;
    it.enabled = !(flags & (MF_GRAYED_ | MF_DISABLED_));
    if (!menu_item_push(m, &it))
        return 0;
    return 1;
}

static WN_API int32_t u32_AppendMenuA(wn_handle hmenu, uint32_t flags,
                                      wn_abiword id_or_sub, const char *text)
{
    /* MF_BITMAP/MF_OWNERDRAW items: keep the raw payload, no pixels yet. */
    if (flags & 0x0004 /*MF_BITMAP*/) {
        wn_log(WN_LOG_DEBUG, "user32: AppendMenuA MF_BITMAP item (no "
               "pixels yet)");
        flags &= ~0x0004u;
    }
    return menu_append_core(hmenu, flags, (uint32_t)id_or_sub, text);
}

static WN_API int32_t u32_AppendMenuW(wn_handle hmenu, uint32_t flags,
                                      wn_abiword id_or_sub,
                                      const uint16_t *text)
{
    char *a = (text && (uintptr_t)text >= 0x10000)
              ? wn_utf16_to_utf8(text, 80) : NULL;
    int32_t r = menu_append_core(hmenu, flags, (uint32_t)id_or_sub, a);
    free(a);
    return r;
}

static int menu_find(u32_menu *m, uint32_t what, uint32_t flags, int *idx)
{
    if (flags & MF_BYPOSITION_) {
        if ((int)what >= m->count)
            return 0;
        *idx = (int)what;
        return 1;
    }
    for (int i = 0; i < m->count; i++)
        if (m->items[i].kind != 1 && m->items[i].id == what) {
            *idx = i;
            return 1;
        }
    return 0;
}

static WN_API int32_t u32_DeleteMenu(wn_handle hmenu, uint32_t what,
                                     uint32_t flags)
{
    u32_menu *m = menu_get(hmenu);
    int idx;
    if (!m || !menu_find(m, what, flags, &idx)) {
        wn_last_error_set(WN_ERR_INVALID_HANDLE);
        return 0;
    }
    if (m->items[idx].kind == 2 && m->items[idx].submenu)
        u32_DestroyMenu(m->items[idx].submenu);
    memmove(&m->items[idx], &m->items[idx + 1],
            (size_t)(m->count - idx - 1) * sizeof *m->items);
    m->count--;
    return 1;
}

static WN_API int32_t u32_RemoveMenu(wn_handle hmenu, uint32_t what,
                                     uint32_t flags)
{
    u32_menu *m = menu_get(hmenu);
    int idx;
    if (!m || !menu_find(m, what, flags, &idx)) {
        wn_last_error_set(WN_ERR_INVALID_HANDLE);
        return 0;
    }
    memmove(&m->items[idx], &m->items[idx + 1],
            (size_t)(m->count - idx - 1) * sizeof *m->items);
    m->count--;
    return 1;
}

static WN_API int32_t u32_EnableMenuItem(wn_handle hmenu, uint32_t what,
                                         uint32_t flags)
{
    u32_menu *m = menu_get(hmenu);
    int idx;
    if (!m || !menu_find(m, what, flags, &idx))
        return (uint32_t)-1;
    int was = m->items[idx].enabled ? 0 /*MF_ENABLED*/ : (MF_GRAYED_ | 1);
    if (flags & (MF_GRAYED_ | MF_DISABLED_))
        m->items[idx].enabled = 0;
    else if (flags & 0x0000 /*MF_ENABLED via not-disabled*/)
        m->items[idx].enabled = 1;
    return was;
}

static WN_API int32_t u32_GetMenuItemCount(wn_handle hmenu)
{
    u32_menu *m = menu_get(hmenu);
    return m ? m->count : (int32_t)-1;
}

static WN_API wn_abiword u32_GetMenuItemID(wn_handle hmenu, int32_t pos)
{
    u32_menu *m = menu_get(hmenu);
    if (!m || pos < 0 || pos >= m->count)
        return (wn_abiword)(uint32_t)-1;
    if (m->items[pos].kind == 1)
        return 0;                    /* separator */
    if (m->items[pos].kind == 2)
        return (wn_abiword)(uint32_t)-1; /* popup */
    return (wn_abiword)m->items[pos].id;
}

/* hwnd -> attached menu + per-window system menu. Bounded parallel tables
 * (the window objects live in a private struct we don't own here). */
static struct { uint64_t hwnd; wn_handle menu; wn_handle sysmenu; } g_win_menus[WN_USER32_MAX_WINDOWS];

static int menu_slot_of(uint64_t hwnd)
{
    for (int i = 0; i < WN_USER32_MAX_WINDOWS; i++)
        if (g_win_menus[i].hwnd == hwnd)
            return i;
    return -1;
}

static int menu_slot_alloc(uint64_t hwnd)
{
    int i = menu_slot_of(hwnd);
    if (i >= 0)
        return i;
    for (i = 0; i < WN_USER32_MAX_WINDOWS; i++)
        if (!g_win_menus[i].hwnd) {
            g_win_menus[i].hwnd = hwnd;
            return i;
        }
    return -1;
}

static WN_API int32_t u32_SetMenu(wn_abiword hwnd, wn_handle hmenu)
{
    if (hmenu && !menu_get(hmenu))
        return 0;
    int i = menu_slot_alloc(hwnd);
    if (i < 0)
        return 0;
    g_win_menus[i].menu = hmenu;
    return 1;
}

static WN_API wn_handle u32_GetMenu(wn_abiword hwnd)
{
    int i = menu_slot_of(hwnd);
    return (i >= 0) ? g_win_menus[i].menu : (wn_handle)0;
}

static WN_API wn_handle u32_GetSystemMenu(wn_abiword hwnd, wn_abiword revert)
{
    int i = menu_slot_alloc(hwnd);
    if (i < 0)
        return (wn_handle)0;
    if (revert) {
        /* TRUE = reset back to the default system menu */
        if (g_win_menus[i].sysmenu)
            u32_DestroyMenu(g_win_menus[i].sysmenu);
        g_win_menus[i].sysmenu = (wn_handle)0;
    }
    if (!g_win_menus[i].sysmenu) {
        wn_handle h = menu_alloc(1);
        u32_menu *m = menu_get(h);
        struct { const char *txt; uint32_t id; uint32_t fl; } defs[] = {
            { "&Restore",  0xF120 /*SC_RESTORE*/,  0x0000 },
            { "&Move",     0xF010 /*SC_MOVE*/,     0x0000 },
            { "&Size",     0xF000 /*SC_SIZE*/,      0x0000 },
            { "Mi&nimize", 0xF020 /*SC_MINIMIZE*/, 0x0000 },
            { "Ma&ximize", 0xF030 /*SC_MAXIMIZE*/, 0x0000 },
            { "",          0,                      MF_SEPARATOR_ },
            { "&Close",    0xF060 /*SC_CLOSE*/,    0x0000 },
        };
        for (size_t k = 0; k < sizeof defs / sizeof defs[0]; k++) {
            u32_menu_item it = { 0 };
            if (defs[k].fl & MF_SEPARATOR_) {
                it.kind = 1;
            } else {
                it.kind = 0;
                it.id = defs[k].id;
                snprintf(it.text, sizeof it.text, "%s", defs[k].txt);
            }
            it.flags = defs[k].fl;
            it.enabled = 1;
            menu_item_push(m, &it);
        }
        g_win_menus[i].sysmenu = h;
    }
    return g_win_menus[i].sysmenu;
}

static WN_API int32_t u32_DrawMenuBar(wn_abiword hwnd)
{
    (void)hwnd;   /* the X backend paints no native menu bars yet */
    return 1;
}

static WN_API int32_t u32_GetMenuState(wn_handle hmenu, uint32_t what,
                                       uint32_t flags)
{
    u32_menu *m = menu_get(hmenu);
    int idx;
    if (!m || !menu_find(m, what, flags, &idx))
        return (uint32_t)-1;
    u32_menu_item *it = &m->items[idx];
    if (it->kind == 1)
        return MF_SEPARATOR_;
    uint32_t st = 0;
    if (!it->enabled)
        st |= MF_GRAYED_ | MF_DISABLED_;
    if (it->checked)
        st |= 0x0008 /*MF_CHECKED*/;
    return (int32_t)st;
}

/* --- window properties ---------------------------------------------------------
 * VCL stores its ControlOfs map on every windowed control via SetProp(atom);
 * stubs returning 0 made the property set silently absent. Keys compare raw
 * (VCL uses int atoms; string-keyed props match by pointer — documented). */
typedef struct u32_prop {
    uint64_t key;
    uint64_t data;
    struct u32_prop *next;
} u32_prop;

static u32_prop *g_props[WN_USER32_MAX_WINDOWS * 2];

static uint32_t prop_slot(uint64_t hwnd)
{
    uint64_t h = (uint64_t)(uintptr_t)hwnd;
    return (uint32_t)((h >> 3) * 2654435761u %
                      (WN_USER32_MAX_WINDOWS * 2));
}

static WN_API int32_t u32_SetPropA(wn_abiword hwnd, wn_abiword key,
                                   wn_abiword data)
{
    if (!win_from_hwnd(hwnd)) {
        wn_last_error_set(WN_ERR_INVALID_HANDLE);
        return 0;
    }
    uint32_t sp = prop_slot(hwnd);
    for (u32_prop *p = g_props[sp]; p; p = p->next)
        if (p->key == (uint64_t)key) {
            p->data = data;
            return 1;
        }
    u32_prop *p = wn_xcalloc(1, sizeof *p);
    p->key = key;
    p->data = data;
    p->next = g_props[sp];
    g_props[sp] = p;
    return 1;
}

static WN_API wn_abiword u32_GetPropA(wn_abiword hwnd, wn_abiword key)
{
    uint32_t sp = prop_slot(hwnd);
    for (u32_prop *p = g_props[sp]; p; p = p->next)
        if (p->key == (uint64_t)key)
            return p->data;
    return 0;
}

static WN_API wn_abiword u32_RemovePropA(wn_abiword hwnd, wn_abiword key)
{
    uint32_t sp = prop_slot(hwnd);
    u32_prop **pp = &g_props[sp];
    for (u32_prop *p = g_props[sp]; p; pp = &p->next, p = p->next)
        if (p->key == (uint64_t)key) {
            *pp = p->next;
            uint64_t d = p->data;
            free(p);
            return d;
        }
    return 0;
}

/* scroll state: per-window sb_* fields (wn_window) since the
 * scrollbar rework; the old global-slot table was removed. */

static WN_API wn_abiword_s u32_SendNotifyMessageA(wn_abiword hwnd,
                                                  uint32_t msg,
                                                  wn_abiword wp,
                                                  wn_abiword_s lp)
{
    return u32_SendMessageA(hwnd, msg, wp, lp);
}

/* IsRectEmpty: a RECT is 4 LONGs (32-bit in every guest word size); TRUE
 * when the rectangle has no area (right<=left or bottom<=top). */
static WN_API int32_t u32_IsRectEmpty(const void *rect)
{
    if (!rect)
        return 1;
    const int32_t *r = rect;
    return (r[2] <= r[0] || r[3] <= r[1]) ? 1 : 0;
}

static WN_API int32_t u32_DestroyIcon(wn_handle icon)
{
    if (!icon)
        return 0;
    wn_handle_close(icon);
    return 1;
}

/* --- icon drawing ------------------------------------------------------------------
 * Module icons carry their owning image (ExtractIconA/LoadIconA(hinst,#n));
 * DrawIconEx walks the module's RT_GROUP_ICON, picks the entry closest to
 * the requested size, and blits the real RT_ICON DIB pixels through gdi32.
 * Builtin IDI_* pixel art is still pending (documented gap): those draws
 * succeed without painting — callers check the return value, not pixels. */

#define U32_RT_ICON       ((const char *)(uintptr_t)3)
#define U32_RT_GROUP_ICON ((const char *)(uintptr_t)14)

static int draw_icon_pixels(wn_handle hdc, uint64_t mod_base, uint32_t group_id,
                            int x, int y, int cx, int cy)
{
    const uint8_t *grp = NULL;
    uint32_t gsz = 0;
    if (!mod_base || !group_id ||
        !wn_res_lookup_bytes(mod_base, U32_RT_GROUP_ICON,
                             (const char *)(uintptr_t)group_id, &grp, &gsz) ||
        gsz < 6)
        return 0;
    uint16_t count;
    memcpy(&count, grp + 4, 2);   /* NEWHEADER: Res@0(2)=0, Type@2(2)=1, Count@4 */
    if (!count || gsz < 6 + (uint32_t)count * 14)
        return 0;
    /* GRPICONENTRY[14]: bWidth@0, bHeight@1, ..., nID@12. Pick the entry
     * closest to (cx,cy); 0 means 256. */
    int best = 0;
    long best_score = 0x7FFFFFFFL;
    for (int i = 0; i < count; i++) {
        const uint8_t *e = grp + 6 + (size_t)i * 14;
        int ew = e[0] ? e[0] : 256;
        int eh = e[1] ? e[1] : 256;
        long score = (long)(ew - cx) * (ew - cx) + (long)(eh - cy) * (eh - cy);
        if (score < best_score) {
            best_score = score;
            best = i;
        }
    }
    uint32_t icon_id;
    memcpy(&icon_id, grp + 6 + (size_t)best * 14 + 12, 4);
    const uint8_t *dib = NULL;
    uint32_t dsz = 0;
    if (!wn_res_lookup_bytes(mod_base, U32_RT_ICON,
                             (const char *)(uintptr_t)icon_id, &dib, &dsz))
        return 0;
    return wn_gdi_draw_dib(hdc, x, y, cx, cy, dib, dsz);
}

static WN_API int32_t u32_DrawIconEx(wn_handle hdc, int32_t x, int32_t y,
                                     wn_handle icon, int32_t cx, int32_t cy,
                                     uint32_t istep, wn_abiword hbr,
                                     uint32_t flags)
{
    (void)istep; (void)hbr; (void)flags;   /* flicker-free draw, steps: later */
    wn_object *o = wn_handle_get(icon, WN_HTYPE_GFX);
    if (!o || !o->ptr) {
        wn_last_error_set(WN_ERR_INVALID_HANDLE);
        return 0;
    }
    u32_res *r = o->ptr;
    int w = cx > 0 ? cx : 32;
    int h = cy > 0 ? cy : 32;
    if (r->is_icon && r->mod_base) {
        if (draw_icon_pixels(hdc, r->mod_base, r->id, x, y, w, h))
            return 1;
        wn_log(WN_LOG_DEBUG, "user32: DrawIconEx module icon %u: pixel "
               "walk failed", r->id);
        return 1;
    }
    wn_log(WN_LOG_DEBUG, "user32: DrawIconEx builtin icon id=%u: art "
           "pending — no-op success", r->id);
    return 1;
}

static WN_API int32_t u32_DrawIcon(wn_handle hdc, int32_t x, int32_t y,
                                   wn_handle icon)
{
    return u32_DrawIconEx(hdc, x, y, icon, 32, 32, 0, 0, 0);
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
                                                     const void *hs_raw,
                                                     uint32_t wait_all,
                                                     uint32_t ms,
                                                     uint32_t wake_mask)
{
    (void)wait_all; (void)wake_mask;
    uint64_t t0 = wn_monotonic_ns() / 1000000;
    /* Handle arrays are DWORD-sized for 32-bit callers (the Inno parent
     * hung forever waiting for a child that had already died: 64-bit reads
     * of its 32-bit handle array never matched the child's handle). */
    wn_handle hs[64];
    if (count > 64)
        count = 64;
    if (wn_wow64_guest32()) {
        const uint32_t *p = hs_raw;
        for (uint32_t i = 0; i < count; i++)
            hs[i] = (wn_handle)(uintptr_t)p[i];
    } else {
        const wn_handle *p = hs_raw;
        for (uint32_t i = 0; i < count; i++)
            hs[i] = (wn_handle)(uintptr_t)p[i];
    }
    for (;;) {
        if (g_q_count)
            return count;          /* WAIT_OBJECT_0 + n: message arrived */
        /* Probe the handles with a zero timeout through the sync engine. */
        if (count) {
            extern uint32_t wn_wait_multiple(uint32_t, const wn_handle *,
                                             int, uint32_t);
            uint32_t wr = wn_wait_multiple(count, hs, (int)wait_all, 0);
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


/* ==================== MessageBox engine ====================================
 * A REAL modal box (the old stub printed the text and answered IDOK —
 * neither IDYES nor IDNO, so Inno's 'Exit Setup?' confirm made the
 * wizard ignore every close attempt: the field "closing hangs the
 * wizard" report). The box is a #32770 window with a Static text child,
 * an icon block on the face, and standard Button children; the modal
 * pump runs inside MessageBoxA/W exactly like DialogBoxParamA's. */
/* (ctx type + ID defines + helper prototypes: top of this file.) */

static int msgbox_has_cancel(msgbox_ctx *m)
{
    for (int i = 0; i < m->n_buttons; i++)
        if (m->ids[i] == WN_IDCANCEL)
            return 1;
    return 0;
}

/* WM_CLOSE / SC_CLOSE on the box: Windows answers IDCANCEL when the box
 * HAS a cancel-style button, else IDOK (MB_YESNO's X is disabled on
 * real Windows; ours answers IDNO — same "don't exit" outcome). */
static int msgbox_close_answer(msgbox_ctx *m)
{
    if (msgbox_has_cancel(m))
        return WN_IDCANCEL;
    for (int i = 0; i < m->n_buttons; i++)
        if (m->ids[i] == WN_IDNO)
            return WN_IDNO;
    return WN_IDOK;
}

/* Icon block on the box face: colored plate + white glyph letter. */
static void msgbox_paint_icon(wn_handle hdc, msgbox_ctx *m)
{
    if (!m->icon_kind)
        return;
    static const uint32_t plate[5] = {
        0, 0x000000CC /*red*/, 0x00CCAA00 /*blue-*/, 0x0000CCCC /*yellow*/,
        0x00CCAA00,
    };
    static const char glyph[5] = { 0, 'X', '?', '!', 'i' };
    int x = m->icon_x, y = m->icon_y, s = 32;
    wn_handle b = g32_CreateSolidBrush(plate[m->icon_kind]);
    int32_t r[4] = { x, y, x + s, y + s };
    g32_FillRect(hdc, r, b);
    wn_handle_close(b);
    g32_SetBkMode(hdc, 1 /*TRANSPARENT*/);
    g32_SetTextColor(hdc, 0x00FFFFFF);
    msgbox_draw_glyph(hdc, glyph[m->icon_kind], x + 6, y + 4, s - 8, s - 8);
}

/* 1-char draw helper with a proper NUL terminator. */
static void msgbox_draw_glyph(wn_handle hdc, char c, int x, int y, int w,
                              int h)
{
    char two[2] = { c, 0 };
    int32_t tr[4] = { x, y, x + w, y + h };
    g32_DrawTextA(hdc, two, -1, tr, 0x20 | 0x24 /*SINGLELINE|VCENTER*/);
}

/* Standard button set for a uType. */
static void msgbox_buttons(uint32_t type, int ids[3], char labels[3][20],
                           int *n_out)
{
    int n = 0;
    switch (type & 0xF) {
    case 0x0 /*MB_OK*/:      ids[n]=WN_IDOK;   snprintf(labels[n],20,"OK"); n++; break;
    case 0x1 /*MB_OKCANCEL*/:
        ids[n]=WN_IDOK;     snprintf(labels[n],20,"OK"); n++;
        ids[n]=WN_IDCANCEL; snprintf(labels[n],20,"Cancel"); n++; break;
    case 0x2 /*MB_ABORTRETRYIGNORE*/:
        ids[n]=WN_IDABORT;  snprintf(labels[n],20,"&Abort"); n++;
        ids[n]=WN_IDRETRY;  snprintf(labels[n],20,"&Retry"); n++;
        ids[n]=WN_IDIGNORE; snprintf(labels[n],20,"&Ignore"); n++; break;
    case 0x3 /*MB_YESNOCANCEL*/:
        ids[n]=WN_IDYES;    snprintf(labels[n],20,"&Yes"); n++;
        ids[n]=WN_IDNO;     snprintf(labels[n],20,"&No"); n++;
        ids[n]=WN_IDCANCEL; snprintf(labels[n],20,"Cancel"); n++; break;
    case 0x4 /*MB_YESNO*/:
        ids[n]=WN_IDYES;    snprintf(labels[n],20,"&Yes"); n++;
        ids[n]=WN_IDNO;     snprintf(labels[n],20,"&No"); n++; break;
    case 0x5 /*MB_RETRYCANCEL*/:
        ids[n]=WN_IDRETRY;  snprintf(labels[n],20,"&Retry"); n++;
        ids[n]=WN_IDCANCEL; snprintf(labels[n],20,"Cancel"); n++; break;
    case 0x6 /*MB_CANCELTRYCONTINUE*/:
        ids[n]=WN_IDCANCEL; snprintf(labels[n],20,"Cancel"); n++;
        ids[n]=10/*IDTRYAGAIN*/; snprintf(labels[n],20,"&Try Again"); n++;
        ids[n]=11/*IDCONTINUE*/; snprintf(labels[n],20,"&Continue"); n++; break;
    default:
        ids[n]=WN_IDOK;   snprintf(labels[n],20,"OK"); n++; break;
    }
    *n_out = n;
}

/* Headless/auto answer: the DEFAULT button of the type (matches what a
 * user pressing Enter would do). */
static int msgbox_auto_answer(const msgbox_ctx *m)
{
    if (m->n_buttons <= 0)
        return WN_IDOK;
    int idx = m->default_idx;
    if (idx < 0 || idx >= m->n_buttons)
        idx = 0;
    return m->ids[idx];
}

/* Build + run the modal box. Returns the pressed button's id. */
static int32_t msgbox_run(uint64_t owner, const char *text8,
                          const char *caption8, uint32_t type)
{
    msgbox_ctx *m = wn_xcalloc(1, sizeof *m);
    m->type = type;
    m->owner = owner;
    msgbox_buttons(type, m->ids, m->labels, &m->n_buttons);
    int def = (int)((type >> 8) & 3);   /* MB_DEFBUTTON2=0x100, 3=0x200 */
    m->default_idx = def < m->n_buttons ? def : 0;
    uint32_t ic = type & 0xF0;
    m->icon_kind = (ic & 0x10) ? 1 : (ic & 0x20) ? 2
                 : (ic & 0x30) ? 3 : (ic & 0x40) ? 4 : 0;

    /* no backend (headless /S installers) or AUTO mode: answer the
     * default button and stay deterministic for tests. */
    int auto_mode = getenv("WINNUX_MSGBOX_AUTO") != NULL;
    if (auto_mode || ensure_gui() != 0) {
        wn_log(WN_LOG_INFO, "MSGBOX(auto) '%s': %s -> default button",
               caption8 ? caption8 : "", text8 ? text8 : "");
        int32_t r = (int32_t)msgbox_auto_answer(m);
        free(m);
        return r;
    }

    /* --- measure the wrapped text ------------------------------------ */
    extern wn_handle g32_CreateCompatibleDC(wn_handle);
    const int MAX_TXT_W = 380, MARGIN = 18, BTN_W = 78, BTN_H = 24,
              BTN_GAP = 10, AREA_PAD = 18;
    wn_handle mdc = g32_CreateCompatibleDC(0);
    int text_h = 0, text_w = 0;
    if (mdc) {
        int32_t mr[4] = { 0, 0, MAX_TXT_W, 0 };
        g32_DrawTextA(mdc, text8 ? text8 : "", -1, mr,
                      0x400 /*DT_CALCRECT*/ | 0x10 /*DT_WORDBREAK*/);
        text_w = mr[2] - mr[0];
        text_h = mr[3] - mr[1];
        g32_ReleaseDC(0, mdc);
    }
    if (text_w < 40)
        text_w = 40;
    if (text_h < 16)
        text_h = 16;

    /* --- geometry ----------------------------------------------------- */
    int icon_w = m->icon_kind ? 32 + 14 : 0;
    int inner_w = icon_w + text_w + MARGIN;
    int btn_row_w = m->n_buttons * BTN_W + (m->n_buttons - 1) * BTN_GAP;
    if (btn_row_w + 2 * AREA_PAD > inner_w)
        inner_w = btn_row_w + 2 * AREA_PAD;
    int box_w = inner_w + 2 * MARGIN;
    if (box_w < 240)
        box_w = 240;
    int inner_h = text_h;
    if (inner_h < 32)
        inner_h = 32;
    int box_h = inner_h + BTN_H + 3 * AREA_PAD;
    if (box_h < 120)
        box_h = 120;
    /* center on the owner (screen center when none) */
    int bx = 0, by = 0;
    wn_window *ow = owner ? win_from_hwnd(owner) : NULL;
    if (ow) {
        int sx, sy;
        win_screen_origin(ow, &sx, &sy);
        bx = sx + (ow->cw - box_w) / 2;
        by = sy + (ow->ch - box_h) / 2;
    } else {
        bx = (u32_GetSystemMetrics(0 /*SM_CXSCREEN*/) - box_w) / 2;
        by = (u32_GetSystemMetrics(1 /*SM_CYSCREEN*/) - box_h) / 2;
    }
    if (bx < 0) bx = 0;
    if (by < 0) by = 0;

    /* --- the box window ------------------------------------------------ */
    char cap[128];
    snprintf(cap, sizeof cap, "%s", caption8 ? caption8 : "");
    uint32_t style = 0x80000000u /*WS_POPUP*/ | 0x00C00000u /*WS_CAPTION*/ |
                     0x00080000u /*WS_SYSMENU*/;
    uint64_t box = create_window_core(0, "#32770", cap, 0, 0, style,
                                      bx, by, box_w, box_h,
                                      (wn_abiword)owner, 0, 0, NULL);
    if (!box) {
        int32_t r = (int32_t)msgbox_auto_answer(m);
        free(m);
        wn_log(WN_LOG_WARN, "MSGBOX: box creation failed -> auto answer %d",
               r);
        return r;
    }
    wn_window *bw = win_from_hwnd(box);
    if (!bw) {
        int32_t r = (int32_t)msgbox_auto_answer(m);
        free(m);
        return r;
    }
    bw->is_dialog = 1;
    bw->ctl_priv_kind = CTL_PRIV_MSGBOX;   /* DestroyWindow frees it */
    bw->ctl_priv = m;
    m->icon_x = MARGIN;
    m->icon_y = AREA_PAD;
    int text_x = MARGIN + icon_w;
    int text_y = AREA_PAD;
    m->result = 0;

    /* text Static */
    uint64_t txt = create_window_core(0, "Static", text8 ? text8 : "",
                                      0, 0,
                                      0x40000000u /*WS_CHILD*/ |
                                      0x10000000u /*WS_VISIBLE*/,
                                      text_x, text_y,
                                      MARGIN + text_w, text_h,
                                      (wn_abiword)box, 0xFFFF /*id*/,
                                      0, NULL);
    (void)txt;

    /* buttons: right-aligned row at the bottom */
    int row_w = btn_row_w;
    int bx0 = box_w - MARGIN - row_w;
    int byy = box_h - AREA_PAD - BTN_H;
    for (int i = 0; i < m->n_buttons; i++) {
        uint32_t bstyle = 0x40000000u /*WS_CHILD*/ |
                          0x10000000u /*WS_VISIBLE*/ |
                          0x10000 /*WS_TABSTOP*/;
        if (i == m->default_idx)
            bstyle |= 0x2000 /*WS_DEFPUSHBUTTON*/;
        char lab[20];
        snprintf(lab, sizeof lab, "%s", m->labels[i]);
        m->mnem[i] = 0;
        for (char *p = lab; *p; p++) {
            if (*p == '&' && p[1] && p[1] != '&') {
                m->mnem[i] = (char)((p[1] >= 'A' && p[1] <= 'Z')
                                      ? p[1] + 32 : p[1]);
                break;
            }
        }
        create_window_core(0, "Button", lab, 0, 0, bstyle,
                           bx0 + i * (BTN_W + BTN_GAP), byy, BTN_W, BTN_H,
                           (wn_abiword)box, (wn_abiword)m->ids[i], 0, NULL);
    }

    /* --- modality ------------------------------------------------------ */
    uint64_t prev_focus = g_focus_hwnd;
    uint64_t prev_active = g_active_hwnd;
    int owner_was_enabled = 1;
    if (owner)
        owner_was_enabled = u32_EnableWindow((wn_abiword)owner, 0);
    u32_ShowWindow((wn_abiword)box, 1 /*SW_SHOWNORMAL*/);
    u32_SetActiveWindow((wn_abiword)box);
    {
        uint64_t def_btn = 0;
        for (int i = 0; i < g_hwnd_count && !def_btn; i++) {
            wn_window *c = g_hwnds[i].win;
            if (c && c->parent == box && c->id == (uint64_t)m->ids[m->default_idx])
                def_btn = (uint64_t)(uintptr_t)hwnd_of_window(c);
        }
        if (!def_btn)
            def_btn = box;
        user32_set_focus_internal(def_btn);
    }
    wn_log(WN_LOG_DEBUG, "MSGBOX modal: '%s' type=0x%x owner=0x%llx",
           cap, type, (unsigned long long)owner);

    uint8_t msgbuf[0x30];   /* guest MSG layout; wn_msg is smaller! */
    while (!m->done) {
        int32_t r = u32_GetMessageA(msgbuf, 0, 0, 0);
        if (r <= 0)
            break;              /* WM_QUIT or backend death: bail */
        uint64_t mh;
        uint32_t mm;
        uint64_t mwp;
        int64_t mlp;
        msg_read(msgbuf, &mh, &mm, &mwp, &mlp);
        /* Alt+mnemonic: WM_CHAR with Alt held clicks the matching button
         * (Windows msgboxes answer Alt+Y / Alt+N). */
        if (mm == WN_WM_CHAR && (u32_GetKeyState(0x12 /*VK_MENU*/)
                                 & 0x8000)) {
            char c = (char)(uint8_t)(mwp & 0xFF);
            if (c >= 'A' && c <= 'Z')
                c = (char)(c + 32);
            int hit = 0;
            for (int i = 0; i < m->n_buttons && !hit; i++) {
                if (m->mnem[i] && m->mnem[i] == c) {
                    for (int j = 0; j < g_hwnd_count; j++) {
                        wn_window *b2 = g_hwnds[j].win;
                        if (b2 && b2->parent == box &&
                            b2->id == (uint64_t)m->ids[i]) {
                            ctl_notify(b2, 0 /*BN_CLICKED*/);
                            hit = 1;
                            break;
                        }
                    }
                }
            }
            if (hit)
                continue;
        }
        if (!u32_IsDialogMessageA(box, msgbuf))
            u32_DispatchMessageA(msgbuf);
    }
    int32_t answer = m->result ? m->result : (int32_t)msgbox_close_answer(m);
    m->result = answer;          /* ctl_priv payload freed by DestroyWindow */
    if (owner && owner_was_enabled)
        u32_EnableWindow((wn_abiword)owner, 1);
    user32_set_focus_internal(prev_focus);
    u32_SetActiveWindow((wn_abiword)prev_active);
    wn_log(WN_LOG_DEBUG, "MSGBOX answered %d", answer);
    u32_DestroyWindow((wn_abiword)box);   /* frees the msgbox ctx payload */
    return answer;
}

static WN_API int32_t u32_MessageBoxA(wn_abiword hwnd, const char *text,
                                      const char *caption, uint32_t type)
{
    return msgbox_run((uint64_t)hwnd, text, caption, type);
}

static WN_API int32_t u32_MessageBoxW(wn_abiword hwnd, const uint16_t *text,
                                      const uint16_t *caption, uint32_t type)
{
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
    int32_t r = msgbox_run((uint64_t)hwnd, t, c, type);
    free(t);
    free(c);
    return r;
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
    { "SetRect", u32_SetRect },
    { "SetRectEmpty", u32_SetRectEmpty },
    { "PtInRect", u32_PtInRect },
    { "WindowFromPoint", u32_WindowFromPoint },
    { "FillRect", g32_FillRect },
    { "GetDC", g32_GetDC },
    { "GetMessageA", u32_GetMessageA },
    { "WaitMessage", u32_WaitMessage },
    { "GetWindowRect", u32_GetWindowRect },
    { "IsWindow", u32_IsWindow },
    { "KillTimer", u32_KillTimer },
    { "PeekMessageA", u32_PeekMessageA },
    { "PostMessageA", u32_PostMessageA },
    { "PostQuitMessage", u32_PostQuitMessage },
    { "RegisterClassA", u32_RegisterClassA },
    { "ReleaseDC", g32_ReleaseDC },
    { "RegisterClassW", u32_RegisterClassW },
    { "GetClassInfoA", u32_GetClassInfoA },
    { "GetClassInfoW", u32_GetClassInfoW },
    { "CharLowerA", u32_CharLowerA },
    { "CharLowerW", u32_CharLowerW },
    { "CharUpperA", u32_CharUpperA },
    { "CharUpperW", u32_CharUpperW },
    { "CharLowerBuffA", u32_CharLowerBuffA },
    { "CharLowerBuffW", u32_CharLowerBuffW },
    { "CharUpperBuffA", u32_CharUpperBuffA },
    { "CharUpperBuffW", u32_CharUpperBuffW },
    { "OemToCharA", u32_OemToCharA },
    { "OemToCharBuffA", u32_OemToCharBuffA },
    { "OemToCharW", u32_OemToCharW },
    { "CharToOemA", u32_CharToOemA },
    { "CharToOemBuffA", u32_CharToOemBuffA },
    { "CharToOemW", u32_CharToOemW },
    { "SendMessageA", u32_SendMessageA },
    { "SendMessageW", u32_SendMessageW },
    { "CallWindowProcA", u32_CallWindowProcA },
    { "CallWindowProcW", u32_CallWindowProcW },
    { "SetTimer", u32_SetTimer },
    { "SetWindowTextA", u32_SetWindowTextA },
    { "SetWindowPos", u32_SetWindowPos },
    { "ScrollWindow", u32_ScrollWindow },
    { "ScrollWindowEx", u32_ScrollWindowEx },
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
    { "IsWindowVisible", u32_IsWindowVisible },
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
    { "MessageBoxIndirectA", u32_MessageBoxIndirectA },
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
    { "GetKeyState", u32_GetKeyState },
    { "GetAsyncKeyState", u32_GetAsyncKeyState },
    { "GetWindowThreadProcessId", u32_GetWindowThreadProcessId },
    { "EnumWindows", u32_EnumWindows },
    { "SetScrollInfo", u32_SetScrollInfo },
    { "GetScrollInfo", u32_GetScrollInfo },
    { "SetScrollPos", u32_SetScrollPos },
    { "GetScrollPos", u32_GetScrollPos },
    { "SetScrollRange", u32_SetScrollRange },
    { "GetScrollRange", u32_GetScrollRange },
    { "ShowScrollBar", u32_ShowScrollBar },
    { "EnableScrollBar", u32_EnableScrollBar },
    { "EnumThreadWindows", u32_EnumThreadWindows },
    { "GetKeyboardType", u32_GetKeyboardType },
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
    { "LoadBitmapA", u32_LoadBitmapA },
    { "IsRectEmpty", u32_IsRectEmpty },
    { "DrawIconEx", u32_DrawIconEx },
    { "DrawIcon", u32_DrawIcon },
    { "CreateMenu", u32_CreateMenu },
    { "CreatePopupMenu", u32_CreatePopupMenu },
    { "DestroyMenu", u32_DestroyMenu },
    { "AppendMenuA", u32_AppendMenuA },
    { "AppendMenuW", u32_AppendMenuW },
    { "DeleteMenu", u32_DeleteMenu },
    { "RemoveMenu", u32_RemoveMenu },
    { "EnableMenuItem", u32_EnableMenuItem },
    { "GetMenuItemCount", u32_GetMenuItemCount },
    { "GetMenuItemID", u32_GetMenuItemID },
    { "GetMenuState", u32_GetMenuState },
    { "SetMenu", u32_SetMenu },
    { "GetMenu", u32_GetMenu },
    { "GetSystemMenu", u32_GetSystemMenu },
    { "DrawMenuBar", u32_DrawMenuBar },
    { "SetPropA", u32_SetPropA },
    { "GetPropA", u32_GetPropA },
    { "RemovePropA", u32_RemovePropA },
    { "SetScrollInfo", u32_SetScrollInfo },
    { "GetScrollInfo", u32_GetScrollInfo },
    { "GetScrollPos", u32_GetScrollPos },
    { "SetScrollPos", u32_SetScrollPos },
    { "SendNotifyMessageA", u32_SendNotifyMessageA },
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
