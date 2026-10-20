/* x11_backend.c — Xlib backend, loaded via dlopen at runtime.
 *
 * No X11 headers are compiled against: function pointers are declared here
 * and resolved with dlsym; XEvent is accessed through layout-exact overlay
 * structs on a fixed 192-byte buffer (the X11 wire ABI, stable since 1987).
 * The rest of WinNux never touches X11.
 */
#include "wn_backend.h"
#include "wn_log.h"
#include "wn_util.h"

#include <dlfcn.h>
#include <poll.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* --- opaque X types (we only ever hold pointers) --------------------------- */
typedef void *wnx_Display;
typedef unsigned long wnx_XID;
typedef unsigned long wnx_Window;
typedef unsigned long wnx_Atom;
typedef void *wnx_Visual;
typedef unsigned long wnx_GContext;

/* XEvent: fixed 192-byte union. FIELD OFFSETS ARE DATA-MODEL DEPENDENT:
 * Xlib lays its structs out for the ABI of THIS process (we dlopen the
 * matching libX11), so LP64 (x86_64) and ILP32 (i386) differ wherever a
 * pointer or unsigned long appears. The original overlays hard-coded the
 * LP64 offsets; on i386 every event decoded garbage (window read from
 * dead bytes), win_for() never matched, and Expose/ClientMessage/input
 * were ALL silently dropped — the field reports of the white-window
 * wizard with dead close/maximize buttons under a real WM. Offsets:
 *   LP64: serial@8, send_event@16, display@24, window@32, ...
 *   ILP32: serial@4, send_event@8, display@12, window@16, ...
 */
#define XEVENT_SIZE 192

#if defined(__x86_64__)
# define EV_OFF_WINDOW       32
# define KY_OFF_X            64
# define KY_OFF_Y            68
# define KY_OFF_STATE        80
# define KY_OFF_KEYCODE      84
# define EX_OFF_X            40
# define EX_OFF_Y            44
# define EX_OFF_WIDTH        48
# define EX_OFF_HEIGHT       52
# define EX_OFF_COUNT        56
# define CF_OFF_X            48
# define CF_OFF_Y            52
# define CF_OFF_WIDTH        56
# define CF_OFF_HEIGHT       60
# define CM_OFF_MSGTYPE     40
# define CM_OFF_FORMAT       48
# define CM_OFF_DATA         56
# define CM_DATA_WORDSIZE    8     /* long l[5] */
#else
# define EV_OFF_WINDOW       16
# define KY_OFF_X            32
# define KY_OFF_Y            36
# define KY_OFF_STATE        48
# define KY_OFF_KEYCODE      52
# define EX_OFF_X            20
# define EX_OFF_Y            24
# define EX_OFF_WIDTH        28
# define EX_OFF_HEIGHT       32
# define EX_OFF_COUNT        36
# define CF_OFF_X            24
# define CF_OFF_Y            28
# define CF_OFF_WIDTH        32
# define CF_OFF_HEIGHT       36
# define CM_OFF_MSGTYPE     20
# define CM_OFF_FORMAT       24
# define CM_OFF_DATA         28
# define CM_DATA_WORDSIZE    4     /* long = 4 bytes on ILP32 */
#endif

/* Offset readers into the raw event buffer (memcpy = no alignment or
 * aliasing assumptions). */
static int32_t ev_i32(const void *raw, size_t off)
{
    int32_t v;
    memcpy(&v, (const uint8_t *)raw + off, sizeof v);
    return v;
}

static uint32_t ev_u32(const void *raw, size_t off)
{
    uint32_t v;
    memcpy(&v, (const uint8_t *)raw + off, sizeof v);
    return v;
}

static wnx_Window ev_window(const void *raw)
{
    wnx_Window w;
    memcpy(&w, (const uint8_t *)raw + EV_OFF_WINDOW, sizeof w);
    return w;
}

/* XWindowAttributes: x@0 y@4 width@8 height@12 — identical on both data
 * models (ints only up to there). THE STRUCT IS ~136 BYTES ON LP64 (~96 on
 * ILP32): XGetWindowAttributes writes the FULL struct, so the destination
 * must be over-sized (a 24-byte overlay smashed the stack and crashed with
 * wild pointers — same class as the TEXTMETRICA /GS bug). */
typedef struct {
    int32_t x, y, width, height;
    int32_t border_width, depth;
    uint8_t rest[160];
} xwattr;
_Static_assert(offsetof(xwattr, width) == 8, "XWindowAttributes ABI");
_Static_assert(offsetof(xwattr, height) == 12, "XWindowAttributes ABI");
_Static_assert(sizeof(xwattr) >= 136, "XWindowAttributes full size");

/* XImage parameters for depth-24 ZPixmap with 32bpp storage: pixel bytes are
 * B,G,R,X — identical to a Win32 32bpp DIB, so zero conversion is needed.
 * Field offsets BY DATA MODEL (same trap as the event block — the old
 * overlay was LP64-only, and on i386 its mask writes LANDED IN XImage's
 * function-pointer tail while byte_order went to bitmap_unit):
 *   LP64: data@16, byte_order@24, bitmap_bit_order@32, bytes_per_line@44,
 *         bits_per_pixel@48, masks@56/64/72
 *   ILP32: data@16, byte_order@20, bitmap_bit_order@28, bytes_per_line@40,
 *         bits_per_pixel@44, masks@48/52/56
 * width@0/height@4 are ints and identical everywhere. The struct itself is
 * opaque: every access goes through these offsets. */
typedef struct wnx_image wnx_XImage;   /* opaque: offset access only */

#if defined(__x86_64__)
# define XI_OFF_BYTE_ORDER        24
# define XI_OFF_BITMAP_BIT_ORDER  32
# define XI_OFF_BPL               44
# define XI_OFF_BITS_PER_PIXEL    48
# define XI_OFF_RED               56
# define XI_OFF_GREEN             64
# define XI_OFF_BLUE              72
#else
# define XI_OFF_BYTE_ORDER        20
# define XI_OFF_BITMAP_BIT_ORDER  28
# define XI_OFF_BPL               40
# define XI_OFF_BITS_PER_PIXEL    44
# define XI_OFF_RED               48
# define XI_OFF_GREEN             52
# define XI_OFF_BLUE              56
#endif

static void xi_w32(wnx_XImage *img, size_t off, uint32_t v)
{
    memcpy((uint8_t *)img + off, &v, sizeof v);
}

static int32_t xi_r32(void *img, size_t off)
{
    int32_t v;
    memcpy(&v, (uint8_t *)img + off, sizeof v);
    return v;
}

/* --- resolved function pointers -------------------------------------------- */
static wnx_Display (*pXOpenDisplay)(const char *);
static int (*pXCloseDisplay)(wnx_Display);
static wnx_Window (*pXDefaultRootWindow)(wnx_Display);
static int (*pXDefaultScreen)(wnx_Display);
static wnx_Visual (*pXDefaultVisual)(wnx_Display, int);
static wnx_Window (*pXCreateSimpleWindow)(wnx_Display, wnx_Window, int, int,
                                          unsigned, unsigned, unsigned,
                                          unsigned long, unsigned long);
static int (*pXDestroyWindow)(wnx_Display, wnx_Window);
static int (*pXMapWindow)(wnx_Display, wnx_Window);
static int (*pXUnmapWindow)(wnx_Display, wnx_Window);
static int (*pXStoreName)(wnx_Display, wnx_Window, const char *);
static int (*pXSelectInput)(wnx_Display, wnx_Window, long);
static int (*pXNextEvent)(wnx_Display, void *);
static int (*pXPending)(wnx_Display);
static int (*pXConnectionNumber)(wnx_Display);
static int (*pXFlush)(wnx_Display);
static int (*pXSync)(wnx_Display, int);
static wnx_Atom (*pXInternAtom)(wnx_Display, const char *, int);
static int (*pXSetWMProtocols)(wnx_Display, wnx_Window, wnx_Atom *, int);
static wnx_GContext (*pXCreateGC)(wnx_Display, wnx_Window, unsigned long, void *);
static int (*pXSetForeground)(wnx_Display, wnx_GContext, unsigned long);
static wnx_XImage *(*pXCreateImage)(wnx_Display, wnx_Visual, int, int, int,
                                    char *, unsigned, unsigned, int, int);
static int (*pXPutImage)(wnx_Display, wnx_Window, wnx_GContext, wnx_XImage *,
                         int, int, int, int, unsigned, unsigned);
static int (*pXFree)(void *);
static int (*pXLookupString)(void *, char *, int, wnx_Atom *, void *);
static int (*pXDrawImageString)(wnx_Display, wnx_Window, wnx_GContext,
                                int, int, const char *, int);
static int (*pXGetWindowAttributes)(wnx_Display, wnx_Window, void *);

static wnx_Display g_dpy;
static wnx_Window g_root;
static wnx_Visual g_visual;
static int g_depth;
static wnx_GContext g_gc;
static wnx_Atom g_wm_delete;

/* Glyph rendering: draw the char server-side into a scratch pixmap, read
 * it back with XGetImage, cache. Gives real font rendering with zero font
 * libraries; the glyph cache keeps it off the hot path. */
typedef struct {
    int w, h;
    uint32_t *rgb;
} x11_glyph;
static x11_glyph *g_glyphs[256];

typedef struct {
    void *ext_data;
    int32_t private1, private2;
    int32_t min_byte1, max_byte1, min_char_or_byte2, max_char_or_byte2;
    int32_t ascent, descent, min_bounds_l, min_bounds_r, min_bounds_w, min_bounds_a, min_bounds_d;
    int32_t max_bounds_l, max_bounds_r, max_bounds_w, max_bounds_a, max_bounds_d;
    void *props_ptr;
    int32_t n_props;
    void *per_char;
    int32_t default_char, n_chrs, rows, pad;
    void *fid_ptr;
} wnx_font_min;   /* XFontStruct (first fields only, offsets known) */

static void *(*pXLoadQueryFont)(wnx_Display, const char *);
static int (*pXTextWidth)(void *, const char *, int);
static wnx_XID (*pXCreatePixmap)(wnx_Display, wnx_Window, unsigned, unsigned, unsigned);
static void *(*pXGetImage)(wnx_Display, wnx_Window, int, int, unsigned, unsigned, unsigned long, int);
static int (*pXFreePixmap)(wnx_Display, wnx_XID);
static int (*pXSetBackground)(wnx_Display, wnx_GContext, unsigned long);
static void *g_font;      /* XFontStruct* */
static wnx_XID g_scratch_pm;
static unsigned g_scratch_w, g_scratch_h;

int wn_backend_glyph_render(unsigned char c, int *w, int *h, uint32_t **rgb)
{
    if (!g_font || !pXGetImage)
        return -1;
    if (!g_glyphs[c]) {
        char s[2] = { (char)c, 0 };
        int cw = pXTextWidth(g_font, s, 1);
        int ch = 16;   /* font ascent+descent estimate */
        if (cw <= 0) cw = 8;
        if ((unsigned)cw > g_scratch_w || (unsigned)ch > g_scratch_h) {
            if (g_scratch_pm)
                pXFreePixmap(g_dpy, g_scratch_pm);
            g_scratch_w = cw > 64 ? (unsigned)cw : 64;
            g_scratch_h = ch > 32 ? (unsigned)ch : 32;
            g_scratch_pm = pXCreatePixmap(g_dpy, g_root, g_scratch_w,
                                          g_scratch_h, (unsigned)g_depth);
            if (!g_scratch_pm)
                return -1;
        }
        /* Draw white on black, then map to RGB. */
        pXSetForeground(g_dpy, g_gc, 0);
        /* XFillRectangle equivalent via PutImage of zeros is complex; use
         * XClearArea? Simplest: rely on fresh pixmaps being zeroed. */
        pXSetBackground(g_dpy, g_gc, 0);
        pXSetForeground(g_dpy, g_gc, 0xFFFFFF);
        pXDrawImageString(g_dpy, g_scratch_pm, g_gc, 0, 12, s, 1);
        pXSync(g_dpy, 0);
        void *xi = pXGetImage(g_dpy, g_scratch_pm, 0, 0, g_scratch_w,
                              g_scratch_h, 0xFFFFFF, 2 /* ZPixmap */);
        if (!xi)
            return -1;
        /* XImage: height@4 (int, same on all models); data@16 (pointer,
         * natural width); bytes_per_line is size-model dependent. */
        int ih = xi_r32(xi, 4);
        int bpl = xi_r32(xi, XI_OFF_BPL);
        uint8_t *data = *(uint8_t **)((char *)xi + 16);
        x11_glyph *g = wn_xmalloc(sizeof *g);
        g->w = cw;
        g->h = ch < ih ? ch : ih;
        g->rgb = wn_xcalloc((size_t)g->w * g->h, 4);
        for (int y = 0; y < g->h && y < ih; y++) {
            for (int x = 0; x < g->w; x++) {
                uint32_t px = 0;
                memcpy(&px, data + (size_t)y * bpl + (size_t)x * 4, 4);
                g->rgb[(size_t)y * g->w + x] = px & 0xFFFFFF;
            }
        }
        pXFree(xi);
        g_glyphs[c] = g;
    }
    *w = g_glyphs[c]->w;
    *h = g_glyphs[c]->h;
    *rgb = g_glyphs[c]->rgb;
    return 0;
}


#define XEVENT_MASK (0x20000 /* StructureNotifyMask (1<<17) */ | \
                     0x8000  /* ExposureMask (1<<15) */ | \
                     0x1 /* KeyPress */ | 0x2 /* KeyRelease */ | \
                     0x4 /* ButtonPress */ | 0x8 /* ButtonRelease */ | \
                     0x40 /* PointerMotionMask (1<<6) */)

/* --- backend ops ------------------------------------------------------------ */

typedef struct {
    wnx_Window xwin;
    int x, y;                 /* last ConfigureNotify position */
} x11_win_priv;

/* X window id -> wn_bwin map, owned by THIS backend. The old scheme
 * (user32's g_bwins storing b->priv pointers and x11 comparing them
 * against window IDs) never matched — the whole input/expose path was
 * silently dead (found via synthetic clicks: events arrived at
 * handle_event and then vanished in win_for). */
#define X11_MAX_WINS 256
static struct { wnx_Window xwin; wn_bwin *b; } g_winmap[X11_MAX_WINS];
static int g_winmap_n;

static void winmap_add(wnx_Window x, wn_bwin *b)
{
    if (g_winmap_n < X11_MAX_WINS) {
        g_winmap[g_winmap_n].xwin = x;
        g_winmap[g_winmap_n].b = b;
        g_winmap_n++;
    }
}

static void winmap_del(wnx_Window x)
{
    for (int i = 0; i < g_winmap_n; i++)
        if (g_winmap[i].xwin == x) {
            g_winmap[i] = g_winmap[g_winmap_n - 1];
            g_winmap_n--;
            return;
        }
}

static wn_bwin *win_for(wnx_Window xwin)
{
    for (int i = 0; i < g_winmap_n; i++)
        if (g_winmap[i].xwin == xwin)
            return g_winmap[i].b;
    return NULL;
}

static wn_bwin *x11_win_create(int w, int h, const char *title, void *userdata)
{
    wn_bwin *b = wn_xcalloc(1, sizeof *b);
    x11_win_priv *p = wn_xcalloc(1, sizeof *p);
    b->priv = p;
    b->width = w;
    b->height = h;
    b->userdata = userdata;
    b->stride = w * 4;
    p->xwin = pXCreateSimpleWindow(g_dpy, g_root, 0, 0, (unsigned)w,
                                   (unsigned)h, 0, 0, 0xFFFFFF);
    pXStoreName(g_dpy, p->xwin, title ? title : "WinNux");
    pXSelectInput(g_dpy, p->xwin, XEVENT_MASK);
    if (g_wm_delete)
        pXSetWMProtocols(g_dpy, p->xwin, &g_wm_delete, 1);
    winmap_add(p->xwin, b);
    return b;
}

static void x11_win_destroy(wn_bwin *b)
{
    x11_win_priv *p = b->priv;
    if (p && p->xwin) {
        winmap_del(p->xwin);
        pXDestroyWindow(g_dpy, p->xwin);
    }
    free(p);
    free(b->pixels);
    free(b);
}

static void x11_win_show(wn_bwin *b)
{
    x11_win_priv *p = b->priv;
    if (!p || !p->xwin)     /* child-surface bwin: nothing to map */
        return;
    pXMapWindow(g_dpy, p->xwin);
    pXFlush(g_dpy);
    b->mapped = 1;
    wn_log(WN_LOG_DEBUG, "x11: mapped window 0x%lx (pending=%d)",
           (unsigned long)p->xwin, pXPending(g_dpy));
}

static void x11_win_hide(wn_bwin *b)
{
    x11_win_priv *p = b->priv;
    if (!pXUnmapWindow || !p || !p->xwin)   /* child bwin: never mapped */
        return;
    pXUnmapWindow(g_dpy, p->xwin);
    pXFlush(g_dpy);
    b->mapped = 0;
    wn_log(WN_LOG_DEBUG, "x11: unmapped window 0x%lx", (unsigned long)p->xwin);
}

static void x11_win_set_title(wn_bwin *b, const char *title)
{
    pXStoreName(g_dpy, ((x11_win_priv *)b->priv)->xwin, title);
}

static int (*pXMoveResizeWindow)(wnx_Display, wnx_Window, int, int,
                                 unsigned, unsigned);
static int (*pXSetWMNormalHints)(wnx_Display, wnx_Window, void *);

/* XSizeHints: `long flags` + int fields — offsets move with the data model.
 * x64 (LP64): flags@0(8), x@8 y@12 width@16 height@20, min@24/28,
 *   max@32/36, width_inc@40/44, aspect@48..64, base@80/84, gravity@88.
 * i386 (ILP32): flags@0(4), x@4 y@8 width@12 height@16, min@20/24,
 *   max@28/32, width_inc@36/40, aspect@44..60, base@60/64, gravity@68.
 * Oversized buffer (HANDOFF gotcha: never undersize X struct overlays). */
#define XSIZEHINTS_BYTES 96
#define XHINT_PMIN 0x10
#define XHINT_PMAX 0x20

#if defined(__x86_64__)
# define XSH_OFF_MINW 24
# define XSH_OFF_MINH 28
# define XSH_OFF_MAXW 32
# define XSH_OFF_MAXH 36
#else
# define XSH_OFF_MINW 20
# define XSH_OFF_MINH 24
# define XSH_OFF_MAXW 28
# define XSH_OFF_MAXH 32
#endif

static void x11_win_fixed_size(wn_bwin *b)
{
    if (!pXSetWMNormalHints)
        return;
    x11_win_priv *p = b->priv;
    if (!p || !p->xwin)
        return;
    uint8_t hints[XSIZEHINTS_BYTES];
    memset(hints, 0, sizeof hints);
    *(int *)(void *)(hints + 0) = XHINT_PMIN | XHINT_PMAX;   /* low word of long */
    *(int *)(void *)(hints + XSH_OFF_MINW) = b->width;
    *(int *)(void *)(hints + XSH_OFF_MINH) = b->height;
    *(int *)(void *)(hints + XSH_OFF_MAXW) = b->width;
    *(int *)(void *)(hints + XSH_OFF_MAXH) = b->height;
    pXSetWMNormalHints(g_dpy, p->xwin, hints);
    pXFlush(g_dpy);
}


static void x11_win_move_resize(wn_bwin *b, int x, int y, int cw, int ch)
{
    x11_win_priv *p = b->priv;
    if (cw < 1) cw = 1;
    if (ch < 1) ch = 1;
    if (pXMoveResizeWindow)
        pXMoveResizeWindow(g_dpy, p->xwin, x, y, (unsigned)cw, (unsigned)ch);
    if (cw != b->width || ch != b->height) {
        b->width = cw;
        b->height = ch;
        b->stride = cw * 4;
        free(b->pixels);
        b->pixels = wn_xmalloc((size_t)cw * ch * 4 + 64);
        memset(b->pixels, 0xFF, (size_t)cw * ch * 4);
    }
    pXFlush(g_dpy);
}

static void dispatch(wn_bwin *b, int type, int x, int y, int val, int val2)
{
    wn_backend_event ev = { .type = type, .win = b, .x = x, .y = y,
                            .val = val, .val2 = val2 };
    wn_backend_event_cb(&ev);
}


static void handle_event(void *raw)
{
    int type = ev_i32(raw, 0);
    wnx_Window xw = ev_window(raw);
    wn_log(WN_LOG_TRACE, "x11: event type=%d win=0x%lx", type,
           (unsigned long)xw);
    switch (type) {
    case 12 /* Expose */: {
        wn_bwin *b = win_for(xw);
        if (b)
            dispatch(b, WN_BEV_EXPOSE, ev_i32(raw, EX_OFF_X),
                     ev_i32(raw, EX_OFF_Y), ev_i32(raw, EX_OFF_WIDTH),
                     ev_i32(raw, EX_OFF_HEIGHT));
        break;
    }
    case 22 /* ConfigureNotify */: {
        wn_bwin *b = win_for(xw);
        if (!b)
            break;
        x11_win_priv *p = b->priv;
        int cx = ev_i32(raw, CF_OFF_X), cy = ev_i32(raw, CF_OFF_Y);
        if (p) {
            p->x = cx;
            p->y = cy;
        }
        int cw = ev_i32(raw, CF_OFF_WIDTH), ch = ev_i32(raw, CF_OFF_HEIGHT);
        if (cw != b->width || ch != b->height)
            dispatch(b, WN_BEV_RESIZE, cw, ch, 0, 0);
        else
            dispatch(b, WN_BEV_CONFIGURE, cx, cy, 0, 0);
        break;
    }
    case 2 /* KeyPress */:
    case 3 /* KeyRelease */: {
        wn_bwin *b = win_for(xw);
        if (!b)
            break;
        char buf[16] = { 0 };
        wnx_Atom keysym = 0;
        int n = pXLookupString(raw, buf, sizeof buf - 1, &keysym, NULL);
        /* modifier-mask reconcile: user32 keeps GetKeyState honest for
         * modifiers held before launch or eaten by WM grabs. Dispatched
         * on every CHANGE so shift/ctrl/alt state is never stale. */
        {
            static int s_last_mods = -1;
            int mods = ev_i32(raw, KY_OFF_STATE);
            if (mods != s_last_mods) {
                s_last_mods = mods;
                dispatch(b, WN_BEV_KEYMODS, 0, 0, mods, 0);
            }
        }
        dispatch(b, type == 2 ? WN_BEV_KEY : WN_BEV_KEYUP,
                 ev_i32(raw, KY_OFF_X), ev_i32(raw, KY_OFF_Y),
                 (int)(keysym & 0xFFFFFFFF), ev_u32(raw, KY_OFF_KEYCODE));
        if (n > 0 && type == 2) {
            buf[n] = '\0';
            for (int i = 0; i < n; i++)
                dispatch(b, WN_BEV_TEXT, 0, 0, (unsigned char)buf[i], 0);
        }
        break;
    }
    case 4 /* ButtonPress */:
    case 5 /* ButtonRelease */: {
        wn_bwin *b = win_for(xw);
        /* For button events the keycode slot holds the button number. */
        if (b)
            dispatch(b, WN_BEV_MOUSE_BUTTON, ev_i32(raw, KY_OFF_X),
                     ev_i32(raw, KY_OFF_Y), (type == 4) ? 1 : 0,
                     ev_u32(raw, KY_OFF_KEYCODE));
        break;
    }
    case 6 /* MotionNotify */: {
        wn_bwin *b = win_for(xw);
        if (b)
            dispatch(b, WN_BEV_MOUSE_MOVE, ev_i32(raw, KY_OFF_X),
                     ev_i32(raw, KY_OFF_Y), 0, 0);
        break;
    }
    case 33 /* ClientMessage */: {
        wn_bwin *b = win_for(xw);
        if (!b || !g_wm_delete)
            break;
        uint64_t data0 = 0;
        memcpy(&data0, (const uint8_t *)raw + CM_OFF_DATA,
               CM_DATA_WORDSIZE);
        if (data0 == (uint64_t)g_wm_delete)
            dispatch(b, WN_BEV_CLOSE, 0, 0, 0, 0);
        break;
    }
    default:
        break;
    }
}

static int x11_pump(int timeout_ms)
{
    int count = 0;
    for (;;) {
        int pending = pXPending(g_dpy);
        if (!pending) {
            if (count > 0 || timeout_ms == 0)
                break;
            struct pollfd pfd = { .fd = pXConnectionNumber(g_dpy),
                                  .events = POLLIN };
            int r = poll(&pfd, 1, timeout_ms < 0 ? -1 : timeout_ms);
            if (r <= 0)
                break;
            pending = pXPending(g_dpy);
            if (!pending)
                break;
        }
        unsigned char ev[XEVENT_SIZE];
        pXNextEvent(g_dpy, ev);
        handle_event(ev);
        count++;
        timeout_ms = 0;   /* after first batch, drain without blocking */
    }
    return count;
}

static void x11_present(wn_bwin *b)
{
    x11_win_priv *p = b->priv;
    /* Child-window surfaces have priv=NULL (offscreen bwins composed onto
     * their parents by user32) — there is no X window to present here. */
    if (!p || !p->xwin || !b->pixels)
        return;
    wnx_XImage *img = pXCreateImage(g_dpy, g_visual, g_depth, 2 /* ZPixmap */,
                                    0, (char *)b->pixels,
                                    (unsigned)b->width, (unsigned)b->height,
                                    32, b->stride);
    if (!img)
        return;
    /* Arch-correct offsets: XI_OFF_* (the LP64-only writes corrupted
     * bitmap_unit + the function-pointer tail on i386). Masks are
     * `unsigned long` — a 32-bit little-endian write carries the value
     * on both data models. */
    xi_w32(img, XI_OFF_BYTE_ORDER, 0);        /* LSBFirst */
    xi_w32(img, XI_OFF_BITMAP_BIT_ORDER, 0);
    xi_w32(img, XI_OFF_BITS_PER_PIXEL, 32);
    xi_w32(img, XI_OFF_RED, 0xFF0000);
    xi_w32(img, XI_OFF_GREEN, 0xFF00);
    xi_w32(img, XI_OFF_BLUE, 0xFF);
    pXPutImage(g_dpy, p->xwin, g_gc, img, 0, 0, 0, 0,
               (unsigned)b->width, (unsigned)b->height);
    /* XDestroyImage is Xfree + data-not-owned; XFree the image header. */
    pXFree(img);
    pXFlush(g_dpy);
}

static void x11_draw_text(wn_bwin *b, int x, int y, const char *utf8, uint32_t bgra)
{
    x11_win_priv *p = b->priv;
    uint32_t r = (bgra >> 16) & 0xFF, g = (bgra >> 8) & 0xFF, bl = bgra & 0xFF;
    unsigned long pixel = (r << 16) | (g << 8) | bl;
    pXSetForeground(g_dpy, g_gc, pixel);
    pXDrawImageString(g_dpy, p->xwin, g_gc, x, y, utf8, (int)strlen(utf8));
}

static int (*pXBell)(wnx_Display, int);

static void x11_beep(void)
{
    if (pXBell) {
        pXBell(g_dpy, 100);
        pXFlush(g_dpy);
    }
}

static int g_screen_w = 1280, g_screen_h = 800;

static void x11_screen_size(int *w, int *h)
{
    if (w)
        *w = g_screen_w;
    if (h)
        *h = g_screen_h;
}

static int x11_poll_fd(void)
{
    return g_dpy ? pXConnectionNumber(g_dpy) : -1;
}

static void x11_win_pos(wn_bwin *b, int *x, int *y)
{
    x11_win_priv *p = b ? b->priv : NULL;
    if (x)
        *x = p ? p->x : 0;
    if (y)
        *y = p ? p->y : 0;
}

static int x11_init(void)
{
    void *x = dlopen("libX11.so.6", RTLD_LAZY | RTLD_LOCAL);
    if (!x) {
        wn_log(WN_LOG_INFO, "x11: libX11.so.6 unavailable: %s", dlerror());
        return -1;
    }
    #define RESOLVE(sym, type, name) \
        do { \
            p##sym = (type)dlsym(x, name); \
            if (!p##sym) { \
                wn_log(WN_LOG_ERR, "x11: missing %s", name); \
                return -1; \
            } \
        } while (0)

    RESOLVE(XOpenDisplay, wnx_Display (*)(const char *), "XOpenDisplay");
    RESOLVE(XCloseDisplay, int (*)(wnx_Display), "XCloseDisplay");
    RESOLVE(XDefaultRootWindow, wnx_Window (*)(wnx_Display), "XDefaultRootWindow");
    RESOLVE(XDefaultScreen, int (*)(wnx_Display), "XDefaultScreen");
    RESOLVE(XDefaultVisual, wnx_Visual (*)(wnx_Display, int), "XDefaultVisual");
    RESOLVE(XCreateSimpleWindow, wnx_Window (*)(wnx_Display, wnx_Window, int, int, unsigned, unsigned, unsigned, unsigned long, unsigned long), "XCreateSimpleWindow");
    RESOLVE(XDestroyWindow, int (*)(wnx_Display, wnx_Window), "XDestroyWindow");
    RESOLVE(XMapWindow, int (*)(wnx_Display, wnx_Window), "XMapWindow");
    pXUnmapWindow = dlsym(x, "XUnmapWindow");   /* optional (win_hide) */
    RESOLVE(XStoreName, int (*)(wnx_Display, wnx_Window, const char *), "XStoreName");
    RESOLVE(XSelectInput, int (*)(wnx_Display, wnx_Window, long), "XSelectInput");
    RESOLVE(XNextEvent, int (*)(wnx_Display, void *), "XNextEvent");
    RESOLVE(XPending, int (*)(wnx_Display), "XPending");
    RESOLVE(XConnectionNumber, int (*)(wnx_Display), "XConnectionNumber");
    RESOLVE(XFlush, int (*)(wnx_Display), "XFlush");
    RESOLVE(XSync, int (*)(wnx_Display, int), "XSync");
    RESOLVE(XInternAtom, wnx_Atom (*)(wnx_Display, const char *, int), "XInternAtom");
    RESOLVE(XSetWMProtocols, int (*)(wnx_Display, wnx_Window, wnx_Atom *, int), "XSetWMProtocols");
    RESOLVE(XCreateGC, wnx_GContext (*)(wnx_Display, wnx_Window, unsigned long, void *), "XCreateGC");
    RESOLVE(XSetForeground, int (*)(wnx_Display, wnx_GContext, unsigned long), "XSetForeground");
    RESOLVE(XCreateImage, wnx_XImage *(*)(wnx_Display, wnx_Visual, int, int, int, char *, unsigned, unsigned, int, int), "XCreateImage");
    RESOLVE(XPutImage, int (*)(wnx_Display, wnx_Window, wnx_GContext, wnx_XImage *, int, int, int, int, unsigned, unsigned), "XPutImage");
    RESOLVE(XFree, int (*)(void *), "XFree");
    RESOLVE(XLookupString, int (*)(void *, char *, int, wnx_Atom *, void *), "XLookupString");
    RESOLVE(XDrawImageString, int (*)(wnx_Display, wnx_Window, wnx_GContext, int, int, const char *, int), "XDrawImageString");
    RESOLVE(XGetWindowAttributes, int (*)(wnx_Display, wnx_Window, void *), "XGetWindowAttributes");
    #undef RESOLVE

    const char *disp = getenv("DISPLAY");
    g_dpy = pXOpenDisplay(disp);
    if (!g_dpy) {
        wn_log(WN_LOG_INFO, "x11: cannot open display '%s'", disp ? disp : "");
        return -1;
    }
    int screen = pXDefaultScreen(g_dpy);
    g_root = pXDefaultRootWindow(g_dpy);
    g_visual = pXDefaultVisual(g_dpy, screen);
    g_depth = 24;   /* standard TrueColor; XPutImage converts if needed */
    g_gc = pXCreateGC(g_dpy, g_root, 0, NULL);
    g_wm_delete = pXInternAtom(g_dpy, "WM_DELETE_WINDOW", 0);
    /* Screen dimensions for GetSystemMetrics / monitor APIs. */
    {
        xwattr wa;
        memset(&wa, 0, sizeof wa);
        if (pXGetWindowAttributes(g_dpy, g_root, &wa) && wa.width > 0) {
            g_screen_w = wa.width;
            g_screen_h = wa.height;
        }
    }
    wn_log(WN_LOG_DEBUG, "x11: screen %dx%d", g_screen_w, g_screen_h);
    pXLoadQueryFont = dlsym(x, "XLoadQueryFont");
    pXTextWidth = dlsym(x, "XTextWidth");
    pXCreatePixmap = dlsym(x, "XCreatePixmap");
    pXGetImage = dlsym(x, "XGetImage");
    pXFreePixmap = dlsym(x, "XFreePixmap");
    pXSetBackground = dlsym(x, "XSetBackground");
    pXMoveResizeWindow = dlsym(x, "XMoveResizeWindow");
    pXSetWMNormalHints = dlsym(x, "XSetWMNormalHints");
    pXBell = dlsym(x, "XBell");
    if (pXLoadQueryFont) {
        g_font = pXLoadQueryFont(g_dpy, "fixed");
        if (!g_font)
            wn_log(WN_LOG_WARN, "x11: font 'fixed' unavailable, text will "
                   "fall back");
    }
    return 0;
}

const wn_backend wn_x11_backend = {
    .name = "x11",
    .init = x11_init,
    .shutdown = NULL,
    .win_create = x11_win_create,
    .win_destroy = x11_win_destroy,
    .win_show = x11_win_show,
    .win_hide = x11_win_hide,
    .win_set_title = x11_win_set_title,
    .win_move_resize = x11_win_move_resize,
    .win_fixed_size = x11_win_fixed_size,
    .pump = x11_pump,
    .present = x11_present,
    .draw_text = x11_draw_text,
    .beep = x11_beep,
    .screen_size = x11_screen_size,
    .poll_fd = x11_poll_fd,
    .win_pos = x11_win_pos,
};
