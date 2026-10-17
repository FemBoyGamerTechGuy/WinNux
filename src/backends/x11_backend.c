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

/* XEvent: fixed 192-byte union; overlays below use the documented member
 * offsets for LP64 (type@0, serial@8, send_event@16, display@24,
 * window@32; event-specific data follows). */
#define XEVENT_SIZE 192

typedef struct {
    int32_t type;
    uint32_t pad4;
    uint64_t serial;
    int32_t send_event;
    uint32_t pad18;
    wnx_Display display;
    wnx_Window window;
} xany;

typedef struct {
    xany any;
    wnx_Window root, subwindow;
    uint64_t time;             /* LP64: Time is unsigned long = 8 bytes! */
    int32_t x, y;              /* 64, 68 */
    int32_t x_root, y_root;    /* 72, 76 */
    uint32_t state;            /* 80 */
    uint32_t keycode;          /* 84 — button number in XButtonEvent */
    int32_t same_screen;       /* 88 */
} xkey;                        /* XKeyEvent AND XButtonEvent shape */

typedef struct {
    xany any;
    int32_t x, y;
    uint32_t width, height;
    int32_t count;
} xexpose;

typedef struct {
    xany any;
    wnx_Window event;
    int32_t x, y;
    uint32_t width, height;
    int32_t border_width;
    wnx_Window above;
    int32_t override_redirect;
} xconfigure;

typedef struct {
    xany any;
    wnx_Window message_type;
    int32_t format;
    uint32_t pad52;
    uint64_t data[5];
} xclient;

/* XImage parameters for depth-24 ZPixmap with 32bpp storage: pixel bytes are
 * B,G,R,X — identical to a Win32 32bpp DIB, so zero conversion is needed. */
/* XImage x64 layout (pointer-aligned): width@0, height@4, xoffset@8,
 * format@12, data@16(8), byte_order@24, bitmap_unit@28,
 * bitmap_bit_order@32, bitmap_pad@36, depth@40, bytes_per_line@44,
 * bits_per_pixel@48, masks@56/64/72, funcs/padding after. */
typedef struct wnx_image {
    int32_t width, height, xoffset, format;   /* 0,4,8,12 */
    char *data;                                /* 16 */
    int32_t byte_order, bitmap_unit, bitmap_bit_order, bitmap_pad; /* 24..36 */
    int32_t depth, bytes_per_line, bits_per_pixel;                 /* 40,44,48 */
    uint32_t pad4c;
    uint64_t red_mask, green_mask, blue_mask;                      /* 56,64,72 */
    void *obf1, *obf2;                                             /* 80,88 */
    int32_t obf3;
    uint32_t pad_obf3;
    void *obf4, *obf5, *obf6, *obf7;
} wnx_XImage;

_Static_assert(offsetof(wnx_XImage, data) == 16, "XImage ABI");
_Static_assert(offsetof(wnx_XImage, byte_order) == 24, "XImage ABI");
_Static_assert(offsetof(wnx_XImage, bytes_per_line) == 44, "XImage ABI");
_Static_assert(offsetof(wnx_XImage, bits_per_pixel) == 48, "XImage ABI");

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
        /* XImage: width@8, height@12, ... data@96 (x64 offsets). */
        int ih = *(int *)((char *)xi + 4);
        int bpl = *(int *)((char *)xi + 44);
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
    pXMapWindow(g_dpy, p->xwin);
    pXFlush(g_dpy);
    b->mapped = 1;
    wn_log(WN_LOG_DEBUG, "x11: mapped window 0x%lx (pending=%d)",
           (unsigned long)p->xwin, pXPending(g_dpy));
}

static void x11_win_set_title(wn_bwin *b, const char *title)
{
    pXStoreName(g_dpy, ((x11_win_priv *)b->priv)->xwin, title);
}

static int (*pXMoveResizeWindow)(wnx_Display, wnx_Window, int, int,
                                 unsigned, unsigned);

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
    xany *a = raw;
    wn_log(WN_LOG_TRACE, "x11: event type=%d win=0x%lx", a->type,
           (unsigned long)a->window);
    switch (a->type) {
    case 12 /* Expose */: {
        xexpose *e = raw;
        wn_bwin *b = win_for(e->any.window);
        if (b)
            dispatch(b, WN_BEV_EXPOSE, e->x, e->y, (int)e->width, (int)e->height);
        break;
    }
    case 22 /* ConfigureNotify */: {
        xconfigure *c = raw;
        wn_bwin *b = win_for(c->any.window);
        if (b && (c->width != (uint32_t)b->width || c->height != (uint32_t)b->height))
            dispatch(b, WN_BEV_RESIZE, (int)c->width, (int)c->height, 0, 0);
        break;
    }
    case 2 /* KeyPress */:
    case 3 /* KeyRelease */: {
        xkey *k = raw;
        wn_bwin *b = win_for(k->any.window);
        if (!b)
            break;
        char buf[16] = { 0 };
        wnx_Atom keysym = 0;
        int n = pXLookupString(raw, buf, sizeof buf - 1, &keysym, NULL);
        dispatch(b, k->any.type == 2 ? WN_BEV_KEY : WN_BEV_KEY, k->x, k->y,
                 (int)(keysym & 0xFFFFFFFF), (int)(unsigned char)k->keycode);
        if (n > 0 && k->any.type == 2) {
            buf[n] = '\0';
            for (int i = 0; i < n; i++)
                dispatch(b, WN_BEV_TEXT, 0, 0, (unsigned char)buf[i], 0);
        }
        break;
    }
    case 4 /* ButtonPress */:
    case 5 /* ButtonRelease */: {
        xkey *k = raw;
        wn_bwin *b = win_for(k->any.window);
        /* For button events the keycode slot holds the button number. */
        if (b)
            dispatch(b, WN_BEV_MOUSE_BUTTON, k->x, k->y,
                     (k->any.type == 4) ? 1 : 0, (int)(unsigned char)k->keycode);
        break;
    }
    case 6 /* MotionNotify */: {
        xkey *k = raw;
        wn_bwin *b = win_for(k->any.window);
        if (b)
            dispatch(b, WN_BEV_MOUSE_MOVE, k->x, k->y, 0, 0);
        break;
    }
    case 33 /* ClientMessage */: {
        xclient *c = raw;
        if (g_wm_delete && c->data[0] == (uint64_t)g_wm_delete) {
            wn_bwin *b = win_for(c->any.window);
            if (b)
                dispatch(b, WN_BEV_CLOSE, 0, 0, 0, 0);
        }
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
    if (!p->xwin || !b->pixels)
        return;
    wnx_XImage *img = pXCreateImage(g_dpy, g_visual, g_depth, 2 /* ZPixmap */,
                                    0, (char *)b->pixels,
                                    (unsigned)b->width, (unsigned)b->height,
                                    32, b->stride);
    if (!img)
        return;
    img->byte_order = 0;        /* LSBFirst */
    img->bitmap_bit_order = 0;
    img->bits_per_pixel = 32;
    img->red_mask = 0xFF0000;
    img->green_mask = 0xFF00;
    img->blue_mask = 0xFF;
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
    pXLoadQueryFont = dlsym(x, "XLoadQueryFont");
    pXTextWidth = dlsym(x, "XTextWidth");
    pXCreatePixmap = dlsym(x, "XCreatePixmap");
    pXGetImage = dlsym(x, "XGetImage");
    pXFreePixmap = dlsym(x, "XFreePixmap");
    pXSetBackground = dlsym(x, "XSetBackground");
    pXMoveResizeWindow = dlsym(x, "XMoveResizeWindow");
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
    .win_set_title = x11_win_set_title,
    .win_move_resize = x11_win_move_resize,
    .pump = x11_pump,
    .present = x11_present,
    .draw_text = x11_draw_text,
};
