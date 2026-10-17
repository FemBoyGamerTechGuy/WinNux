/* wn_backend.h — windowing backend abstraction.
 *
 * NOTHING outside backends/ may touch X11 or Wayland. user32/gdi32 render
 * into per-window software framebuffers and present through this interface.
 * Selection: WINNUX_BACKEND=x11|wayland|auto (auto: Wayland if
 * WAYLAND_DISPLAY usable, else X11).
 */
#ifndef WN_BACKEND_H
#define WN_BACKEND_H

#include <stdint.h>
#include <stddef.h>

/* Window message numbers (subset, Win32 values). */
#define WN_WM_NULL        0x0000
#define WN_WM_CREATE      0x0001
#define WN_WM_DESTROY     0x0002
#define WN_WM_CLOSE       0x0010
#define WN_WM_PAINT       0x000F
#define WN_WM_SIZE        0x0005
#define WN_WM_MOVE        0x0003
#define WN_WM_TIMER       0x0113
#define WN_WM_QUIT        0x0012
#define WN_WM_KEYDOWN     0x0100
#define WN_WM_KEYUP       0x0101
#define WN_WM_CHAR        0x0102
#define WN_WM_SYSKEYDOWN  0x0104
#define WN_WM_LBUTTONDOWN 0x0201
#define WN_WM_LBUTTONUP   0x0202
#define WN_WM_MOUSEMOVE   0x0200
#define WN_WM_RBUTTONDOWN 0x0204
#define WN_WM_RBUTTONUP   0x0205

/* Structure the backend fills with raw events; user32 translates to MSG. */
typedef struct wn_backend_event {
    int type;               /* enum below */
    void *win;              /* wn_bwin* */
    int x, y;               /* mouse / size / position */
    int val, val2;          /* keysym / ascii */
} wn_backend_event;

enum wn_backend_ev {
    WN_BEV_NONE = 0,
    WN_BEV_EXPOSE,
    WN_BEV_RESIZE,
    WN_BEV_CLOSE,
    WN_BEV_KEY,
    WN_BEV_KEYUP,
    WN_BEV_MOUSE_MOVE,
    WN_BEV_MOUSE_BUTTON,
    WN_BEV_TEXT,
    WN_BEV_CONFIGURE,       /* position/size from the WM (x, y, w, h) */
};

typedef struct wn_bwin {
    void *priv;             /* backend private (X11 window etc.) */
    int width, height;      /* current client size */
    uint8_t *pixels;        /* BGRA software framebuffer (owned by user32) */
    int stride;
    void *userdata;         /* user32 window object */
    int mapped;
} wn_bwin;

typedef struct wn_backend {
    const char *name;
    int  (*init)(void);
    void (*shutdown)(void);
    wn_bwin *(*win_create)(int w, int h, const char *title, void *userdata);
    void (*win_destroy)(wn_bwin *w);
    void (*win_show)(wn_bwin *w);
    void (*win_set_title)(wn_bwin *w, const char *title);
    /* Move/resize a top-level backend window (NULL = fixed-size). */
    void (*win_move_resize)(wn_bwin *w, int x, int y, int cw, int ch);
    /* Poll for events up to timeout_ms (0 = don't block, -1 = forever).
     * Returns count of events dispatched through cb. */
    int  (*pump)(int timeout_ms);
    /* Present a BGRA framebuffer to the screen. */
    void (*present)(wn_bwin *w);
    /* Draw UTF-8 text (optional; NULL = use software font path). */
    void (*draw_text)(wn_bwin *w, int x, int y, const char *utf8, uint32_t bgra);
    /* Audible beep (MessageBeep; NULL = silent success). */
    void (*beep)(void);
    /* Screen dimensions in pixels (NULL = 800x600 guess). */
    void (*screen_size)(int *w, int *h);
    /* Pollable fd that wakes when backend events are pending
     * (-1/NULL = none; user32 falls back to periodic polling). */
    int  (*poll_fd)(void);
    /* Query a top-level window's position on screen (optional). */
    void (*win_pos)(wn_bwin *w, int *x, int *y);
} wn_backend;

/* Select and initialize the backend. Returns 0 on success. */
int  wn_backend_init(void);

/* The active backend (NULL before wn_backend_init). */
const wn_backend *wn_backend_get(void);

/* Event callback the backend invokes (implemented by user32). */
void wn_backend_event_cb(const wn_backend_event *ev);

/* Backend name that would be chosen (for --version / logs). */
const char *wn_backend_pick_name(void);

#endif /* WN_BACKEND_H */
