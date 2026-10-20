/* gdi32.c — builtin gdi32.dll: device contexts over software framebuffers.
 *
 * Rendering model: every DC targets a BGRA buffer (window backing store or
 * a DIB section). Text renders through the backend's server-side rasterizer
 * into the buffer (glyph cache), so present() always shows the final pixels.
 * COLORREF (0x00BBGGRR) converts to buffer words (0x00RRGGBB) on the way in.
 */
#include "wn_dll.h"
#include "wn_backend.h"
#include "wn_process.h"
#include "wn_handle.h"
#include "wn_wow64.h"
#include "wn_log.h"
#include "wn_util.h"
#include "wn_font.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

extern uint64_t wn_user32_paint_count(void);
extern void wn_user32_validate_paint(uint64_t hwnd);
extern wn_handle wn_user32_hwnd_of_bwin(wn_bwin *bwin);

/* --- GDI object model ---------------------------------------------------------- */

typedef enum {
    GDI_DC_WINDOW = 1,      /* targets a user32 window buffer */
    GDI_DC_MEMORY,          /* targets a DIB section bitmap or 1x1 scratch */
    GDI_BRUSH,
    GDI_PEN,
    GDI_FONT,
    GDI_BITMAP,             /* DIB section */
} gdi_kind;

typedef struct gdi_obj {
    gdi_kind kind;
    /* DC state */
    struct {
        uint64_t hwnd;              /* window DCs */
        wn_bwin *bwin;
        uint8_t *pixels;            /* memory DC target */
        int w, h, stride;
        int dib_bottom_up;          /* memory DC bitmap orientation */
        uint32_t text_color;        /* COLORREF */
        uint32_t bk_color;
        int bk_mode;                /* TRANSPARENT=1, OPAQUE=2 */
        int cur_x, cur_y;           /* MoveTo position */
        struct gdi_obj *cur_bitmap;
        struct gdi_obj *cur_font;   /* selected HFONT (NULL = default) */
        struct gdi_obj *cur_brush;  /* selected HBRUSH (NULL = white) */
        wn_handle    cur_brush_h;   /* its handle (SelectObject returns it) */
        struct gdi_obj *cur_pen;    /* selected HPEN (NULL = black) */
        wn_handle    cur_pen_h;
        int rop2;                    /* SetROP2 mode (R2_COPYPEN default) */
    } dc;
    /* object state */
    uint32_t color;                 /* brush/pen COLORREF */
    struct {                        /* bitmap */
        uint8_t *bits;
        int w, h;
        int bpp;
        int bottom_up;
    } bmp;
    struct {                        /* font (LOGFONT distilled) */
        int height;                 /* requested cell height (px, >0) */
        int weight;                 /* >=700 = bold */
        int italic;
        int ft_slot;                /* FreeType slot (>=0) or -1 = bitmap */
        char face[64];              /* informational */
    } font;
} gdi_obj;

static wn_handle gdi_new(gdi_obj *o)
{
    return wn_handle_alloc(WN_HTYPE_GFX, o);
}

static gdi_obj *gdi_get(wn_handle h, gdi_kind kind)
{
    wn_object *o = wn_handle_get(h, WN_HTYPE_GFX);
    if (!o)
        return NULL;
    gdi_obj *g = o->ptr;
    if (kind == GDI_DC_WINDOW || kind == GDI_DC_MEMORY) {
        if (g->kind != GDI_DC_WINDOW && g->kind != GDI_DC_MEMORY)
            return NULL;
    } else if (g->kind != kind) {
        return NULL;
    }
    /* Window DCs cache the pixel buffer; a backend RESIZE reallocs it.
     * Re-bind lazily on every use so a DC held across a resize can never
     * draw through a freed buffer (the "resizing breaks the app" class:
     * pointer identity + dimensions are re-read from the LIVE wn_bwin). */
    if (g->kind == GDI_DC_WINDOW && g->dc.bwin) {
        if (g->dc.pixels != g->dc.bwin->pixels ||
            g->dc.w != g->dc.bwin->width ||
            g->dc.h != g->dc.bwin->height ||
            g->dc.stride != g->dc.bwin->stride) {
            g->dc.pixels = g->dc.bwin->pixels;
            g->dc.w = g->dc.bwin->width;
            g->dc.h = g->dc.bwin->height;
            g->dc.stride = g->dc.bwin->stride;
        }
    }
    return g;
}

static uint32_t colorref_to_u32(uint32_t cr)
{
    return ((cr & 0xFF) << 16) | (cr & 0xFF00) | ((cr >> 16) & 0xFF);
}

/* --- pixel helpers ---------------------------------------------------------------- */

static void put_px(uint8_t *px, uint32_t rgb)
{
    px[0] = (uint8_t)(rgb & 0xFF);         /* B */
    px[1] = (uint8_t)((rgb >> 8) & 0xFF);  /* G */
    px[2] = (uint8_t)((rgb >> 16) & 0xFF); /* R */
}

static void fill_rect_rgb(gdi_obj *dc, int l, int t, int r, int b, uint32_t rgb)
{
    if (dc->dc.dib_bottom_up) {
        int tmp = t;
        t = dc->dc.h - b;
        b = dc->dc.h - tmp;
    }
    if (l < 0) l = 0;
    if (t < 0) t = 0;
    if (r > dc->dc.w) r = dc->dc.w;
    if (b > dc->dc.h) b = dc->dc.h;
    for (int y = t; y < b; y++) {
        uint8_t *row = dc->dc.pixels + (size_t)y * dc->dc.stride;
        for (int x = l; x < r; x++)
            put_px(row + x * 4, rgb);
    }
}

/* --- text: embedded bitmap font engine ----------------------------------------------
 *
 * Every glyph is an 8x16 1-bit cell (wn_font.h). We nearest-neighbor scale
 * to the font's cell height; bold/italic pick their atlas, with a synthesis
 * fallback (bold = OR with 1px shift, italic = 1px shear).
 */

/* effective metrics for the DC's current font */
static void font_metrics(gdi_obj *dc, int *cell_h, int *adv)
{
    gdi_obj *f = dc->dc.cur_font;
    if (f && f->font.ft_slot >= 0 && wn_ft_available()) {
        int asc, desc, hgt, avg;
        wn_ft_metrics(f->font.ft_slot, &asc, &desc, &hgt, &avg);
        *cell_h = hgt;
        *adv = avg;
        return;
    }
    int h = WN_FONT_CELL_H;
    if (f && f->font.height > 0)
        h = f->font.height;
    if (h < 5)
        h = 5;
    *cell_h = h;
    *adv = (h * WN_FONT_ADVANCE + WN_FONT_CELL_H - 1) / WN_FONT_CELL_H;
}

static void draw_glyph_cell(gdi_obj *dc, const unsigned char *rows,
                            int x, int y, int cell_h, uint32_t rgb)
{
    for (int py = 0; py < cell_h; py++) {
        int sy = py * WN_FONT_CELL_H / cell_h;
        if (sy >= WN_FONT_CELL_H)
            sy = WN_FONT_CELL_H - 1;
        unsigned char row = rows[sy];
        int dy = dc->dc.dib_bottom_up ? dc->dc.h - 1 - (y + py) : y + py;
        if (dy < 0 || dy >= dc->dc.h)
            continue;
        uint8_t *line = dc->dc.pixels + (size_t)dy * dc->dc.stride;
        for (int px = 0; px < WN_FONT_ADVANCE; px++) {
            if (!(row & (0x80 >> px)))
                continue;
            int sx = px;
            int dx = x + px;
            if (dx < 0 || dx >= dc->dc.w)
                continue;
            (void)sx;
            put_px(line + (size_t)dx * 4, rgb);
        }
    }
}

/* map one UTF-16 codepoint to atlas rows (never NULL: missing box) */
static const unsigned char *glyph_rows(uint32_t cp, gdi_obj *dc)
{
    int bold = dc->dc.cur_font && dc->dc.cur_font->font.weight >= 700;
    int ital = dc->dc.cur_font && dc->dc.cur_font->font.italic;
    const unsigned char *g = wn_font_glyph(cp, bold, ital);
    if (g)
        return g;
    /* synthesis fallback: base glyph + style transform is approximated by
     * drawing the plain glyph twice with 1px offset (bold) */
    if ((bold || ital) && cp <= 0xFF) {
        g = wn_font_glyph(cp, 0, 0);
        if (g)
            return g;
    }
    return wn_font_missing();
}

/* fwd: default font object (defined below) */
static gdi_obj *default_font(gdi_obj *dc);

/* UTF-16 text draw; returns the x advance consumed.
 *
 * FreeType path (when the DC font resolved to a slot): alpha-blended
 * subpixel-advancing glyphs with per-codepoint positioning; surrogate
 * pairs combine into one codepoint. Falls back to the bitmap atlas. */
static int draw_text16(gdi_obj *dc, int x, int y,
                       const uint16_t *s, size_t n)
{
    uint32_t rgb = colorref_to_u32(dc->dc.text_color);
    uint32_t bk = colorref_to_u32(dc->dc.bk_color);
    int cell_h, adv;
    font_metrics(dc, &cell_h, &adv);
    gdi_obj *fobj = dc->dc.cur_font ? dc->dc.cur_font : default_font(dc);
    int slot = fobj && fobj->kind == GDI_FONT ? fobj->font.ft_slot : -1;
    if (slot >= 0 && wn_ft_available()) {
        int asc, desc, hgt, avg;
        wn_ft_metrics(slot, &asc, &desc, &hgt, &avg);
        int baseline = y + asc;
        int fake_bold = wn_ft_slot_bold(slot);
        if (dc->dc.bk_mode == 2 /*OPAQUE*/)
            fill_rect_rgb(dc, x, y, x + (int)n * avg, y + hgt, bk);
        int cx = x;
        for (size_t i = 0; i < n; i++) {
            if (!s[i])
                break;
            uint32_t cp = s[i];
            if (cp >= 0xD800 && cp < 0xDC00 && i + 1 < n &&
                s[i + 1] >= 0xDC00 && s[i + 1] < 0xE000) {
                cp = 0x10000 + ((cp - 0xD800) << 10) + (s[i + 1] - 0xDC00);
                i++;
            }
            const wn_ft_glyph_t *g = wn_ft_glyph(slot, cp);
            if (g) {
                int gx = cx + g->left;
                int gy = baseline - g->top;
                for (int py = 0; py < g->h; py++) {
                    int dy = dc->dc.dib_bottom_up
                                ? dc->dc.h - 1 - (gy + py) : gy + py;
                    if (dy < 0 || dy >= dc->dc.h)
                        continue;
                    uint8_t *line = dc->dc.pixels +
                                    (size_t)dy * dc->dc.stride;
                    for (int px = 0; px < g->w; px++) {
                        int dx = gx + px;
                        if (dx < 0 || dx >= dc->dc.w)
                            continue;
                        uint8_t a = g->alpha[(size_t)py * g->w + px];
                        if (fake_bold && px + 1 < g->w) {
                            int a2 = g->alpha[(size_t)py * g->w + px + 1];
                            if (a2 > a)
                                a = a2;
                        }
                        if (!a)
                            continue;
                        uint8_t *dst = line + (size_t)dx * 4;
                        dst[0] = (uint8_t)((dst[0] * (255 - a) +
                                 (rgb & 0xFF) * a) / 255);
                        dst[1] = (uint8_t)((dst[1] * (255 - a) +
                                 ((rgb >> 8) & 0xFF) * a) / 255);
                        dst[2] = (uint8_t)((dst[2] * (255 - a) +
                                 ((rgb >> 16) & 0xFF) * a) / 255);
                    }
                }
                cx += g->adv_x;
            } else {
                cx += avg;
            }
        }
        return cx - x;
    }
    int bold = dc->dc.cur_font && dc->dc.cur_font->font.weight >= 700;
    int cx = x;
    for (size_t i = 0; i < n; i++) {
        if (!s[i])
            break;
        const unsigned char *g = glyph_rows(s[i], dc);
        if (dc->dc.bk_mode == 2 /*OPAQUE*/)
            fill_rect_rgb(dc, cx, y, cx + adv, y + cell_h, bk);
        draw_glyph_cell(dc, g, cx, y, cell_h, rgb);
        if (bold) {
            /* bold synthesis when only the book glyph exists */
            if (s[i] <= 0xFF && !wn_font_glyph(s[i], 1, 0) &&
                wn_font_glyph(s[i], 0, 0))
                draw_glyph_cell(dc, g, cx + 1, y, cell_h, rgb);
        }
        cx += adv;
    }
    return cx - x;
}

/* Default DC font lazily materialized so cur_font is always valid. */
static gdi_obj *default_font(gdi_obj *dc)
{
    static gdi_obj *def;
    (void)dc;
    if (!def) {
        def = wn_xcalloc(1, sizeof *def);
        def->kind = GDI_FONT;
        def->font.height = WN_FONT_CELL_H;
        def->font.weight = 400;
        def->font.ft_slot = wn_ft_select("MS Sans Serif", 16, 0, 0);
        snprintf(def->font.face, sizeof def->font.face, "System");
    }
    return def;
}

static void draw_text_into(gdi_obj *dc, int x, int y, const char *s, size_t n)
{
    /* ANSI entry: treat bytes as Latin-1 (maps onto the atlas directly). */
    uint16_t w[4096];
    size_t m = n < 4096 ? n : 4096;
    for (size_t i = 0; i < m; i++)
        w[i] = (unsigned char)s[i];
    draw_text16(dc, x, y, w, m);
}

/* --- window DCs ---------------------------------------------------------------------- */

/* PAINTSTRUCT x64: hdc@0(8), fErase@8(4), rcPaint@0xC(16), fRestore@0x1C,
 * fIncUpdate@0x20, rgbReserved@0x24[32] — 68 bytes. */

WN_API wn_handle g32_BeginPaint(wn_abiword hwnd, void *ps)
{
    wn_object *wo = wn_handle_get((wn_handle)(uintptr_t)hwnd, WN_HTYPE_GFX);
    if (!wo || !ps)
        return (wn_handle)0;
    extern void wn_user32_paint_rect(uint64_t hwnd, int *l, int *t, int *r, int *b);
    int l = 0, t = 0, r = 0, b = 0;
    wn_user32_paint_rect(hwnd, &l, &t, &r, &b);

    gdi_obj *dc = wn_xcalloc(1, sizeof *dc);
    dc->kind = GDI_DC_WINDOW;
    extern wn_bwin *wn_user32_bwin_of(uint64_t hwnd);
    dc->dc.hwnd = hwnd;
    dc->dc.bwin = wn_user32_bwin_of(hwnd);
    if (!dc->dc.bwin) {
        free(dc);
        return (wn_handle)0;
    }
    dc->dc.pixels = dc->dc.bwin->pixels;
    dc->dc.w = dc->dc.bwin->width;
    dc->dc.h = dc->dc.bwin->height;
    dc->dc.stride = dc->dc.bwin->stride;
    dc->dc.text_color = 0x00000000;   /* black */
    dc->dc.bk_color = 0x00FFFFFF;     /* white */
    dc->dc.bk_mode = 2;               /* OPAQUE */
    wn_handle hdc = gdi_new(dc);

    memset(ps, 0, 68);
    /* PAINTSTRUCT.hdc is CALLER-width (4 bytes for an i386 guest): the
     * 8-byte host handle store smashed fErase + rc fields. */
    if (wn_wow64_guest32())
        *(uint32_t *)(void *)ps = (uint32_t)(uintptr_t)hdc;
    else
        *(wn_handle *)(void *)ps = hdc;
    *(uint32_t *)(void *)((uint8_t *)ps + 8) = 1;   /* fErase */
    int32_t *rc = (int32_t *)((uint8_t *)ps + 0xC);
    rc[0] = l; rc[1] = t; rc[2] = r; rc[3] = b;
    return hdc;
}

WN_API int32_t g32_EndPaint(wn_abiword hwnd, const void *ps)
{
    (void)ps;
    wn_object *wo = wn_handle_get((wn_handle)(uintptr_t)hwnd, WN_HTYPE_GFX);
    if (!wo)
        return 0;
    const wn_backend *be = wn_backend_get();
    extern wn_bwin *wn_user32_bwin_of(uint64_t hwnd);
    wn_bwin *b = wn_user32_bwin_of(hwnd);
    if (be && be->present && b)
        be->present(b);
    wn_user32_validate_paint(hwnd);
    return 1;
}

WN_API wn_handle g32_GetDC(wn_abiword hwnd)
{
    extern wn_bwin *wn_user32_bwin_of(uint64_t hwnd);
    wn_bwin *b = wn_user32_bwin_of(hwnd);
    if (!b)
        return (wn_handle)0;
    gdi_obj *dc = wn_xcalloc(1, sizeof *dc);
    dc->kind = GDI_DC_WINDOW;
    dc->dc.hwnd = hwnd;
    dc->dc.bwin = b;
    dc->dc.pixels = b->pixels;
    dc->dc.w = b->width;
    dc->dc.h = b->height;
    dc->dc.stride = b->stride;
    dc->dc.text_color = 0;
    dc->dc.bk_color = 0x00FFFFFF;
    dc->dc.bk_mode = 2;
    return gdi_new(dc);
}

WN_API int32_t g32_ReleaseDC(wn_abiword hwnd, wn_handle hdc)
{
    (void)hwnd;
    gdi_obj *dc = gdi_get(hdc, GDI_DC_WINDOW);
    if (!dc)
        return 0;
    wn_handle_close(hdc);
    return 1;
}

/* --- memory DCs + DIB sections ----------------------------------------------------------- */

static WN_API wn_handle g32_CreateCompatibleDC(wn_handle hdc)
{
    (void)hdc;
    gdi_obj *dc = wn_xcalloc(1, sizeof *dc);
    dc->kind = GDI_DC_MEMORY;
    static uint8_t scratch[4];
    dc->dc.pixels = scratch;
    dc->dc.w = 1;
    dc->dc.h = 1;
    dc->dc.stride = 4;
    dc->dc.text_color = 0;
    dc->dc.bk_color = 0x00FFFFFF;
    dc->dc.bk_mode = 2;
    return gdi_new(dc);
}

static WN_API int32_t g32_DeleteDC(wn_handle hdc)
{
    gdi_obj *dc = gdi_get(hdc, GDI_DC_MEMORY);
    if (!dc)
        return 0;
    wn_handle_close(hdc);
    return 1;
}

/* BITMAPINFOHEADER: biSize@0(4), biWidth@4, biHeight@8, biPlanes@0xC,
 * biBitCount@0xE, ... The header is followed by the palette when bpp<=8
 * (unsupported here; 24/32bpp only). */
static WN_API wn_handle g32_CreateDIBSection(wn_handle hdc, const void *bmi,
                                             uint32_t usage, void **bits,
                                             void *section, uint32_t offset)
{
    (void)hdc; (void)usage; (void)section; (void)offset;
    if (!bmi || !bits)
        return (wn_handle)0;
    const uint8_t *hdr = bmi;
    int w = *(const int32_t *)(const void *)(hdr + 4);
    int h = *(const int32_t *)(const void *)(hdr + 8);
    uint16_t bpp = *(const uint16_t *)(const void *)(hdr + 0xE);
    if (w <= 0 || h == 0 || (bpp != 24 && bpp != 32)) {
        wn_log(WN_LOG_WARN, "gdi32: CreateDIBSection unsupported (w=%d h=%d "
               "bpp=%u)", w, h, bpp);
        wn_last_error_set(WN_ERR_INVALID_PARAMETER);
        return (wn_handle)0;
    }
    int bottom_up = h > 0;
    int ah = h < 0 ? -h : h;
    size_t size = (size_t)w * ah * (bpp / 8);
    gdi_obj *bmp = wn_xcalloc(1, sizeof *bmp);
    bmp->kind = GDI_BITMAP;
    bmp->bmp.bits = wn_xmalloc(size + 16);
    memset(bmp->bmp.bits, 0, size);
    bmp->bmp.w = w;
    bmp->bmp.h = ah;
    bmp->bmp.bpp = bpp;
    bmp->bmp.bottom_up = bottom_up;
    *bits = bmp->bmp.bits;
    return gdi_new(bmp);
}

static WN_API wn_handle g32_SelectObject(wn_handle hdc, wn_handle obj)
{
    gdi_obj *dc = gdi_get(hdc, GDI_DC_MEMORY);
    if (!dc)
        return (wn_handle)0;
    gdi_obj *o = wn_handle_get(obj, WN_HTYPE_GFX) ?
                 ((wn_object *)wn_handle_get(obj, WN_HTYPE_GFX))->ptr : NULL;
    if (!o)
        return (wn_handle)0;
    if (o->kind == GDI_FONT) {
        wn_handle old = (wn_handle)(uintptr_t)dc->dc.cur_font;
        if (!old)
            old = (wn_handle)(uintptr_t)default_font(dc);
        dc->dc.cur_font = o;
        return old;
    }
    if (o->kind != GDI_BITMAP) {
        if (o->kind == GDI_BRUSH) {
            wn_handle old = dc->dc.cur_brush_h;
            dc->dc.cur_brush = o;
            dc->dc.cur_brush_h = obj;
            return old;
        }
        if (o->kind == GDI_PEN) {
            wn_handle old = dc->dc.cur_pen_h;
            dc->dc.cur_pen = o;
            dc->dc.cur_pen_h = obj;
            return old;
        }
        return (wn_handle)0;
    }
    wn_handle old = (wn_handle)0;
    if (dc->dc.cur_bitmap)
        old = (wn_handle)0;   /* previous bitmap tracking minimal */
    dc->dc.cur_bitmap = o;
    dc->dc.pixels = o->bmp.bits;
    dc->dc.w = o->bmp.w;
    dc->dc.h = o->bmp.h;
    dc->dc.stride = o->bmp.w * (o->bmp.bpp / 8);
    dc->dc.dib_bottom_up = o->bmp.bottom_up;
    return old;
}

static WN_API int32_t g32_DeleteObject(wn_handle obj)
{
    wn_object *o = wn_handle_get(obj, WN_HTYPE_GFX);
    if (!o)
        return 0;
    return wn_handle_close(obj);
}

/* --- drawing ops --------------------------------------------------------------------------- */

WN_API int32_t g32_FillRect(wn_handle hdc, const void *rect, wn_handle brush)
{
    gdi_obj *dc = gdi_get(hdc, GDI_DC_WINDOW);
    if (!dc || !rect)
        return 0;
    gdi_obj *br = gdi_get(brush, GDI_BRUSH);
    uint32_t cr = br ? br->color : 0x00FFFFFF;
    const int32_t *r = rect;
    fill_rect_rgb(dc, r[0], r[1], r[2], r[3], colorref_to_u32(cr));
    return 1;
}

WN_API wn_handle g32_CreateSolidBrush(uint32_t color)
{
    gdi_obj *br = wn_xcalloc(1, sizeof *br);
    br->kind = GDI_BRUSH;
    br->color = color;
    return gdi_new(br);
}

static WN_API wn_handle g32_CreatePen(uint32_t style, uint32_t width, uint32_t color)
{
    (void)style; (void)width;
    gdi_obj *pen = wn_xcalloc(1, sizeof *pen);
    pen->kind = GDI_PEN;
    pen->color = color;
    return gdi_new(pen);
}

/* CreateBrushIndirect: LOGBRUSH {lbStyle@0, lbColor@4, lbHatch@8} — all
 * fixed-width fields, same layout in i386 and x64 guests. Hatched/hollow
 * styles are drawn solid (logged); the wizard's fills are BS_SOLID. */
static WN_API wn_handle g32_CreateBrushIndirect(const void *logbrush)
{
    if (!logbrush)
        return (wn_handle)0;
    const uint32_t *lb = logbrush;
    if (lb[0] != 0 /*BS_SOLID*/)
        wn_log(WN_LOG_DEBUG, "gdi32: CreateBrushIndirect style %u drawn "
               "as solid", lb[0]);
    gdi_obj *br = wn_xcalloc(1, sizeof *br);
    br->kind = GDI_BRUSH;
    br->color = lb[1];
    return gdi_new(br);
}

/* CreatePenIndirect: LOGPEN {lopnStyle@0, lopnWidth(POINT)@4, lopnColor@12}
 * — fixed-width fields, identical layout in both guest word sizes. */
static WN_API wn_handle g32_CreatePenIndirect(const void *logpen)
{
    if (!logpen)
        return (wn_handle)0;
    const uint32_t *lp = logpen;
    if (lp[0] != 0 /*PS_SOLID*/)
        wn_log(WN_LOG_DEBUG, "gdi32: CreatePenIndirect style %u drawn "
               "as solid", lp[0]);
    gdi_obj *pen = wn_xcalloc(1, sizeof *pen);
    pen->kind = GDI_PEN;
    pen->color = lp[3];
    return gdi_new(pen);
}

/* PatBlt: BLACKNESS/WHITENESS paint directly; PATCOPY (and friends, logged)
 * use the selected brush — VCL's TCanvas.Brush — defaulting to white. */
static WN_API int32_t g32_PatBlt(wn_handle hdc, int32_t x, int32_t y,
                                 int32_t w, int32_t h, uint32_t rop)
{
    gdi_obj *dc = gdi_get(hdc, GDI_DC_WINDOW);
    if (!dc || w <= 0 || h <= 0)
        return 0;
    uint32_t rgb;
    if (rop == 0x00000042u /*BLACKNESS*/)
        rgb = 0x000000;
    else if (rop == 0x00FF0062u /*WHITENESS*/)
        rgb = 0xFFFFFF;
    else {
        rgb = dc->dc.cur_brush ? colorref_to_u32(dc->dc.cur_brush->color)
                                : 0xFFFFFF;
        if (rop != 0x00F00021u /*PATCOPY*/)
            wn_log(WN_LOG_DEBUG, "gdi32: PatBlt rop 0x%x approximated "
                   "as PATCOPY", rop);
    }
    fill_rect_rgb(dc, x, y, x + w, y + h, rgb);
    return 1;
}

/* SetROP2: record the drawing mode (R2_COPYPEN default). The raster ops
 * honor R2_COPY/R2_XOR semantics at draw time; this stores per-DC state. */
static WN_API int32_t g32_SetROP2(wn_handle hdc, int32_t mode)
{
    gdi_obj *dc = gdi_get(hdc, GDI_DC_WINDOW);
    if (!dc || mode < 1 || mode > 16)
        return 0;
    int old = dc->dc.rop2 ? dc->dc.rop2 : 13 /*R2_COPYPEN*/;
    dc->dc.rop2 = mode;
    return old;
}

static WN_API int32_t g32_UnrealizeObject(wn_handle obj)
{
    (void)obj;   /* re-realization only matters for palettes/brush origins */
    return 1;
}

/* GetObjectA: the object descriptor. BITMAP's trailing bmBits pointer makes
 * the struct 20 (i386) / 24 (x64) bytes; LOGFONTA/LOGBRUSH/LOGPEN are all
 * fixed-width (60/12/16 in both). Callers ask for what they will read. */
static WN_API int32_t g32_GetObjectA(wn_handle obj, int32_t cb, void *buf)
{
    wn_object *wo = wn_handle_get(obj, WN_HTYPE_GFX);
    if (!wo || !wo->ptr)
        return 0;
    gdi_obj *o = wo->ptr;
    const int g32 = wn_wow64_guest32();
    if (o->kind == GDI_BITMAP) {
        int need = g32 ? 20 : 24;
        if (!buf)
            return need;
        if (cb < need)
            return 0;
        memset(buf, 0, (size_t)need);
        uint8_t *b = buf;
        uint32_t *w32 = (uint32_t *)buf;
        w32[1] = (uint32_t)o->bmp.w;                 /* bmWidth */
        w32[2] = (uint32_t)o->bmp.h;                 /* bmHeight */
        w32[3] = (uint32_t)(o->bmp.w * (o->bmp.bpp / 8)); /* bmWidthBytes */
        *(uint16_t *)(void *)(b + 0x10) = 1;         /* bmPlanes */
        *(uint16_t *)(void *)(b + 0x12) = (uint16_t)o->bmp.bpp;
        return need;
    }
    if (o->kind == GDI_BRUSH) {
        if (!buf)
            return 12;
        if (cb < 12)
            return 0;
        uint32_t *lb = buf;   /* LOGBRUSH: style, color, hatch */
        lb[0] = 0;            /* BS_SOLID */
        lb[1] = o->color;
        lb[2] = 0;
        return 12;
    }
    if (o->kind == GDI_PEN) {
        if (!buf)
            return 16;
        if (cb < 16)
            return 0;
        uint32_t *lp = buf;   /* LOGPEN: style, width POINT, color */
        lp[0] = 0;            /* PS_SOLID */
        lp[1] = 1; lp[2] = 0; /* POINT {1, 0} */
        lp[3] = o->color;
        return 16;
    }
    if (o->kind == GDI_FONT) {
        if (!buf)
            return 60;
        if (cb < 60)
            return 0;
        memset(buf, 0, 60);
        uint8_t *b = buf;
        *(int32_t *)(void *)(b + 0) = o->font.height;   /* lfHeight */
        *(int32_t *)(void *)(b + 0x10) = o->font.weight; /* lfWeight */
        b[0x14] = (uint8_t)o->font.italic;               /* lfItalic */
        b[0x17] = 1;                                      /* ANSI charset */
        snprintf((char *)b + 0x1C, 32, "%.31s", o->font.face);
        return 60;
    }
    return 0;
}

/* --- cross-DLL DIB blit (icon drawing) --------------------------------------
 * user32's DrawIconEx resolves the icon and hands the raw RT_ICON DIB here;
 * gdi32 owns the DC pixel writer. 24/32bpp, top-down or bottom-up, scaled
 * to (cx,cy) with nearest neighbor. Non-32bpp icon DIBs carry XOR+AND
 * halves — the image is the half with actual pixels. */
int wn_gdi_draw_dib(wn_handle hdc, int x, int y, int cx, int cy,
                    const uint8_t *dib, uint32_t dib_size)
{
    gdi_obj *dc = gdi_get(hdc, GDI_DC_WINDOW);
    if (!dc || !dib || dib_size < 40 || cx <= 0 || cy <= 0)
        return 0;
    uint32_t bsize;
    memcpy(&bsize, dib + 0, 4);
    if (bsize < 40)
        return 0;
    int32_t bw, bh;
    memcpy(&bw, dib + 4, 4);
    memcpy(&bh, dib + 8, 4);
    uint16_t bpp;
    memcpy(&bpp, dib + 0xE, 2);
    if ((bpp != 24 && bpp != 32) || bw <= 0 || bh == 0) {
        wn_log(WN_LOG_WARN, "gdi32: icon DIB unsupported (w=%d h=%d bpp=%u)",
               (int)bw, (int)bh, bpp);
        return 0;
    }
    int bottom_up = bh > 0;
    int ah = bh < 0 ? -bh : bh;
    int rows = bpp == 32 ? ah : ah / 2;   /* non-32bpp icons: XOR half */
    if (rows <= 0)
        return 0;
    int pxbytes = bpp / 8;
    size_t rowbytes = (((size_t)bw * (size_t)pxbytes) + 3) & ~(size_t)3;
    if (40 + rowbytes * (size_t)rows > dib_size) {
        wn_log(WN_LOG_WARN, "gdi32: icon DIB truncated (%u bytes)", dib_size);
        return 0;
    }
    const uint8_t *pix = dib + 40;
    for (int dy = 0; dy < cy; dy++) {
        int sy = rows * dy / cy;
        int syy = bottom_up ? rows - 1 - sy : sy;
        const uint8_t *src = pix + (size_t)syy * rowbytes;
        int dyd = y + dy;
        if (dyd < 0 || dyd >= dc->dc.h)
            continue;
        int dyrow = dc->dc.dib_bottom_up ? dc->dc.h - 1 - dyd : dyd;
        uint8_t *dst = dc->dc.pixels + (size_t)dyrow * dc->dc.stride;
        for (int dx = 0; dx < cx; dx++) {
            int sx = bw * dx / cx;
            const uint8_t *sp = src + (size_t)sx * pxbytes;
            if (bpp == 32 && sp[3] == 0)
                continue;            /* fully transparent pixel: skip */
            int dxd = x + dx;
            if (dxd < 0 || dxd >= dc->dc.w)
                continue;
            uint8_t *dp = dst + (size_t)dxd * 4;
            dp[0] = sp[0]; dp[1] = sp[1]; dp[2] = sp[2]; dp[3] = 0xFF;
        }
    }
    return 1;
}

/* Cross-DLL (see wn_dll.h): a loadable HBITMAP from a raw RT_BITMAP-style
 * DIB (BITMAPINFOHEADER + pixels). 24/32bpp direct; 4/8bpp through the
 * inline palette. The object is normalized to 32bpp top-down storage so
 * every draw path (BitBlt, StretchBlt later) sees one format. */
wn_handle wn_gdi_bitmap_from_dib(const uint8_t *dib, uint32_t dib_size)
{
    if (!dib || dib_size < 40)
        return (wn_handle)0;
    uint32_t bsize;
    memcpy(&bsize, dib + 0, 4);
    if (bsize < 40)
        return (wn_handle)0;
    int32_t bw, bh;
    memcpy(&bw, dib + 4, 4);
    memcpy(&bh, dib + 8, 4);
    uint16_t bpp;
    memcpy(&bpp, dib + 0xE, 2);
    if ((bpp != 24 && bpp != 32 && bpp != 8 && bpp != 4) ||
        bw <= 0 || bh == 0) {
        wn_log(WN_LOG_WARN, "gdi32: RT_BITMAP DIB unsupported (w=%d h=%d "
               "bpp=%u)", (int)bw, (int)bh, bpp);
        return (wn_handle)0;
    }
    int bottom_up = bh > 0;
    int rows = bh < 0 ? -bh : bh;
    if ((uint64_t)bw > 32768 || (uint64_t)rows > 32768)
        return (wn_handle)0;
    size_t pix_off = 40;
    const uint8_t *pal = NULL;
    int pal_colors = 0;
    size_t rowbytes;
    if (bpp <= 8) {
        uint32_t clr_used;
        memcpy(&clr_used, dib + 32, 4);   /* biClrUsed */
        pal_colors = (int)(clr_used ? clr_used : (1u << bpp));
        pal = dib + 40;
        pix_off = 40 + (size_t)pal_colors * 4;
        rowbytes = bpp == 4 ? ((((size_t)bw + 1) / 2) + 3) & ~(size_t)3
                           : (((size_t)bw) + 3) & ~(size_t)3;
    } else {
        rowbytes = (((size_t)bw * (size_t)(bpp / 8)) + 3) & ~(size_t)3;
    }
    if (pix_off + rowbytes * (size_t)rows > dib_size) {
        wn_log(WN_LOG_WARN, "gdi32: RT_BITMAP DIB truncated (%u bytes)",
               dib_size);
        return (wn_handle)0;
    }
    gdi_obj *bmp = wn_xcalloc(1, sizeof *bmp);
    if (!bmp)
        return (wn_handle)0;
    bmp->kind = GDI_BITMAP;
    bmp->bmp.bits = wn_xcalloc((size_t)bw * (size_t)rows, 4);
    if (!bmp->bmp.bits) {
        free(bmp);
        return (wn_handle)0;
    }
    bmp->bmp.w = bw;
    bmp->bmp.h = rows;
    bmp->bmp.bpp = 32;
    bmp->bmp.bottom_up = 0;   /* normalized below */
    const uint8_t *src = dib + pix_off;
    for (int i = 0; i < rows; i++) {
        int drow = bottom_up ? rows - 1 - i : i;
        const uint8_t *sp = src + (size_t)i * rowbytes;
        uint8_t *dp = bmp->bmp.bits + (size_t)drow * (size_t)bw * 4;
        for (int x = 0; x < bw; x++) {
            uint8_t *d = dp + (size_t)x * 4;
            if (bpp == 24 || bpp == 32) {
                const uint8_t *sd = sp + (size_t)x * (bpp / 8);
                d[0] = sd[0]; d[1] = sd[1]; d[2] = sd[2]; d[3] = 0xFF;
            } else {
                int idx;
                if (bpp == 4) {
                    uint8_t byte = sp[x >> 1];
                    idx = (x & 1) ? (byte & 0x0F) : (byte >> 4);
                } else {
                    idx = sp[x];
                }
                if (idx >= pal_colors)
                    idx = pal_colors ? pal_colors - 1 : 0;
                const uint8_t *q = pal + (size_t)idx * 4;  /* B G R res */
                d[0] = q[0]; d[1] = q[1]; d[2] = q[2]; d[3] = 0xFF;
            }
        }
    }
    return gdi_new(bmp);
}

/* Cross-DLL helper (see wn_dll.h): a plain 32bpp bitmap object with real
 * pixel storage — the shape CreateDIBSection hands out, usable by
 * user32's LoadBitmap (OBM_* system bitmaps). Pixels are zero-initialized. */
wn_handle wn_bitmap_handle_alloc(int w, int h)
{
    if (w <= 0 || h <= 0 || w > 32768 || h > 32768)
        return (wn_handle)0;
    gdi_obj *bmp = wn_xcalloc(1, sizeof *bmp);
    if (!bmp)
        return (wn_handle)0;
    bmp->kind = GDI_BITMAP;
    bmp->bmp.bits = wn_xcalloc((size_t)w * (size_t)h, 4);
    if (!bmp->bmp.bits) {
        free(bmp);
        return (wn_handle)0;
    }
    bmp->bmp.w = w;
    bmp->bmp.h = h;
    bmp->bmp.bpp = 32;
    bmp->bmp.bottom_up = 0;
    return gdi_new(bmp);
}

/* CreateCompatibleBitmap: a bitmap matching the DC's format. Every WinNux
 * drawing surface is 32bpp BGRA-style, so the format is independent of the
 * DC; the size comes from the caller (the Inno wizard builds 32x32 buffers
 * for its icon, and a NULL return here made VCL raise EOutOfResources). */
static WN_API wn_handle g32_CreateCompatibleBitmap(wn_handle hdc,
                                                   int32_t w, int32_t h)
{
    (void)hdc;
    wn_handle r = wn_bitmap_handle_alloc(w, h);
    if (!r)
        wn_last_error_set(WN_ERR_INVALID_PARAMETER);
    return r;
}

static WN_API wn_handle g32_GetStockObject(int32_t idx)
{
    /* Stock objects: WHITE_BRUSH 0, LTGRAY 1, GRAY 2, DKGRAY 3, BLACK_BRUSH 4,
     * NULL_BRUSH 5, WHITE_PEN 6, BLACK_PEN 7, NULL_PEN 8, SYSTEM_FONT 13... */
    static wn_handle stock[32];
    static int inited;
    if (!inited) {
        static const uint32_t brush_colors[] = {
            0x00FFFFFF, 0x00C0C0C0, 0x00808080, 0x00404040, 0x00000000,
        };
        for (int i = 0; i < 5; i++) {
            gdi_obj *br = wn_xcalloc(1, sizeof *br);
            br->kind = GDI_BRUSH;
            br->color = brush_colors[i];
            stock[i] = gdi_new(br);
        }
        for (int i = 6; i <= 8; i++) {
            gdi_obj *pen = wn_xcalloc(1, sizeof *pen);
            pen->kind = GDI_PEN;
            pen->color = (i == 6) ? 0x00FFFFFF : 0;
            stock[i] = gdi_new(pen);
        }
        for (int i = 13; i <= 15; i++) {
            gdi_obj *f = wn_xcalloc(1, sizeof *f);
            f->kind = GDI_FONT;
            stock[i] = gdi_new(f);
        }
        inited = 1;
    }
    if (idx < 0 || idx > 15 || !stock[idx])
        return (wn_handle)0;
    return stock[idx];
}

WN_API uint32_t g32_SetTextColor(wn_handle hdc, uint32_t color)
{
    gdi_obj *dc = gdi_get(hdc, GDI_DC_WINDOW);
    if (!dc)
        return 0;
    uint32_t old = dc->dc.text_color;
    dc->dc.text_color = color;
    return old;
}

WN_API uint32_t g32_SetBkColor(wn_handle hdc, uint32_t color)
{
    gdi_obj *dc = gdi_get(hdc, GDI_DC_WINDOW);
    if (!dc)
        return 0;
    uint32_t old = dc->dc.bk_color;
    dc->dc.bk_color = color;
    return old;
}

WN_API int32_t g32_SetBkMode(wn_handle hdc, int32_t mode)
{
    gdi_obj *dc = gdi_get(hdc, GDI_DC_WINDOW);
    if (!dc)
        return 0;
    int old = dc->dc.bk_mode;
    dc->dc.bk_mode = mode;
    return old;
}

WN_API int32_t g32_TextOutA(wn_handle hdc, int x, int y,
                                   const char *s, int32_t count)
{
    gdi_obj *dc = gdi_get(hdc, GDI_DC_WINDOW);
    if (!dc || !s)
        return 0;
    size_t n = count < 0 ? strlen(s) : (size_t)count;
    if (!dc->dc.cur_font)
        dc->dc.cur_font = default_font(dc);
    draw_text_into(dc, x, y, s, n);
    return 1;
}

static WN_API int32_t g32_TextOutW(wn_handle hdc, int x, int y,
                                   const uint16_t *s, int32_t count)
{
    gdi_obj *dc = gdi_get(hdc, GDI_DC_WINDOW);
    if (!dc || !s)
        return 0;
    size_t n = 0;
    if (count < 0) {
        while (s[n] && n < 65536)
            n++;
    } else {
        n = (size_t)count;
    }
    if (!dc->dc.cur_font)
        dc->dc.cur_font = default_font(dc);
    draw_text16(dc, x, y, s, n);
    return 1;
}

WN_API uint32_t g32_SetPixel(wn_handle hdc, int32_t x, int32_t y, uint32_t color)
{
    gdi_obj *dc = gdi_get(hdc, GDI_DC_WINDOW);
    if (!dc || x < 0 || y < 0 || x >= dc->dc.w || y >= dc->dc.h)
        return 0;
    int dy = dc->dc.dib_bottom_up ? dc->dc.h - 1 - y : y;
    uint8_t *px = dc->dc.pixels + (size_t)dy * dc->dc.stride + (size_t)x * 4;
    uint32_t old = px[2] | (px[1] << 8) | (px[0] << 16);
    put_px(px, colorref_to_u32(color));
    return old;
}

static WN_API int32_t g32_MoveToEx(wn_handle hdc, int32_t x, int32_t y, void *pt)
{
    gdi_obj *dc = gdi_get(hdc, GDI_DC_WINDOW);
    if (!dc)
        return 0;
    if (pt) {
        int32_t *p = pt;
        p[0] = dc->dc.cur_x;
        p[1] = dc->dc.cur_y;
    }
    dc->dc.cur_x = x;
    dc->dc.cur_y = y;
    return 1;
}

static WN_API int32_t g32_LineTo(wn_handle hdc, int32_t x, int32_t y)
{
    gdi_obj *dc = gdi_get(hdc, GDI_DC_WINDOW);
    if (!dc)
        return 0;
    uint32_t rgb = colorref_to_u32(dc->dc.text_color);  /* use text color as pen (simplification) */
    int x0 = dc->dc.cur_x, y0 = dc->dc.cur_y;
    int dx = x - x0, dy = y - y0;
    int sx = dx > 0 ? 1 : -1, sy = dy > 0 ? 1 : -1;
    dx = dx < 0 ? -dx : dx;
    dy = dy < 0 ? -dy : dy;
    int err = dx - dy;
    int cx = x0, cy = y0;
    for (;;) {
        if (cx >= 0 && cy >= 0 && cx < dc->dc.w && cy < dc->dc.h) {
            int ddy = dc->dc.dib_bottom_up ? dc->dc.h - 1 - cy : cy;
            put_px(dc->dc.pixels + (size_t)ddy * dc->dc.stride + (size_t)cx * 4, rgb);
        }
        if (cx == x && cy == y)
            break;
        int e2 = 2 * err;
        if (e2 > -dy) { err -= dy; cx += sx; }
        if (e2 < dx)  { err += dx; cy += sy; }
    }
    dc->dc.cur_x = x;
    dc->dc.cur_y = y;
    return 1;
}

WN_API int32_t g32_Rectangle(wn_handle hdc, int l, int t, int r, int b)
{
    gdi_obj *dc = gdi_get(hdc, GDI_DC_WINDOW);
    if (!dc)
        return 0;
    uint32_t rgb = colorref_to_u32(dc->dc.text_color);
    /* Thin frame. */
    for (int x = l; x < r; x++) {
        int y1 = t, y2 = b - 1;
        if (y1 >= 0 && y1 < dc->dc.h && x >= 0 && x < dc->dc.w) {
            int dy = dc->dc.dib_bottom_up ? dc->dc.h - 1 - y1 : y1;
            put_px(dc->dc.pixels + (size_t)dy * dc->dc.stride + (size_t)x * 4, rgb);
        }
        if (y2 >= 0 && y2 < dc->dc.h && x >= 0 && x < dc->dc.w) {
            int dy = dc->dc.dib_bottom_up ? dc->dc.h - 1 - y2 : y2;
            put_px(dc->dc.pixels + (size_t)dy * dc->dc.stride + (size_t)x * 4, rgb);
        }
    }
    for (int y = t; y < b; y++) {
        int x1 = l, x2 = r - 1;
        if (x1 >= 0 && x1 < dc->dc.w && y >= 0 && y < dc->dc.h) {
            int dy = dc->dc.dib_bottom_up ? dc->dc.h - 1 - y : y;
            put_px(dc->dc.pixels + (size_t)dy * dc->dc.stride + (size_t)x1 * 4, rgb);
        }
        if (x2 >= 0 && x2 < dc->dc.w && y >= 0 && y < dc->dc.h) {
            int dy = dc->dc.dib_bottom_up ? dc->dc.h - 1 - y : y;
            put_px(dc->dc.pixels + (size_t)dy * dc->dc.stride + (size_t)x2 * 4, rgb);
        }
    }
    return 1;
}

/* BitBlt SRCCOPY between DCs (window <-> memory). */
static WN_API int32_t g32_BitBlt(wn_handle dst, int dx0, int dy0, int w, int h,
                                 wn_handle src, int sx0, int sy0, uint32_t rop)
{
    if (rop != 0x00CC0020 /* SRCCOPY */) {
        wn_log(WN_LOG_WARN, "gdi32: BitBlt rop 0x%x unsupported (SRCCOPY only)", rop);
        wn_last_error_set(WN_ERR_NOT_SUPPORTED);
        return 0;
    }
    gdi_obj *d = gdi_get(dst, GDI_DC_WINDOW);
    gdi_obj *s = gdi_get(src, GDI_DC_WINDOW);
    if (!d || !s || !s->dc.pixels)
        return 0;
    for (int row = 0; row < h; row++) {
        for (int col = 0; col < w; col++) {
            int sxs = sx0 + col, sys = sy0 + row;
            if (sxs < 0 || sys < 0 || sxs >= s->dc.w || sys >= s->dc.h)
                continue;
            int dxd = dx0 + col, dyd = dy0 + row;
            if (dxd < 0 || dyd < 0 || dxd >= d->dc.w || dyd >= d->dc.h)
                continue;
            int syy = s->dc.dib_bottom_up ? s->dc.h - 1 - sys : sys;
            int dyy = d->dc.dib_bottom_up ? d->dc.h - 1 - dyd : dyd;
            const uint8_t *sp = s->dc.pixels + (size_t)syy * s->dc.stride + (size_t)sxs * 4;
            uint8_t *dp = d->dc.pixels + (size_t)dyy * d->dc.stride + (size_t)dxd * 4;
            dp[0] = sp[0]; dp[1] = sp[1]; dp[2] = sp[2]; dp[3] = 0xFF;
        }
    }
    return 1;
}

/* SetDIBitsToDevice: app-provided DIB (usually bottom-up) -> DC.
 * TWELVE stack words (StartScan was missing - it sits between YSrc and
 * NumScans and the wow64 cleanup counts from this arity). */
static WN_API int32_t g32_SetDIBitsToDevice(wn_handle hdc, int xdst, int ydst,
                                            uint32_t w, uint32_t h, int xsrc,
                                            int ysrc, uint32_t startscan,
                                            uint32_t lines,
                                            const void *bits, const void *bmi,
                                            uint32_t usage)
{
    (void)usage; (void)lines; (void)startscan;
    gdi_obj *d = gdi_get(hdc, GDI_DC_WINDOW);
    if (!d || !bits || !bmi)
        return 0;
    const uint8_t *hdr = bmi;
    int bw = *(const int32_t *)(const void *)(hdr + 4);
    int bh = *(const int32_t *)(const void *)(hdr + 8);
    uint16_t bpp = *(const uint16_t *)(const void *)(hdr + 0xE);
    int ah = bh < 0 ? -bh : bh;
    int bottom_up = bh > 0;
    if (bpp != 32) {
        wn_log(WN_LOG_WARN, "gdi32: SetDIBitsToDevice bpp=%u unsupported", bpp);
        return 0;
    }
    for (uint32_t row = 0; row < h; row++) {
        for (uint32_t col = 0; col < w; col++) {
            int sxs = xsrc + (int)col;
            int sys = ysrc + (int)row;
            if (sxs < 0 || sxs >= bw)
                continue;
            int sy = bottom_up ? ah - 1 - sys : sys;
            if (sy < 0 || sy >= ah)
                continue;
            int dx = xdst + (int)col, dy2 = ydst + (int)row;
            if (dx < 0 || dy2 < 0 || dx >= d->dc.w || dy2 >= d->dc.h)
                continue;
            int dyy = d->dc.dib_bottom_up ? d->dc.h - 1 - dy2 : dy2;
            const uint8_t *sp = (const uint8_t *)bits +
                                (size_t)sy * bw * 4 + (size_t)sxs * 4;
            uint8_t *dp = d->dc.pixels + (size_t)dyy * d->dc.stride + (size_t)dx * 4;
            dp[0] = sp[0]; dp[1] = sp[1]; dp[2] = sp[2]; dp[3] = 0xFF;
        }
    }
    return 1;
}

static WN_API int32_t g32_GetDeviceCaps(wn_handle hdc, int32_t idx)
{
    gdi_obj *dc = gdi_get(hdc, GDI_DC_WINDOW);
    int w = dc ? dc->dc.w : 640, h = dc ? dc->dc.h : 480;
    switch (idx) {
    case 8 /* HORZRES */: return w;
    case 10 /* VERTRES */: return h;
    case 12 /* BITSPIXEL */: return 32;
    case 14 /* PLANES */: return 1;
    case 88 /* LOGPIXELSX */:
    case 90 /* LOGPIXELSY */: return 96;
    default: return 0;
    }
}

/* --- export table ----------------------------------------------------------------------------- */

/* --- fonts --------------------------------------------------------------------------- */

/* LOGFONTA x64: lfHeight@0(4), lfWidth@4, lfEscapement@8, lfOrientation@0xC,
 * lfWeight@0x10, lfItalic@0x14(byte), lfUnderline@0x15, lfStrikeOut@0x16,
 * lfCharSet@0x17, lfOutPrecision@0x18, ..., lfFaceName@0x1C[32]. */

static gdi_obj *font_from_logfont(const void *lf, int wide)
{
    if (!lf)
        return NULL;
    gdi_obj *f = wn_xcalloc(1, sizeof *f);
    f->kind = GDI_FONT;
    const uint8_t *b = lf;
    int32_t h = *(const int32_t *)(const void *)b;
    f->font.height = h < 0 ? -h + (h < -12 ? 4 : 3)   /* char height -> cell */
                  : (h > 0 ? h : WN_FONT_CELL_H);
    if (f->font.height < 5)
        f->font.height = 5;
    f->font.weight = *(const int32_t *)(const void *)(b + 0x10);
    f->font.italic = b[0x14] ? 1 : 0;
    const char *face = wide ? NULL : (const char *)(b + 0x1C);
    if (wide) {
        const uint16_t *wface = (const uint16_t *)(const void *)(b + 0x1C);
        char *d = f->font.face;
        for (size_t i = 0; i + 1 < sizeof f->font.face && wface[i]; i++)
            d[i] = (char)(wface[i] < 128 ? wface[i] : '?');
    } else if (face) {
        snprintf(f->font.face, sizeof f->font.face, "%.*s",
                 (int)sizeof f->font.face - 1, face);
    }
    /* FreeType slot AFTER the face name is known: real family +
     * antialiased rendering when available; -1 keeps the bitmap atlas. */
    f->font.ft_slot = wn_ft_select(f->font.face, f->font.height,
                                   f->font.weight >= 700, f->font.italic);
    return f;
}

static WN_API wn_handle g32_CreateFontIndirectA(const void *lf)
{
    gdi_obj *f = font_from_logfont(lf, 0);
    return f ? gdi_new(f) : (wn_handle)0;
}

static WN_API wn_handle g32_CreateFontIndirectW(const void *lf)
{
    gdi_obj *f = font_from_logfont(lf, 1);
    return f ? gdi_new(f) : (wn_handle)0;
}

/* CreateFontA/W: 14 args, all in registers+stack; distill into LOGFONTA. */
static WN_API wn_handle g32_CreateFontA(int32_t height, int32_t width,
                                        int32_t escapement, int32_t orient,
                                        int32_t weight, uint32_t italic,
                                        uint32_t underline, uint32_t strike,
                                        uint32_t charset, uint32_t outprec,
                                        uint32_t clipprec, uint32_t quality,
                                        uint32_t pitch, const char *face)
{
    uint8_t lf[0x3C];
    memset(lf, 0, sizeof lf);
    *(int32_t *)(void *)lf = height;
    *(int32_t *)(void *)(lf + 0x10) = weight;
    lf[0x14] = (uint8_t)italic;
    lf[0x15] = (uint8_t)underline;
    lf[0x16] = (uint8_t)strike;
    lf[0x17] = (uint8_t)charset;
    if (face)
        snprintf((char *)lf + 0x1C, 32, "%.*s", 31, face);
    (void)width; (void)escapement; (void)orient;
    (void)outprec; (void)clipprec; (void)quality; (void)pitch;
    return g32_CreateFontIndirectA(lf);
}

static WN_API wn_handle g32_CreateFontW(int32_t height, int32_t width,
                                        int32_t escapement, int32_t orient,
                                        int32_t weight, uint32_t italic,
                                        uint32_t underline, uint32_t strike,
                                        uint32_t charset, uint32_t outprec,
                                        uint32_t clipprec, uint32_t quality,
                                        uint32_t pitch, const uint16_t *face)
{
    char aface[32] = "";
    if (face) {
        size_t i = 0;
        while (face[i] && i < 31) {
            aface[i] = (char)(face[i] < 128 ? face[i] : '?');
            i++;
        }
    }
    return g32_CreateFontA(height, width, escapement, orient, weight, italic,
                           underline, strike, charset, outprec, clipprec,
                           quality, pitch, aface);
}

/* TEXTMETRICA x64 layout (53 bytes, padded to 56 = 0x38):
 * tmHeight@0x00 tmAscent@0x04 tmDescent@0x08 tmInternalLeading@0x0C
 * tmExternalLeading@0x10 tmAveCharWidth@0x14 tmMaxCharWidth@0x18
 * tmWeight@0x1C tmOverhang@0x20 tmDigitizedAspectX@0x24
 * tmDigitizedAspectY@0x28 tmFirstChar@0x2C tmLastChar@0x2D
 * tmDefaultChar@0x2E tmBreakChar@0x2F tmItalic@0x30 tmUnderlined@0x31
 * tmStruckOut@0x32 tmPitchAndFamily@0x33 tmCharSet@0x34
 *
 * THE SIZE IS LOAD-BEARING: putty calls GetTextMetricsA with a 56-byte
 * stack buffer whose /GS canary sits immediately after it; an earlier
 * version memset 0x58 bytes and wrote tmPitchAndFamily at 0x54 — the
 * 32-byte overflow zeroed the canary and killed putty with
 * STATUS_STACK_BUFFER_OVERRUN (0xC0000409). Never write past 0x38. */
static WN_API int32_t g32_GetTextMetricsA(wn_handle hdc, void *tm)
{
    gdi_obj *dc = gdi_get(hdc, GDI_DC_WINDOW);
    if (!dc || !tm)
        return 0;
    gdi_obj *f = dc->dc.cur_font ? dc->dc.cur_font : default_font(dc);
    int cell_h, adv;
    font_metrics(dc, &cell_h, &adv);
    memset(tm, 0, 0x38);                  /* exactly sizeof(TEXTMETRICA) */
    int32_t *v = tm;
    if (f->font.ft_slot >= 0 && wn_ft_available()) {
        int asc, desc, hgt, avg;
        wn_ft_metrics(f->font.ft_slot, &asc, &desc, &hgt, &avg);
        v[0] = hgt;                       /* tmHeight */
        v[1] = asc;                       /* tmAscent (real) */
        v[2] = desc;                      /* tmDescent (real) */
        v[3] = hgt - asc - desc > 0 ? hgt - asc - desc : 0;
        v[4] = 0;                         /* tmExternalLeading */
        v[5] = avg;                       /* tmAveCharWidth */
        v[6] = avg;                       /* tmMaxCharWidth */
        v[7] = f->font.weight;            /* tmWeight */
        ((uint8_t *)tm)[0x30] = (uint8_t)f->font.italic;
        ((uint8_t *)tm)[0x33] = 0x24;     /* VARIABLE_PITCH | FF_SWISS-ish */
        ((uint8_t *)tm)[0x34] = 0x00;
        return 1;
    }
    v[0] = cell_h;                        /* tmHeight */
    v[1] = cell_h - 3;                    /* tmAscent */
    v[2] = 3;                             /* tmDescent */
    v[3] = 2;                             /* tmInternalLeading */
    v[4] = 0;                             /* tmExternalLeading */
    v[5] = adv;                           /* tmAveCharWidth */
    v[6] = adv;                           /* tmMaxCharWidth */
    v[7] = f->font.weight;                /* tmWeight */
    ((uint8_t *)tm)[0x30] = (uint8_t)f->font.italic;  /* tmItalic */
    ((uint8_t *)tm)[0x33] = 0x01;         /* tmPitchAndFamily: FIXED_PITCH */
    ((uint8_t *)tm)[0x34] = 0x00;         /* tmCharSet: ANSI */
    return 1;
}

static WN_API int32_t g32_GetTextMetricsW(wn_handle hdc, void *tm)
{
    return g32_GetTextMetricsA(hdc, tm);   /* same layout for the fields we set */
}

/* --- font enumeration -----------------------------------------------------------
 * Windows guests walk the font world before drawing UI: Inno Setup probes
 * EnumFontsA during wizard construction and VCL TScreen.Fonts walks
 * EnumFontFamilies. The old stub answered "not implemented" (return 0 +
 * ERROR 120 garbage), i.e. "this machine has NO fonts" — empty font lists
 * flowed into RTL font pickers. We enumerate the faces our text path can
 * actually serve: every name below is accepted by CreateFont* and renders
 * (FreeType buckets on x64; the 8x16 bitmap atlas everywhere). The metrics
 * come from the same source GetTextMetricsA reports, so a face's LOGFONT
 * and TEXTMETRIC never disagree with what the DC path draws.
 *
 * Callbacks are guest code: 32-bit guests are invoked through the 4-dword
 * bridge (the LOGFONT/TEXTMETRIC live in guest-addressable memory — low
 * arena under wow64), native-width guests are called directly. One entry
 * per face, FontType = TRUETYPE_FONTTYPE (we scale, so raster-style
 * per-size enumeration would be a lie). Return value is the last
 * callback result — stop on zero, exactly the Windows protocol. */
typedef struct {
    const char *name;
    uint8_t     pitch_family;
    int32_t     weight;
} font_face_ent;

static const font_face_ent g_font_faces[] = {
    { "MS Sans Serif",    0x24 /* VARIABLE|FF_SWISS */, 400 },
    { "MS Shell Dlg",     0x24,                          400 },
    { "Tahoma",           0x24,                          400 },
    { "Arial",            0x24,                          400 },
    { "MS Serif",         0x22 /* VARIABLE|FF_ROMAN  */, 400 },
    { "Times New Roman",  0x22,                          400 },
    { "Courier New",      0x31 /* FIXED|FF_MODERN    */, 400 },
    { "Fixedsys",         0x31,                          400 },
    { "System",           0x24,                          700 },
    { "Small Fonts",      0x24,                          400 },
};
#define WN_FONT_FACE_COUNT \
    (sizeof g_font_faces / sizeof g_font_faces[0])

typedef WN_API int32_t (*wn_font_enum_cb)(const void *lf, const void *tm,
                                          uint32_t type, wn_abiword lparam);

/* LOGFONT + TEXTMETRIC pair for one face, in the caller's width.
 * Layouts (wingdi.h, 4-byte packed — same field order both arches):
 *   LOGFONTA 60 / LOGFONTW 92: lfHeight@0 lfWeight@16 lfItalic@20
 *     lfCharSet@23 lfPitchAndFamily@27 lfFaceName@28 ([32] CHAR/WCHAR).
 *   TEXTMETRICA 56: tmHeight@0 tmAscent@4 tmDescent@8 tmInternalLeading@12
 *     tmExternalLeading@16 tmAveCharWidth@20 tmMaxCharWidth@24 tmWeight@28
 *     tmOverhang@32 tmDigitizedAspectX@36 tmDigitizedAspectY@40
 *     tmFirstChar@44 tmLastChar@45 tmDefaultChar@46 tmBreakChar@47
 *     tmItalic@48 tmUnderlined@49 tmStruckOut@50 tmPitchAndFamily@51
 *     tmCharSet@52.
 *   TEXTMETRICW 60: same LONG head; FirstChar/LastChar/Default/Break are
 *     WCHAR@44/46/48/50, Italic@52 Underlined@53 StruckOut@54
 *     PitchAndFamily@55 CharSet@56. */
static void fill_font_enum_blk(uint8_t *blk, const font_face_ent *f, int wide)
{
    size_t lf_sz = wide ? 92 : 60;
    memset(blk, 0, lf_sz + (wide ? 60 : 56));

    int asc = 13, desc = 3, hgt = 16, ave = 8;   /* bitmap atlas cell 8x16 */
    if (wn_ft_available()) {
        int slot = wn_ft_select(f->name, 16, f->weight >= 700, 0);
        if (slot >= 0)
            wn_ft_metrics(slot, &asc, &desc, &hgt, &ave);
        else { asc = 13; desc = 3; hgt = 16; ave = 8; }
    }

    int32_t *lf = (int32_t *)(void *)blk;
    lf[0] = hgt;                    /* lfHeight (cell height, positive) */
    lf[4] = 0;                      /* lfWidth */
    lf[8] = 0;                      /* lfEscapement */
    lf[12] = 0;                     /* lfOrientation */
    lf[16] = f->weight;             /* lfWeight */
    blk[20] = 0;                    /* lfItalic */
    blk[21] = 0;                    /* lfUnderline */
    blk[22] = 0;                    /* lfStrikeOut */
    blk[23] = 0;                    /* lfCharSet: ANSI */
    blk[24] = 0;                    /* lfOutPrecision */
    blk[25] = 0;                    /* lfClipPrecision */
    blk[26] = 0;                    /* lfQuality */
    blk[27] = f->pitch_family;      /* lfPitchAndFamily */
    if (wide) {
        uint16_t *w = (uint16_t *)(void *)(blk + 28);
        for (size_t i = 0; i + 1 < 32 && f->name[i]; i++)
            w[i] = (uint16_t)(uint8_t)f->name[i];
    } else {
        strncpy((char *)(void *)(blk + 28), f->name, 31);
    }

    uint8_t *tm = blk + lf_sz;
    int32_t *v = (int32_t *)(void *)tm;
    v[0] = hgt;                     /* tmHeight */
    v[1] = asc;                     /* tmAscent */
    v[2] = desc;                    /* tmDescent */
    v[3] = hgt - asc - desc > 0 ? hgt - asc - desc : 2;   /* internal lead */
    v[4] = 0;                       /* tmExternalLeading */
    v[5] = ave;                     /* tmAveCharWidth */
    v[6] = ave;                     /* tmMaxCharWidth */
    v[7] = f->weight;               /* tmWeight */
    v[8] = 0;                       /* tmOverhang */
    v[9] = 96;                      /* tmDigitizedAspectX */
    v[10] = 96;                     /* tmDigitizedAspectY */
    if (wide) {
        uint16_t *w = (uint16_t *)(void *)(tm + 44);
        w[0] = 0x20;                /* tmFirstChar */
        w[1] = 0xFF;                /* tmLastChar */
        w[2] = 0x3F;                /* tmDefaultChar */
        w[3] = 0x20;                /* tmBreakChar */
        tm[52] = 0;                 /* tmItalic */
        tm[53] = 0;                 /* tmUnderlined */
        tm[54] = 0;                 /* tmStruckOut */
        tm[55] = f->pitch_family;
        tm[56] = 0;                 /* tmCharSet */
    } else {
        tm[44] = 0x20;              /* tmFirstChar */
        tm[45] = 0xFF;              /* tmLastChar */
        tm[46] = 0x3F;              /* tmDefaultChar */
        tm[47] = 0x20;              /* tmBreakChar */
        tm[48] = 0;                 /* tmItalic */
        tm[49] = 0;                 /* tmUnderlined */
        tm[50] = 0;                 /* tmStruckOut */
        tm[51] = f->pitch_family;
        tm[52] = 0;                 /* tmCharSet */
    }
}

static int32_t enum_fonts_core(wn_handle hdc, const char *face_a,
                               const uint16_t *face_w, wn_abiword proc,
                               wn_abiword lparam, int wide)
{
    (void)hdc;   /* the face world is machine-wide, not per-DC */
    if (!proc)
        return 0;
    int g32 = wn_wow64_guest32();
    size_t lf_sz = wide ? 92 : 60;
    size_t tm_sz = wide ? 60 : 56;

    /* Face filter: NULL/"" walks every face, a name picks one. The name
     * rides guest memory — read it bounded + safe-probed. */
    char want[64] = "";
    if (face_a) {
        size_t n = wn_safe_strnlen(face_a, 32);
        if (n < sizeof want) {
            memcpy(want, face_a, n);
            want[n] = 0;
        }
    } else if (face_w && wn_ptr_readable(face_w, 2)) {
        char *u = wn_utf16_to_utf8(face_w, 32);
        if (u) {
            snprintf(want, sizeof want, "%s", u);
            free(u);
        }
    }
    for (char *p = want; *p; p++)   /* face matching is case-insensitive */
        *p = (char)((*p >= 'A' && *p <= 'Z') ? *p + 32 : *p);

    uint8_t *blk;
#if defined(__x86_64__)
    blk = g32 ? wn_low_malloc(lf_sz + tm_sz) : wn_xmalloc(lf_sz + tm_sz);
#else
    blk = wn_xmalloc(lf_sz + tm_sz);
#endif

    int32_t last = 1;
    int reported = 0;
    for (size_t i = 0; i < WN_FONT_FACE_COUNT; i++) {
        if (want[0] && strcasecmp(g_font_faces[i].name, want) != 0)
            continue;
        fill_font_enum_blk(blk, &g_font_faces[i], wide);
        int32_t r;
        if (g32)
            r = (int32_t)wn_wow64_call_wndproc32(
                (uint32_t)proc, (uint32_t)(uintptr_t)blk,
                (uint32_t)(uintptr_t)(blk + lf_sz), 4 /*TRUETYPE_FONTTYPE*/,
                (uint32_t)lparam);
        else
            r = ((wn_font_enum_cb)(uintptr_t)proc)(
                blk, blk + lf_sz, 4 /*TRUETYPE_FONTTYPE*/, lparam);
        reported = 1;
        last = r;
        if (!r)
            break;   /* callback asked to stop the enumeration */
    }
    if (!reported && want[0]) {
        /* Unknown-but-requested face: our renderer serves ANY name through
         * the alias buckets, so reporting it is consistent — on Windows a
         * full font dir would answer it too. Windows-contract callers that
         * search for a specific face then find it and stop guessing. */
        font_face_ent alias;
        alias.name = want;
        alias.pitch_family = 0x24;
        alias.weight = 400;
        fill_font_enum_blk(blk, &alias, wide);
        int32_t r;
        if (g32)
            r = (int32_t)wn_wow64_call_wndproc32(
                (uint32_t)proc, (uint32_t)(uintptr_t)blk,
                (uint32_t)(uintptr_t)(blk + lf_sz), 4, (uint32_t)lparam);
        else
            r = ((wn_font_enum_cb)(uintptr_t)proc)(
                blk, blk + lf_sz, 4, lparam);
        last = r;
    }
#if defined(__x86_64__)
    if (g32)
        wn_low_free(blk);
    else
        free(blk);
#else
    free(blk);
#endif
    return last;
}

static WN_API int32_t g32_EnumFontsA(wn_handle hdc, wn_pcstr face,
                                     wn_abiword proc, wn_abiword lparam)
{
    return enum_fonts_core(hdc, face, NULL, proc, lparam, 0);
}

static WN_API int32_t g32_EnumFontsW(wn_handle hdc, wn_pcwstr face,
                                     wn_abiword proc, wn_abiword lparam)
{
    return enum_fonts_core(hdc, NULL, face, proc, lparam, 1);
}

static WN_API int32_t g32_EnumFontFamiliesA(wn_handle hdc, wn_pcstr face,
                                            wn_abiword proc,
                                            wn_abiword lparam)
{
    return enum_fonts_core(hdc, face, NULL, proc, lparam, 0);
}

static WN_API int32_t g32_EnumFontFamiliesW(wn_handle hdc, wn_pcwstr face,
                                            wn_abiword proc,
                                            wn_abiword lparam)
{
    return enum_fonts_core(hdc, NULL, face, proc, lparam, 1);
}

static WN_API int32_t g32_GetTextExtentPoint32A(wn_handle hdc,
                                                const char *s, int32_t count,
                                                void *size)
{
    gdi_obj *dc = gdi_get(hdc, GDI_DC_WINDOW);
    if (!dc || !s || !size)
        return 0;
    size_t n = count < 0 ? strlen(s) : (size_t)count;
    gdi_obj *f = dc->dc.cur_font ? dc->dc.cur_font : default_font(dc);
    int32_t *sz = size;
    if (f->font.ft_slot >= 0 && wn_ft_available()) {
        int wpx = 0;
        for (size_t i = 0; i < n; i++) {
            const wn_ft_glyph_t *g = wn_ft_glyph(f->font.ft_slot,
                                                 (uint8_t)s[i]);
            wpx += g ? g->adv_x : 0;
        }
        int asc, desc, hgt, avg;
        wn_ft_metrics(f->font.ft_slot, &asc, &desc, &hgt, &avg);
        sz[0] = wpx;
        sz[1] = hgt;              /* same cell height GetTextMetrics reports */
        return 1;
    }
    int cell_h, adv;
    font_metrics(dc, &cell_h, &adv);
    sz[0] = (int32_t)(n * (size_t)adv);
    sz[1] = cell_h;
    return 1;
}

static WN_API int32_t g32_GetTextExtentPoint32W(wn_handle hdc,
                                                const uint16_t *s,
                                                int32_t count, void *size)
{
    gdi_obj *dc = gdi_get(hdc, GDI_DC_WINDOW);
    if (!dc || !s || !size)
        return 0;
    size_t n = 0;
    if (count < 0) {
        while (s[n] && n < 65536)
            n++;
    } else {
        n = (size_t)count;
    }
    gdi_obj *f = dc->dc.cur_font ? dc->dc.cur_font : default_font(dc);
    int32_t *sz = size;
    if (f->font.ft_slot >= 0 && wn_ft_available()) {
        int wpx = 0;
        for (size_t i = 0; i < n; i++) {
            if (!s[i])
                break;
            uint32_t cp = s[i];
            if (cp >= 0xD800 && cp < 0xDC00 && i + 1 < n &&
                s[i + 1] >= 0xDC00 && s[i + 1] < 0xE000) {
                cp = 0x10000 + ((cp - 0xD800) << 10) + (s[i + 1] - 0xDC00);
                i++;
            }
            const wn_ft_glyph_t *g = wn_ft_glyph(f->font.ft_slot, cp);
            wpx += g ? g->adv_x : 0;
        }
        int asc, desc, hgt, avg;
        wn_ft_metrics(f->font.ft_slot, &asc, &desc, &hgt, &avg);
        sz[0] = wpx;
        sz[1] = hgt;
        return 1;
    }
    int cell_h, adv;
    font_metrics(dc, &cell_h, &adv);
    sz[0] = (int32_t)(n * (size_t)adv);
    sz[1] = cell_h;
    return 1;
}

/* GetTextExtentPoint(32)A/W: the pre-Windows-95 name of the same API. The
 * Inno engine imports the short name; as a stub it wrote NOTHING into the
 * caller's SIZE, so VCL layout math consumed stale stack garbage. */
static WN_API int32_t g32_GetTextExtentPointA(wn_handle hdc, const char *s,
                                              int32_t count, void *size)
{
    return g32_GetTextExtentPoint32A(hdc, s, count, size);
}

static WN_API int32_t g32_GetTextExtentPointW(wn_handle hdc,
                                              const uint16_t *s,
                                              int32_t count, void *size)
{
    return g32_GetTextExtentPoint32W(hdc, s, count, size);
}

/* GetCurrentPositionEx: report the DC's line-draw position (POINT = 2 LONGs,
 * same layout for i386 and x64 guests). */
static WN_API int32_t g32_GetCurrentPositionEx(wn_handle hdc, void *pt)
{
    gdi_obj *dc = gdi_get(hdc, GDI_DC_WINDOW);
    if (!dc || !pt)
        return 0;
    int32_t *p = pt;
    p[0] = dc->dc.cur_x;
    p[1] = dc->dc.cur_y;
    return 1;
}

/* Measure the pixel width of a UTF-16 run with the DC's current font
 * (FreeType advances when available, average width otherwise). */
static void measure_text16(gdi_obj *dc, const uint16_t *s, size_t n, int *out_w)
{
    *out_w = 0;
    if (!s || !n)
        return;
    gdi_obj *fobj = dc->dc.cur_font ? dc->dc.cur_font : default_font(dc);
    int slot = fobj && fobj->kind == GDI_FONT ? fobj->font.ft_slot : -1;
    if (slot >= 0 && wn_ft_available()) {
        int wpx = 0;
        for (size_t i = 0; i < n; i++) {
            if (!s[i])
                break;
            uint32_t cp = s[i];
            if (cp >= 0xD800 && cp < 0xDC00 && i + 1 < n &&
                s[i + 1] >= 0xDC00 && s[i + 1] < 0xE000) {
                cp = 0x10000 + ((cp - 0xD800) << 10) + (s[i + 1] - 0xDC00);
                i++;
            }
            const wn_ft_glyph_t *g = wn_ft_glyph(slot, cp);
            wpx += g ? g->adv_x : 0;
        }
        *out_w = wpx;
        return;
    }
    int cell_h, adv;
    font_metrics(dc, &cell_h, &adv);
    *out_w = (int)n * adv;
}

/* DrawTextA/W: single-line + DT_CALCRECT + word-wrap basics + accelerator
 * prefixes. DT_*: LEFT 0, CENTER 6, RIGHT 2, VCENTER 0x24, TOP 0, BOTTOM 8,
 * CALCRECT 0x400, SINGLELINE 0x20, NOPREFIX 0x100, WORDBREAK 0x10.
 * WITHOUT DT_NOPREFIX (Windows default) the text is processed: '&x' marks
 * 'x' as the keyboard accelerator (drawn underlined, '&' removed), '&&'
 * collapses to a literal '&'. Dialog control captions rely on this — putty
 * labels like "Cate&gory:" were rendering a raw ampersand before. */
static int32_t draw_text_common(gdi_obj *dc, const uint16_t *s, size_t n,
                                void *rect, uint32_t fmt)
{
    if (!rect)
        return 0;
    int32_t *r = rect;
    int cell_h, adv;
    font_metrics(dc, &cell_h, &adv);
    uint32_t f = fmt ? fmt : 0;   /* DT_LEFT|DT_TOP is 0 */
    int calc = (f & 0x400) != 0;
    /* Pass 1: build the display string with prefixes stripped.
     * u_line/u_col describe the underlined char in DISPLAY coords. */
    uint16_t disp[4096];
    size_t dn = 0;
    int u_line = -1, u_col = -1;
    if (!(f & 0x100 /*DT_NOPREFIX*/) && n <= 4096) {
        int line = 0;
        for (size_t i = 0; i < n; i++) {
            if (s[i] == u'&') {
                if (i + 1 < n && s[i + 1] == u'&') {
                    disp[dn++] = u'&';       /* && -> literal & */
                    i++;
                } else if (i + 1 < n && s[i + 1] != u'\n') {
                    u_line = line;           /* &x -> underline x */
                    u_col = (int)dn;
                    disp[dn++] = s[++i];
                }
                continue;
            }
            if (s[i] == u'\n')
                line++;
            disp[dn++] = s[i];
        }
        s = disp;
        n = dn;
    } else {
        u_line = -1;
    }
    /* wrap: split at spaces/newlines when WORDBREAK */
    int max_w = r[2] - r[0];
    int lines = 1;
    int widest = 0;
    int cur = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] == '\n') {
            if (cur > widest) widest = cur;
            cur = 0;
            lines++;
            continue;
        }
        cur += adv;
        if ((f & 0x10) && max_w > adv && cur > max_w) {
            if (cur - adv > widest) widest = cur - adv;
            cur = adv;
            lines++;
        }
    }
    if (cur > widest) widest = cur;
    int text_h = lines * cell_h;
    if (calc) {
        r[2] = r[0] + widest;
        r[3] = r[1] + text_h;
        return text_h;
    }
    /* vertical placement */
    int y0 = r[1];
    if (f & 8 /*BOTTOM*/)
        y0 = r[3] - text_h;
    else if (f & 0x20 /*VCENTER*/)
        y0 = r[1] + (r[3] - r[1] - text_h) / 2;
    /* draw line by line */
    size_t i = 0;
    int line_idx = 0;
    while (i < n && line_idx < lines) {
        size_t start = i, len = 0;
        int wpx = 0;
        while (i < n && s[i] != '\n') {
            if ((f & 0x10) && max_w > adv && wpx + adv > max_w)
                break;
            wpx += adv;
            len++;
            i++;
        }
        int x0 = r[0];
        if ((f & 2) /*RIGHT*/)
            x0 = r[2] - wpx;
        else if ((f & 6) == 6 /*CENTER*/)
            x0 = r[0] + (r[2] - r[0] - wpx) / 2;
        draw_text16(dc, x0, y0 + line_idx * cell_h, s + start, len);
        /* accelerator underline for THIS line */
        if (u_line == line_idx && u_col >= 0 &&
            (size_t)u_col >= start && (size_t)u_col < start + len) {
            int pre = 0, chw = 0;
            measure_text16(dc, s + start, (size_t)u_col - start, &pre);
            measure_text16(dc, s + u_col, 1, &chw);
            int uy = y0 + line_idx * cell_h + cell_h - 2;
            fill_rect_rgb(dc, x0 + pre, uy, x0 + pre + (chw ? chw : adv),
                          uy + 1, colorref_to_u32(dc->dc.text_color));
        }
        if (i < n && s[i] == '\n')
            i++;
        line_idx++;
    }
    return text_h;
}

WN_API int32_t g32_DrawTextA(wn_handle hdc, const char *s,
                                    int32_t count, void *rect, uint32_t fmt)
{
    gdi_obj *dc = gdi_get(hdc, GDI_DC_WINDOW);
    if (!dc || !rect)
        return 0;
    if (!s)
        return 0;
    size_t n = count < 0 ? strlen(s) : (size_t)count;
    if (count == 0)
        return 0;
    if (!dc->dc.cur_font)
        dc->dc.cur_font = default_font(dc);
    uint16_t w[4096];
    size_t m = n < 4096 ? n : 4096;
    for (size_t i = 0; i < m; i++)
        w[i] = (unsigned char)s[i];
    return draw_text_common(dc, w, m, rect, fmt);
}

WN_API int32_t g32_DrawTextW(wn_handle hdc, const uint16_t *s,
                                    int32_t count, void *rect, uint32_t fmt)
{
    gdi_obj *dc = gdi_get(hdc, GDI_DC_WINDOW);
    if (!dc || !rect || !s)
        return 0;
    size_t n = 0;
    if (count < 0) {
        while (s[n] && n < 65536)
            n++;
    } else {
        n = (size_t)count;
    }
    if (!dc->dc.cur_font)
        dc->dc.cur_font = default_font(dc);
    uint16_t w[4096];
    size_t m = n < 4096 ? n : 4096;
    memcpy(w, s, m * 2);
    return draw_text_common(dc, w, m, rect, fmt);
}

/* Control-painting helpers shared with user32's builtin controls. */

WN_API int32_t g32_DefaultFontHeight(void)
{
    return WN_FONT_CELL_H;
}

/* checkbox / radio frames, Windows-classic style */
WN_API void g32_DrawCtlFrame(wn_handle hdc, int x, int y, int radio, int state)
{
    gdi_obj *dc = gdi_get(hdc, GDI_DC_WINDOW);
    if (!dc)
        return;
    uint32_t box = state ? 0 : 0x00FFFFFF;
    uint32_t mark = state ? 0x00000000 : 0x00000000;
    uint32_t shad = 0x00808080;
    /* shadow + box */
    int r_[4];
    r_[0] = x + 1; r_[1] = y + 1; r_[2] = x + 13; r_[3] = y + 13;
    wn_handle b1 = g32_CreateSolidBrush(shad);
    g32_FillRect(hdc, r_, b1);
    wn_handle_close(b1);
    r_[0] = x; r_[1] = y; r_[2] = x + 12; r_[3] = y + 12;
    wn_handle b2 = g32_CreateSolidBrush(box);
    g32_FillRect(hdc, r_, b2);
    wn_handle_close(b2);
    if (state) {
        wn_handle b3 = g32_CreateSolidBrush(mark);
        if (radio) {
            r_[0] = x + 3; r_[1] = y + 3; r_[2] = x + 9; r_[3] = y + 9;
        } else {
            /* check mark: two thick strokes */
            int32_t m1[4] = { x + 2, y + 6, x + 4, y + 8 };
            int32_t m2[4] = { x + 4, y + 8, x + 9, y + 3 };
            g32_FillRect(hdc, m1, b3);
            g32_FillRect(hdc, m2, b3);
            wn_handle_close(b3);
            return;
        }
        g32_FillRect(hdc, r_, b3);
        wn_handle_close(b3);
    }
}

/* DrawEdge: 3D control borders. uFlags: BF_RECT=0x4 etc. (subset). Classic
 * palette: raised = light top-left / dark bottom-right; sunken = swapped. */
WN_API int32_t g32_DrawEdge(wn_handle hdc, void *rect, uint32_t edge,
                            uint32_t flags)
{
    gdi_obj *dc = gdi_get(hdc, GDI_DC_WINDOW);
    if (!dc || !rect)
        return 0;
    int32_t *r = rect;
    int l = r[0], t = r[1], rt = r[2], b = r[3];
    int sunken = (edge & 0xA) != 0;   /* BDR_SUNKENOUTER|BDR_SUNKENINNER */
    uint32_t lite = 0x00FFFFFF, dark = 0x00808080, mid = 0x00A0A0A0;
    (void)flags;
    int32_t q[4];
    wn_handle bl = g32_CreateSolidBrush(lite);
    wn_handle bd = g32_CreateSolidBrush(dark);
    wn_handle bm = g32_CreateSolidBrush(mid);
    if (sunken) {
        q[0] = l; q[1] = t; q[2] = rt; q[3] = t + 1;
        g32_FillRect(hdc, q, bd);
        q[0] = l; q[1] = t; q[2] = l + 1; q[3] = b;
        g32_FillRect(hdc, q, bd);
        q[0] = l + 1; q[1] = t + 1; q[2] = rt; q[3] = t + 2;
        g32_FillRect(hdc, q, bm);
        q[0] = l + 1; q[1] = t + 1; q[2] = l + 2; q[3] = b;
        g32_FillRect(hdc, q, bm);
        q[0] = l; q[1] = b - 1; q[2] = rt; q[3] = b;
        g32_FillRect(hdc, q, bl);
        q[0] = rt - 1; q[1] = t; q[2] = rt; q[3] = b;
        g32_FillRect(hdc, q, bl);
    } else {
        q[0] = l; q[1] = t; q[2] = rt; q[3] = t + 1;
        g32_FillRect(hdc, q, bl);
        q[0] = l; q[1] = t; q[2] = l + 1; q[3] = b;
        g32_FillRect(hdc, q, bl);
        q[0] = l + 1; q[1] = t + 1; q[2] = rt; q[3] = t + 2;
        g32_FillRect(hdc, q, bm);
        q[0] = l + 1; q[1] = t + 1; q[2] = l + 2; q[3] = b;
        g32_FillRect(hdc, q, bm);
        q[0] = l; q[1] = b - 1; q[2] = rt; q[3] = b;
        g32_FillRect(hdc, q, bd);
        q[0] = rt - 1; q[1] = t; q[2] = rt; q[3] = b;
        g32_FillRect(hdc, q, bd);
    }
    wn_handle_close(bl);
    wn_handle_close(bd);
    wn_handle_close(bm);
    return 1;
}

const wn_export_entry wn_gdi32_exports[] = {
    { "BitBlt", g32_BitBlt },
    { "PatBlt", g32_PatBlt },
    { "SetROP2", g32_SetROP2 },
    { "UnrealizeObject", g32_UnrealizeObject },
    { "GetObjectA", g32_GetObjectA },
    { "CreateBrushIndirect", g32_CreateBrushIndirect },
    { "CreatePenIndirect", g32_CreatePenIndirect },
    { "CreateCompatibleBitmap", g32_CreateCompatibleBitmap },
    { "CreateCompatibleDC", g32_CreateCompatibleDC },
    { "CreateDIBSection", g32_CreateDIBSection },
    { "CreateFontA", g32_CreateFontA },
    { "CreateFontIndirectA", g32_CreateFontIndirectA },
    { "CreateFontIndirectW", g32_CreateFontIndirectW },
    { "CreateFontW", g32_CreateFontW },
    { "DrawTextA", g32_DrawTextA },
    { "DrawTextW", g32_DrawTextW },
    { "DrawEdge", g32_DrawEdge },
    { "GetTextExtentPoint32A", g32_GetTextExtentPoint32A },
    { "GetTextExtentPoint32W", g32_GetTextExtentPoint32W },
    { "GetTextExtentPointA", g32_GetTextExtentPointA },
    { "GetTextExtentPointW", g32_GetTextExtentPointW },
    { "GetCurrentPositionEx", g32_GetCurrentPositionEx },
    { "GetTextMetricsA", g32_GetTextMetricsA },
    { "GetTextMetricsW", g32_GetTextMetricsW },
    { "EnumFontsA", g32_EnumFontsA },
    { "EnumFontsW", g32_EnumFontsW },
    { "EnumFontFamiliesA", g32_EnumFontFamiliesA },
    { "EnumFontFamiliesW", g32_EnumFontFamiliesW },
    { "CreatePen", g32_CreatePen },
    { "CreateSolidBrush", g32_CreateSolidBrush },
    { "DeleteDC", g32_DeleteDC },
    { "DeleteObject", g32_DeleteObject },
    { "GetDeviceCaps", g32_GetDeviceCaps },
    { "GetStockObject", g32_GetStockObject },
    { "LineTo", g32_LineTo },
    { "MoveToEx", g32_MoveToEx },
    { "Rectangle", g32_Rectangle },
    { "SelectObject", g32_SelectObject },
    { "SetBkColor", g32_SetBkColor },
    { "SetBkMode", g32_SetBkMode },
    { "SetDIBitsToDevice", g32_SetDIBitsToDevice },
    { "SetPixel", g32_SetPixel },
    { "SetTextColor", g32_SetTextColor },
    { "TextOutA", g32_TextOutA },
    { "TextOutW", g32_TextOutW },
    { NULL, NULL },
};
