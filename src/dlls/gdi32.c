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
#include "wn_log.h"
#include "wn_util.h"
#include "wn_font.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

WN_API wn_handle g32_BeginPaint(uint64_t hwnd, void *ps)
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
    *(wn_handle *)(void *)ps = hdc;
    *(uint32_t *)(void *)((uint8_t *)ps + 8) = 1;   /* fErase */
    int32_t *rc = (int32_t *)((uint8_t *)ps + 0xC);
    rc[0] = l; rc[1] = t; rc[2] = r; rc[3] = b;
    return hdc;
}

WN_API int32_t g32_EndPaint(uint64_t hwnd, const void *ps)
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

WN_API wn_handle g32_GetDC(uint64_t hwnd)
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

WN_API int32_t g32_ReleaseDC(uint64_t hwnd, wn_handle hdc)
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
        /* brushes/pens: accepted, state not tracked yet */
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

/* SetDIBitsToDevice: app-provided DIB (usually bottom-up) -> DC. */
static WN_API int32_t g32_SetDIBitsToDevice(wn_handle hdc, int xdst, int ydst,
                                            uint32_t w, uint32_t h, int xsrc,
                                            int ysrc, uint32_t lines,
                                            const void *bits, const void *bmi,
                                            uint32_t usage)
{
    (void)usage; (void)lines;
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

/* DrawTextA/W: single-line + DT_CALCRECT + word-wrap basics.
 * DT_*: LEFT 0, CENTER 6, RIGHT 2, VCENTER 0x24, TOP 0, BOTTOM 8,
 * CALCRECT 0x400, SINGLELINE 0x20, NOPREFIX 0x100, WORDBREAK 0x10. */
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
    { "GetTextMetricsA", g32_GetTextMetricsA },
    { "GetTextMetricsW", g32_GetTextMetricsW },
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
