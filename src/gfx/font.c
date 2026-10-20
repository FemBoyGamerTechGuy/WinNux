/* font.c — embedded bitmap font engine API (data in font_bitmap.c).
 *
 * Self-contained GDI text rasterizer: no X11/Xft, no dlopen, works on every
 * backend (X11, Wayland, headless). Bold/italic use dedicated atlases.
 */
#include "wn_font.h"

#include <stddef.h>

extern const unsigned char g_glyph_book[256][WN_FONT_CELL_H];
extern const unsigned char g_glyph_bold[256][WN_FONT_CELL_H];
extern const unsigned char g_glyph_ital[256][WN_FONT_CELL_H];

static const unsigned char g_missing[WN_FONT_CELL_H] = {
    0x00, 0x00, 0x7E, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x7E, 0x00, 0x00
};

static const unsigned char *cell_of(uint32_t cp, int bold, int italic)
{
    if (cp > 0xFF)
        return NULL;
    const unsigned char (*tab)[WN_FONT_CELL_H] =
        bold ? g_glyph_bold : (italic ? g_glyph_ital : g_glyph_book);
    if (cp == 0x20 /* space: a legitimately BLANK glyph — rendering the
                    * missing-glyph box for it turned every space into an
                    * ugly "[]" (VLM-verified on the wizard screenshot) */)
        return tab[cp];
    const unsigned char *g = tab[cp];
    for (int y = 0; y < WN_FONT_CELL_H; y++)
        if (g[y])
            return g;
    return NULL;    /* atlas gap: never rendered */
}

const unsigned char *wn_font_glyph(uint32_t cp, int bold, int italic)
{
    return cell_of(cp, bold, italic);
}

const unsigned char *wn_font_missing(void)
{
    return g_missing;
}

int wn_font_has(uint32_t cp)
{
    return cell_of(cp, 0, 0) != NULL;
}
