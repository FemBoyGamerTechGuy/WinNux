/* wn_font.h — embedded bitmap font engine (8x16 mono atlas).
 *
 * Source atlas: src/gfx/font_bitmap.c (generated from DejaVu Sans Mono;
 * see scripts/dev/gen_font.py). Self-contained: no backend, no dlopen, works
 * under X11, Wayland, and headless. This is the GDI text path.
 *
 * Metrics (scale 1): cell 8x16, cap height ~10, baseline at row 12,
 * advance = 8. Scaling: nearest-neighbor to the requested cell height;
 * bold/italic have dedicated atlases (plus a synthesis fallback).
 */
#ifndef WN_FONT_H
#define WN_FONT_H

#include <stdint.h>

/* Atlas constants. */
#define WN_FONT_ADVANCE   8
#define WN_FONT_CELL_H    16
#define WN_FONT_BASELINE  12

/* Glyph rows for a codepoint (16 rows, 8 bits each, MSB = left pixel).
 * Returns NULL when the atlas has no glyph (draw the missing box then). */
const unsigned char *wn_font_glyph(uint32_t cp, int bold, int italic);

/* Missing-glyph box (hollow rectangle) — same row encoding, never NULL. */
const unsigned char *wn_font_missing(void);

/* Does the atlas cover this codepoint at all? */
int wn_font_has(uint32_t cp);

/* --- FreeType path (dlopen'd at runtime; bitmap atlas is the fallback) --------
 * See src/gfx/font_ft.c. Slots are (family, style, pixel height) triples. */

struct wn_ft_glyph {
    uint32_t cp;
    int16_t left, top;       /* bitmap placement relative to the pen/baseline */
    int16_t w, h;            /* alpha bitmap size */
    int32_t adv_x;           /* pen advance in pixels */
    uint8_t *alpha;          /* w*h 8-bit coverage (internal cache ownership) */
    struct wn_ft_glyph *next;   /* internal: cache chain */
};
typedef struct wn_ft_glyph wn_ft_glyph_t;

/* 1 if FreeType loaded AND the struct overlays self-verified. */
int wn_ft_available(void);

/* Pick a slot for a Windows face name at a pixel height. -1 = use bitmap. */
int wn_ft_select(const char *face_name, int px_height, int bold, int italic);

/* Rendered glyph for a slot+codepoint (cached). Never NULL when slot valid. */
const wn_ft_glyph_t *wn_ft_glyph(int slot_idx, uint32_t cp);

/* Face metrics in pixels (ascent/descent above/below baseline, cell height,
 * average advance). */
void wn_ft_metrics(int slot_idx, int *ascent, int *descent, int *height,
                   int *avg_adv);

/* 1 when the slot wants bold but only a regular file exists (double-strike
 * synthesis is needed by the blit path). */
int wn_ft_slot_bold(int slot_idx);

#endif /* WN_FONT_H */
