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

#endif /* WN_FONT_H */
