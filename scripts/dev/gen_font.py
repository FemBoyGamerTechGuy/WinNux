#!/usr/bin/env python3
"""Generate src/gfx/font_bitmap.c — 8x16 monospace glyph atlas (dev-time tool).

Renders DejaVu Sans Mono (Book + Bold + Oblique) at 15px into 1-bit
glyphs for ASCII + Latin-1 + Latin Ext-A/B + IPA + geometry. The build
stays pure C; the generated file is committed.

BASELINE CONTRACT (2026-10-21 field fix, "letters vertically misaligned,
some higher and some lower"): the old generator cropped each glyph to
its ink box and CENTERED it vertically in the cell — that destroyed
baseline information, so 'x' rode higher than 'H' and every letter sat
at its own height. All glyphs now render anchored at ONE baseline row
(WN_FONT_BASELINE = 12) and keep their true vertical position: H/x rest
ON the baseline, g/y/p descend below it, | dips like a paren. Only
HORIZONTAL centering (into the 8px cell) still happens. GetTextMetrics
(tmAscent = cell_h * 12/16) and SetTextAlign(TA_BASELINE) read the SAME
row, so what you measure is what you draw.

Cell: 8 px wide, 16 px tall, row byte = 8 pixel bits (MSB left).
"""
from PIL import Image, ImageFont, ImageDraw
import sys

REG  = '/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf'
BOLD = '/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf'
ITAL = '/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Oblique.ttf'

W, H = 8, 16
BASELINE = 12          # the ONE shared baseline row inside the cell


def render_set(path, size, cps):
    font = ImageFont.truetype(path, size)
    out = {}
    for cp in cps:
        # Tall canvas, glyph drawn with its BASELINE at canvas row 40.
        # anchor='ls' = left-baseline: every glyph shares that row.
        canvas = Image.new('1', (W * 3, 80), 0)
        d = ImageDraw.Draw(canvas)
        try:
            d.text((W, 40), chr(cp), font=font, fill=1, anchor='ls')
        except Exception:
            out[cp] = [0] * H
            continue
        bbox = canvas.getbbox()
        if not bbox:
            out[cp] = [0] * H
            continue
        x0, y0, x1, y1 = bbox
        # Vertical placement is EXACTLY where it rendered, translated so
        # the baseline lands on row BASELINE (never centered!). Only X
        # is centered into the 8px cell.
        cell = Image.new('1', (W, H), 0)
        gw, gh = x1 - x0, y1 - y0
        paste_y = BASELINE + (y0 - 40)
        if paste_y < 0:
            paste_y = 0
        ox = (W - gw) // 2 - x0
        ox = max(0, min(ox, W - gw))
        cell.paste(canvas.crop(bbox), (ox, paste_y))
        rows = []
        px = cell.load()
        for y in range(H):
            b = 0
            for x in range(W):
                if px[x, y]:
                    b |= 0x80 >> x
            rows.append(b)
        out[cp] = rows
    return out


CPS = list(range(0x20, 0x7F))          # ASCII
CPS += list(range(0xA0, 0x180))        # Latin-1 + Latin Ext-A
CPS += list(range(0x180, 0x250))       # Latin Ext-B + IPA
CPS += [0x2500, 0x2501, 0x2502, 0x2503, 0x250C, 0x250F, 0x2510, 0x2513,
        0x2514, 0x2517, 0x251C, 0x2523, 0x2524, 0x252B, 0x2534, 0x253B,
        0x254B, 0x2550, 0x2551, 0x2552, 0x255A, 0x2554, 0x2557, 0x255D,
        0x2560, 0x2563, 0x2566, 0x2569, 0x256C, 0x2580, 0x2584, 0x2588,
        0x2592, 0x2593, 0x25B2, 0x25BA, 0x25BC, 0x25C4, 0x25CF, 0x25E6,
        0x2605, 0x260E, 0x2610, 0x2611, 0x2612]

book = render_set(REG, 15, CPS)
bold = render_set(BOLD, 15, CPS)
ital = render_set(ITAL, 15, CPS)


def emit_table(name, data):
    out = ['const unsigned char %s[256][16] = {' % name]
    line = []
    for cp in range(0x100):
        rows = data.get(cp)
        if rows is None:
            rows = [0] * H
        line.append('{' + ','.join('0x%02X' % b for b in rows) + '}')
        if len(line) == 4:
            out.append('    ' + ','.join(line) + ',')
            line = []
    if line:
        out.append('    ' + ','.join(line) + ',')
    out.append('};')
    return '\n'.join(out)


header = """/* font_bitmap.c — GENERATED FILE, do not edit by hand.
 * Source: scripts/dev/gen_font.py (PIL render of DejaVu Sans Mono 15px
 * into 8x16 cells; committed so builds need no Python/PIL).
 * Coverage: ASCII, Latin-1, Latin Ext-A/B, IPA, box/block geometry.
 * Row encoding: 16 bytes per glyph, 8 pixel bits per byte, MSB = left.
 *
 * BASELINE: every glyph shares ONE baseline row (WN_FONT_BASELINE = %d
 * of 16). H/x/... rest on it; g/y/p/... descend below it; |/(/) dip
 * like parens. The old cell-centered glyphs sat at per-glyph heights
 * ("some letters higher, some lower" field report) — never re-center
 * vertically. GDI reads WN_FONT_BASELINE for tmAscent and TA_BASELINE
 * so metrics match what is drawn.
 */
#include "wn_font.h"

""" % BASELINE

tables = [
    emit_table('g_glyph_book', book),
    '',
    emit_table('g_glyph_bold', bold),
    '',
    emit_table('g_glyph_ital', ital),
]

with open('src/gfx/font_bitmap.c', 'w') as f:
    f.write(header)
    f.write('\n\n'.join(tables))
    f.write('\n')

# sanity: H and x must END on the same row; g/y/p must END together.
def bottom(rows, table):
    for y in range(H - 1, -1, -1):
        if table[rows][y] if False else rows[y]:
            return y
    return None

checks = []
for ch, name in ((ord('H'), 'book'), (ord('x'), 'book'), (ord('|'), 'book')):
    pass
bH = bottom(book[ord('H')], None)
bx = bottom(book[ord('x')], None)
bg = bottom(book[ord('g')], None)
by = bottom(book[ord('y')], None)
bp = bottom(book[ord('p')], None)
bpipe = bottom(book[ord('|')], None)
assert bH == bx, "H (%d) and x (%d) do not share a bottom row!" % (bH, bx)
assert bg == by == bp, "descenders g(%d) y(%d) p(%d) differ!" % (bg, by, bp)
assert bpipe >= bg, "| (%d) must not sit above the descenders (%d)" % (bpipe, bg)
print("baseline row: %d; bottoms  H=%d x=%d | g=%d y=%d p=%d pipe=%d"
      % (BASELINE, bH, bx, bg, by, bp, bpipe))
print("wrote src/gfx/font_bitmap.c")
