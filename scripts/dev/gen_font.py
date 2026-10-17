#!/usr/bin/env python3
"""Generate src/gfx/font_bitmap.c — 8x16 monospace glyph atlas (dev-time tool).

Renders DejaVu Sans Mono (Book + Bold + Oblique) at 16px cell height into
1-bit glyphs for codepoints 32..126 (ASCII) and 160..0x24F (Latin-1 +
Latin Ext-A/B + IPA). The build itself stays pure C; the generated file is
committed. Cell: 8 px wide, 16 px tall, row byte = 8 pixel bits (MSB left).
"""
from PIL import Image, ImageFont, ImageDraw
import sys

REG  = '/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf'
BOLD = '/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf'
ITAL = '/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Oblique.ttf'

W, H = 8, 16

def render_set(path, size, cps):
    font = ImageFont.truetype(path, size)
    out = {}
    for cp in cps:
        img = Image.new('1', (W * 2, H * 3), 0)   # padding for bearing
        d = ImageDraw.Draw(img)
        try:
            d.text((W // 2, H // 2), chr(cp), font=font, fill=1)
        except Exception:
            continue
        # crop to content, then center into WxH cell
        bbox = img.getbbox()
        if not bbox:
            out[cp] = [0] * H
            continue
        x0, y0, x1, y1 = bbox
        glyph = img.crop(bbox)
        gw, gh = glyph.size
        ox = (W - gw) // 2
        oy = (H - gh) // 2 - 1   # slight optical lift
        cell = Image.new('1', (W, H), 0)
        cell.paste(glyph, (max(0, ox), max(0, oy)))
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

hdr = '''/* font_bitmap.c — GENERATED FILE, do not edit by hand.
 * Source: scripts/dev/gen_font.py (PIL render of DejaVu Sans Mono 15px
 * into 8x16 cells; committed so builds need no Python/PIL).
 * Coverage: ASCII, Latin-1, Latin Ext-A/B, IPA, box/block geometry.
 * Row encoding: 16 bytes per glyph, 8 pixel bits per byte, MSB = left.
 */
#include "wn_font.h"

/* Glyph index = codepoint (tables are 256 entries, zero-filled gaps). */
'''

src = hdr + '\n' + emit_table('g_glyph_book', book) + '\n\n'
src += emit_table('g_glyph_bold', bold) + '\n\n'
src += emit_table('g_glyph_ital', ital) + '\n'

# coverage report
have = [cp for cp in CPS if any(book[cp])]
sys.stderr.write('glyphs rendered: %d / %d\n' % (len(have), len(CPS)))
open('src/gfx/font_bitmap.c', 'w').write(src)
