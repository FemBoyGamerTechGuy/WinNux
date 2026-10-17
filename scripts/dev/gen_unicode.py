#!/usr/bin/env python3
"""Generate src/common/unicode.c — compact BMP Unicode tables for WinNux.

One-time dev generator (NOT part of the build; the generated .c is committed).
Data: Python's unicodedata module.
Tables:
  - case pairs: codepoints whose simple upper/lower differ (binary-searchable)
  - ctype ranges: Windows C1_*/C2_*/C3_* classification, run-length encoded
"""
import unicodedata, sys

# ---------------- case mapping ----------------
pairs = []          # (cp, upper, lower)
for cp in range(0x10000):
    ch = chr(cp)
    up = cp; lo = cp
    u = unicodedata.category(ch)
    if u.startswith('L'):        # letters only case-map
        m = unicodedata.bidirectional(ch)
        if m in ('L', 'R', 'AL', 'LRE', 'LRO', 'RLE', 'RLO', 'PDF', 'AL', 'L'):
            pass
    upname = ch.upper(); loname = ch.lower()
    if len(upname) == 1: up = ord(upname)
    if len(loname) == 1: lo = ord(loname)
    if up != cp or lo != cp:
        pairs.append((cp, up, lo))

# ---------------- ctype1 ranges ----------------
# Windows C1 flags
C1_UPPER, C1_LOWER, C1_DIGIT, C1_SPACE, C1_PUNCT, C1_CNTRL, C1_BLANK, C1_XDIGIT, C1_ALPHA = (
    1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80, 0x100)

def c1_of(cp):
    ch = chr(cp)
    cat = unicodedata.category(ch)
    f = 0
    if cat == 'Lu': f |= C1_UPPER | C1_ALPHA
    elif cat == 'Ll': f |= C1_LOWER | C1_ALPHA
    elif cat == 'Lt': f |= C1_UPPER | C1_LOWER | C1_ALPHA
    elif cat in ('Lm', 'Lo'): f |= C1_ALPHA
    elif cat == 'Nd': f |= C1_DIGIT
    elif cat in ('Pc','Pd','Ps','Pe','Pi','Pf','Po','Sm','Sk','Sc'):
        f |= C1_PUNCT
    elif cat in ('Zs','Zl','Zp'): f |= C1_SPACE
    elif cat == 'Cc': f |= C1_CNTRL
    elif cat in ('Mn','Mc','Me'): f |= C1_ALPHA
    # explicit space set (matches Windows: includes 0x1c-0x1f, 0x85)
    if cp in (0x09,0x0A,0x0B,0x0C,0x0D,0x1C,0x1D,0x1E,0x1F,0x85) or \
       cp in (0xA0,0x1680) or 0x2000 <= cp <= 0x200A or \
       cp in (0x2028,0x2029,0x202F,0x205F,0x3000):
        f |= C1_SPACE
    if cp == 0x09 or cp == 0x20 or cat == 'Zs':
        f |= C1_BLANK
    if '0' <= ch <= '9' or 'a' <= ch <= 'f' or 'A' <= ch <= 'F' or \
       0xFF10 <= cp <= 0xFF19 or 0xFF21 <= cp <= 0xFF26 or 0xFF41 <= cp <= 0xFF46:
        f |= C1_XDIGIT
    if cat == 'Nd':
        f |= C1_XDIGIT if '0' <= ch <= '9' else 0
    return f

# ctype1 run-length ranges
ranges1 = []
prev = None
for cp in range(0x10000):
    f = c1_of(cp)
    if ranges1 and prev == f and ranges1[-1][1] == cp - 1:
        ranges1[-1] = (ranges1[-1][0], cp, f)
    else:
        ranges1.append((cp, cp, f))
    prev = f

# ---------------- ctype2 (directionality values) ----------------
# C2 values: 0 = not applicable, 1 L2R, 2 R2L, 3 euro number, 4 euro sep,
# 5 euro term, 6 arabic number, 7 common sep, 8 no. separator?? Windows:
# C2_LEFTTORIGHT 1, C2_RIGHTTOLEFT 2, C2_EUROPENUMBER 3, C2_EUROPESEPARATOR 4,
# C2_EUROPETERMINATOR 5, C2_ARABICNUMBER 6, C2_COMMONSEPARATOR 7,
# C2_BLOCKSEPARATOR 8, C2_SEGMENTSEPARATOR 9, C2_WHITESPACE 10, C2_OTHERNEUTRAL 11
def c2_of(cp):
    ch = chr(cp)
    b = unicodedata.bidirectional(ch)
    m = {'L':1, 'R':2, 'AL':2, 'AN':6, 'EN':3, 'ES':4, 'ET':5, 'CS':7,
         'WS':10, 'S':9, 'B':10, 'ON':11, 'BN':0, 'NSM':0, 'PDF':11,
         'LRE':11,'LRO':11,'RLE':11,'RLO':11,'LRI':11,'RLI':11,'FSI':11,'PDI':11}
    return m.get(b, 0)

ranges2 = []
for cp in range(0x10000):
    f = c2_of(cp)
    if ranges2 and ranges2[-1][2] == f and ranges2[-1][1] == cp - 1:
        ranges2[-1] = (ranges2[-1][0], cp, f)
    else:
        ranges2.append((cp, cp, f))

# ---------------- ctype3 ----------------
C3_NONSPACING, C3_DIACRITIC, C3_VOWEL, C3_VOWELMARK, C3_SYMBOL = 1, 2, 4, 8, 0x10
C3_KATAKANA, C3_HIRAGANA, C3_HALFWIDTH, C3_FULLWIDTH, C3_IDEOGRAPH = 0x20, 0x40, 0x80, 0x100, 0x200

def c3_of(cp):
    ch = chr(cp)
    cat = unicodedata.category(ch)
    f = 0
    if cat == 'Mn': f |= C3_NONSPACING
    if 0x0300 <= cp <= 0x036F: f |= C3_DIACRITIC
    if cat in ('Sk','Sc','Sm'): f |= C3_SYMBOL
    if 0x30A0 <= cp <= 0x30FF: f |= C3_KATAKANA
    if 0x3040 <= cp <= 0x309F: f |= C3_HIRAGANA
    if 0xFF00 <= cp <= 0xFFEF: f |= C3_HALFWIDTH | (C3_FULLWIDTH if cp >= 0xFF01 else 0)
    if 0x4E00 <= cp <= 0x9FFF: f |= C3_IDEOGRAPH
    if 0x3000 <= cp <= 0x303F: f |= C3_IDEOGRAPH
    if cat in ('Lu','Ll','Lt','Lm','Lo'):
        if 0x4E00 <= cp <= 0x9FFF: f |= C3_IDEOGRAPH
    return f

ranges3 = []
for cp in range(0x10000):
    f = c3_of(cp)
    if ranges3 and ranges3[-1][2] == f and ranges3[-1][1] == cp - 1:
        ranges3[-1] = (ranges3[-1][0], cp, f)
    else:
        ranges3.append((cp, cp, f))

# ---------------- emit C ----------------
def emit_case(pairs):
    out = []
    out.append('/* {cp, upper, lower}: codepoints whose case mapping is not identity. */')
    out.append('static const struct { uint16_t cp, up, lo; } g_case_map[] = {')
    line = []
    for cp, up, lo in pairs:
        line.append('{0x%04X,0x%04X,0x%04X}' % (cp, up, lo))
        if len(line) == 6:
            out.append('    ' + ','.join(line) + ',')
            line = []
    if line:
        out.append('    ' + ','.join(line) + ',')
    out.append('};')
    return '\n'.join(out)

def emit_ranges(name, ranges):
    out = []
    out.append('static const struct { uint16_t lo, hi; uint16_t v; } %s[] = {' % name)
    line = []
    for lo, hi, v in ranges:
        line.append('{0x%04X,0x%04X,0x%04X}' % (lo, hi, v))
        if len(line) == 6:
            out.append('    ' + ','.join(line) + ',')
            line = []
    if line:
        out.append('    ' + ','.join(line) + ',')
    out.append('};')
    return '\n'.join(out)

hdr = '''/* unicode.c — GENERATED FILE, do not edit by hand.
 * Source of truth: scripts/dev/gen_unicode.py (Python unicodedata, run
 * once at dev time; the build itself stays pure C).
 * Tables cover the BMP: simple case mapping + Windows C1/C2/C3 classes
 * used by GetStringTypeW and LCMapStringW.
 */
#include "wn_unicode.h"
#include <stddef.h>
#include <stdint.h>

'''

body = []
body.append(emit_case(pairs))
body.append('')
body.append(emit_ranges('g_c1_ranges', ranges1))
body.append('')
body.append(emit_ranges('g_c2_ranges', ranges2))
body.append('')
body.append(emit_ranges('g_c3_ranges', ranges3))
body.append('''
/* binary search in a {lo,hi,v} range table */
static uint32_t range_lookup(const struct { uint16_t lo, hi; uint16_t v; } *t,
                             size_t n, uint32_t cp)
{
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (cp < t[mid].lo)
            hi = mid;
        else if (cp > t[mid].hi)
            lo = mid + 1;
        else
            return t[mid].v;
    }
    return 0;
}

static const struct { uint16_t cp, up, lo; } *case_find(uint32_t cp)
{
    size_t lo = 0, hi = sizeof g_case_map / sizeof g_case_map[0];
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (cp < g_case_map[mid].cp)
            hi = mid;
        else if (cp > g_case_map[mid].cp)
            lo = mid + 1;
        else
            return &g_case_map[mid];
    }
    return NULL;
}

uint32_t wn_uni_to_upper(uint32_t cp)
{
    if (cp >= 0x10000)
        return cp;
    const typeof(g_case_map[0]) *e = case_find(cp);
    return e ? e->up : cp;
}

uint32_t wn_uni_to_lower(uint32_t cp)
{
    if (cp >= 0x10000)
        return cp;
    const typeof(g_case_map[0]) *e = case_find(cp);
    return e ? e->lo : cp;
}

uint32_t wn_uni_ctype1(uint32_t cp)
{
    if (cp >= 0x10000)
        return 0;
    return range_lookup(g_c1_ranges,
                        sizeof g_c1_ranges / sizeof g_c1_ranges[0], cp);
}

uint32_t wn_uni_ctype2(uint32_t cp)
{
    if (cp >= 0x10000)
        return 0;
    return range_lookup(g_c2_ranges,
                        sizeof g_c2_ranges / sizeof g_c2_ranges[0], cp);
}

uint32_t wn_uni_ctype3(uint32_t cp)
{
    if (cp >= 0x10000)
        return 0;
    return range_lookup(g_c3_ranges,
                        sizeof g_c3_ranges / sizeof g_c3_ranges[0], cp);
}
''')

open('src/common/unicode.c', 'w').write(hdr + '\n'.join(body) + '\n')
sys.stderr.write('pairs=%d c1_ranges=%d c2_ranges=%d c3_ranges=%d\\n' %
                 (len(pairs), len(ranges1), len(ranges2), len(ranges3)))
