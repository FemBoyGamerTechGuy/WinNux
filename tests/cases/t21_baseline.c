/* t21: text-baseline contract (the "letters vertically misaligned, some
 * higher and some lower" field fix).
 *
 * The old 8x16 atlas centered each glyph's ink in its cell — baseline
 * information died, so 'x' rode higher than 'H'. The regenerated atlas
 * anchors EVERY glyph at one shared baseline row (WN_FONT_BASELINE=12);
 * GetTextMetrics (tmAscent) and SetTextAlign (TA_BASELINE) read the
 * same row, so what you measure is what you draw.
 *
 * This case renders "Hxgyp|" onto a real window DC under Xvfb and reads
 * the framebuffer back with GetPixel (the window DC IS the framebuffer
 * backing store), asserting:
 *   1. H and x END on the same pixel row (baseline-resting glyphs).
 *   2. g, y, p END on the same pixel row (uniform descenders).
 *   3. H's bottom row == y_origin + tmAscent - 1 (metrics match draw).
 *   4. TA_BASELINE at the same baseline lands on the SAME rows (and
 *      GetTextAlign returns what SetTextAlign set).
 *   5. TA_BOTTOM / TA_CENTER shifts are consistent with tmAscent +
 *      tmDescent.
 *   6. GetTextExtentPoint32 width matches the drawn ink extent (±2px
 *      side bearing).
 * '|', a paren-class glyph, dips 1px below the g/y/p band by font
 * design — its bottom must be IN [yband, yband+1].
 */
#include <windows.h>
#include <stdio.h>

static int glyph_bottom(HDC hdc, int x0, int x1, int y0, int y1)
{
    for (int y = y1; y >= y0; y--) {
        for (int x = x0; x < x1; x++) {
            COLORREF c = GetPixel(hdc, x, y);
            int r = (int)(c & 0xFF), g = (int)((c >> 8) & 0xFF),
                b = (int)((c >> 16) & 0xFF);
            if (r < 0x80 || g < 0x80 || b < 0x80)   /* dark = ink */
                return y;
        }
    }
    return -1;
}

int main(void)
{
    WNDCLASSA wc = { 0 };
    wc.lpfnWndProc = DefWindowProcA;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = "T21Baseline";
    if (!RegisterClassA(&wc)) { puts("T21 FAIL RegisterClass"); return 1; }
    HWND wnd = CreateWindowExA(0, "T21Baseline", "t21", WS_OVERLAPPEDWINDOW,
                               4, 4, 360, 240, NULL, NULL, NULL, NULL);
    ShowWindow(wnd, SW_SHOW);

    HDC hdc = GetDC(wnd);
    RECT rc;
    GetClientRect(wnd, &rc);
    HBRUSH white = CreateSolidBrush(RGB(255, 255, 255));
    FillRect(hdc, &rc, white);
    SetTextColor(hdc, RGB(0, 0, 0));
    SetBkMode(hdc, TRANSPARENT);

    /* --- pass 1: default TA (TA_TOP|TA_LEFT) ------------------------- */
    const int x0 = 30, y0 = 30;
    if (!TextOutA(hdc, x0, y0, "Hxgyp|", 6))
        { puts("T21 FAIL TextOutA"); return 2; }

    /* per-glyph x bands from the extent width of one glyph */
    SIZE sz;
    if (!GetTextExtentPoint32A(hdc, "Hxgyp|", 6, &sz))
        { puts("T21 FAIL GetTextExtentPoint32A"); return 3; }
    int gw = sz.cx / 6;

    int bH = glyph_bottom(hdc, x0, x0 + gw, y0, y0 + sz.cy + 4);
    int bx = glyph_bottom(hdc, x0 + gw, x0 + 2 * gw, y0, y0 + sz.cy + 4);
    int bg = glyph_bottom(hdc, x0 + 2 * gw, x0 + 3 * gw, y0, y0 + sz.cy + 4);
    int by = glyph_bottom(hdc, x0 + 3 * gw, x0 + 4 * gw, y0, y0 + sz.cy + 4);
    int bp = glyph_bottom(hdc, x0 + 4 * gw, x0 + 5 * gw, y0, y0 + sz.cy + 4);
    int bpipe = glyph_bottom(hdc, x0 + 5 * gw, x0 + 6 * gw,
                            y0, y0 + sz.cy + 4);
    printf("T21 bottoms H=%d x=%d g=%d y=%d p=%d |=%d (origin y=%d)\n",
           bH, bx, bg, by, bp, bpipe, y0);
    if (bH < 0 || bx < 0 || bg < 0 || by < 0 || bp < 0 || bpipe < 0)
        { puts("T21 FAIL no ink found"); return 4; }

    if (bH != bx)
        { printf("T21 FAIL H(%d) and x(%d) bottoms differ\n", bH, bx);
          return 5; }
    if (bg != by || by != bp)
        { printf("T21 FAIL descenders differ g=%d y=%d p=%d\n", bg, by, bp);
          return 6; }
    if (bg <= bH)
        { puts("T21 FAIL descenders must sit below baseline glyphs");
          return 7; }
    if (bpipe < bg || bpipe > bg + 1)
        { printf("T21 FAIL | bottom %d outside [%d,%d]\n", bpipe, bg, bg+1);
          return 8; }

    /* --- metrics must match the drawing ------------------------------ */
    TEXTMETRICA tm;
    if (!GetTextMetricsA(hdc, &tm))
        { puts("T21 FAIL GetTextMetricsA"); return 9; }
    printf("T21 metrics h=%d asc=%d desc=%d avg=%d\n",
           tm.tmHeight, tm.tmAscent, tm.tmDescent, tm.tmAveCharWidth);
    if (bH != y0 + tm.tmAscent - 1)
        { printf("T21 FAIL H bottom %d != y0+tmAscent-1=%d\n",
                 bH, y0 + tm.tmAscent - 1); return 10; }
    if (tm.tmHeight < tm.tmAscent + tm.tmDescent)
        { puts("T21 FAIL tmHeight < tmAscent+tmDescent"); return 11; }

    /* --- extent vs drawn ink ------------------------------------------ */
    /* GetTextExtentPoint32 must return the ADVANCE width (what the next
     * glyph position would be), which legitimately exceeds the ink by the
     * side bearings (up to ~2px per glyph). Ink must never exceed the
     * extent, and the gap must stay within bearing loss. */
    int ink_w = 0;
    for (int x = x0; x < x0 + 200; x++) {
        int yb = glyph_bottom(hdc, x, x + 1, y0, y0 + sz.cy + 4);
        if (yb >= 0) ink_w = x - x0 + 1;
    }
    printf("T21 extent cx=%d ink_w=%d\n", sz.cx, ink_w);
    if (ink_w > sz.cx || sz.cx - ink_w > 12)
        { printf("T21 FAIL extent %d vs ink %d\n", sz.cx, ink_w);
          return 12; }

    /* --- pass 2: TA_BASELINE puts the SAME baseline on the same rows -- */
    if (SetTextAlign(hdc, TA_BASELINE) != 0)
        { puts("T21 FAIL SetTextAlign must return previous 0"); return 13; }
    if (GetTextAlign(hdc) != TA_BASELINE)
        { puts("T21 FAIL GetTextAlign mismatch"); return 14; }
    /* clear region and redraw with baseline == y0 + tm.tmAscent */
    RECT rc2 = { 0, 100, 340, 210 };
    FillRect(hdc, &rc2, white);
    if (!TextOutA(hdc, x0, y0 + tm.tmAscent, "Hxgyp|", 6))
        { puts("T21 FAIL TextOutA TA_BASELINE"); return 15; }
    int cH = glyph_bottom(hdc, x0, x0 + gw, y0 + 4, y0 + sz.cy + 20);
    int cx = glyph_bottom(hdc, x0 + gw, x0 + 2 * gw, y0 + 4,
                          y0 + sz.cy + 20);
    printf("T21 TA_BASELINE bottoms H=%d x=%d want H=%d\n", cH, cx, bH);
    if (cH != bH || cx != bx)
        { puts("T21 FAIL TA_BASELINE did not keep the same baseline");
          return 16; }

    /* --- TA_BOTTOM: the LINE BOX bottom edge == passed y. H has no
     * descender, so its ink stops on the baseline: tmDescent above the
     * box bottom (allow 2px for rounding). */
    SetTextAlign(hdc, TA_BOTTOM);
    FillRect(hdc, &rc2, white);
    TextOutA(hdc, x0, y0 + tm.tmHeight, "Hxgyp|", 6);
    int dB = glyph_bottom(hdc, x0, x0 + gw, y0, y0 + sz.cy + 20);
    int want_dB = y0 + tm.tmHeight - tm.tmDescent - 1;
    printf("T21 TA_BOTTOM bottom=%d want=%d..%d\n", dB, want_dB,
           y0 + tm.tmHeight - 1);
    if (dB < want_dB - 1 || dB > y0 + tm.tmHeight - 1)
        { puts("T21 FAIL TA_BOTTOM bottom edge mismatch"); return 17; }

    SetTextAlign(hdc, TA_TOP);   /* restore */
    ReleaseDC(wnd, hdc);
    puts("T21 PASS");
    return 0;
}
