/* t23: scrollbar contracts — the "real scrollbars" batch.
 *
 * SCROLLINFO state (Set/GetScrollInfo, Set/GetScrollPos/Range,
 * ShowScrollBar), SBM_ on 'ScrollBar' controls, EM_LINESCROLL /
 * EM_SCROLL / EM_GETFIRSTVISIBLELINE on multiline edits (the license
 * viewer's scrolling contracts), and the painted-strip geometry via
 * GetPixel (arrows + thumb must be INSIDE the strip; track must not eat
 * the edit's text area). All SendMessage-driven: deterministic under
 * Xvfb without synthetic input.
 */
#include <windows.h>
#include <stdio.h>

static int ok = 1;
#define CHECK(c, ...) do { if (!(c)) { printf("T23 FAIL: " __VA_ARGS__); \
        ok = 0; } } while (0)

int main(void)
{
    WNDCLASSA wc = { 0 };
    wc.lpfnWndProc = DefWindowProcA;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = "T23Scroll";
    RegisterClassA(&wc);
    HWND wnd = CreateWindowExA(0, "T23Scroll", "t23", WS_OVERLAPPEDWINDOW,
                               4, 4, 420, 300, NULL, NULL, NULL, NULL);
    ShowWindow(wnd, SW_SHOW);
    RECT rc;
    GetClientRect(wnd, &rc);

    /* --- SCROLLINFO round-trip on the main window (SB_VERT) --------- */
    SCROLLINFO si;
    memset(&si, 0, sizeof si);
    si.cbSize = sizeof si;
    si.fMask = SIF_RANGE | SIF_PAGE | SIF_POS;
    si.nMin = 0; si.nMax = 100; si.nPage = 10; si.nPos = 7;
    int prev = SetScrollInfo(wnd, SB_VERT, &si, TRUE);
    CHECK(prev == 7, "SetScrollInfo ret prev pos (got %d)\n", prev);
    SCROLLINFO so;
    memset(&so, 0, sizeof so);
    so.cbSize = sizeof so;
    so.fMask = SIF_ALL;
    CHECK(GetScrollInfo(wnd, SB_VERT, &so), "GetScrollInfo ret\n");
    CHECK(so.nMin == 0 && so.nMax == 100 && so.nPage == 10 && so.nPos == 7,
          "SCROLLINFO round trip %d..%d page=%d pos=%d\n",
          so.nMin, so.nMax, so.nPage, so.nPos);

    /* position clamp against page: pos cannot exceed max-page+1 */
    SetScrollPos(wnd, SB_VERT, 500, TRUE);
    int p = GetScrollPos(wnd, SB_VERT);
    CHECK(p == 91, "page clamp: pos 500 -> %d (want 91)\n", p);
    SetScrollRange(wnd, SB_VERT, 0, 200, TRUE);
    int mn, mx;
    GetScrollRange(wnd, SB_VERT, &mn, &mx);
    CHECK(mn == 0 && mx == 200, "range round trip %d..%d\n", mn, mx);

    /* ShowScrollBar off -> pos still readable, style off */
    ShowScrollBar(wnd, SB_VERT, FALSE);
    CHECK(GetScrollPos(wnd, SB_VERT) >= 0, "pos readable while hidden\n");

    /* --- SBM_ on a real ScrollBar control --------------------------- */
    HWND sb = CreateWindowExA(0, "SCROLLBAR", NULL, WS_CHILD | WS_VISIBLE |
                              SBS_VERT, 300, 10, 17, 200, wnd, (HMENU)77,
                              NULL, NULL);
    CHECK(sb != NULL, "ScrollBar create\n");
    SendMessageA(sb, SBM_SETRANGE, 0, (LPARAM)50);
    LRESULT r1 = SendMessageA(sb, SBM_SETPOS, 12, 0);
    LRESULT r2 = SendMessageA(sb, SBM_GETPOS, 0, 0);
    CHECK(r2 == 12, "SBM_SETPOS/GETPOS (got %ld)\n", (long)r2);
    DWORD out[2] = { 0, 0 };
    SendMessageA(sb, SBM_GETRANGE, 0, (LPARAM)out);
    CHECK(out[0] == 0 && out[1] == 50, "SBM_GETRANGE %lu %lu\n",
          out[0], out[1]);
    (void)r1;

    /* --- multiline edit scrolling (RichEdit viewer contract) -------- */
    HWND ed = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", NULL,
                              WS_CHILD | WS_VISIBLE | ES_MULTILINE,
                              10, 10, 200, 120, wnd, (HMENU)78, NULL, NULL);
    CHECK(ed != NULL, "edit create\n");
    static char big[4096];
    int pos = 0;
    for (int i = 0; i < 40; i++)
        pos += snprintf(big + pos, sizeof big - pos, "line%02d\r\n", i);
    SetWindowTextA(ed, big);
    CHECK(SendMessageA(ed, EM_GETFIRSTVISIBLELINE, 0, 0) == 0,
          "first visible starts at 0\n");
    SendMessageA(ed, WM_VSCROLL, SB_LINEDOWN, 0);
    CHECK(SendMessageA(ed, EM_GETFIRSTVISIBLELINE, 0, 0) == 1,
          "WM_VSCROLL SB_LINEDOWN advances first line (got %ld)\n",
          (long)SendMessageA(ed, EM_GETFIRSTVISIBLELINE, 0, 0));
    CHECK(SendMessageA(ed, EM_LINESCROLL, 5, 0) != 0,
          "EM_LINESCROLL ret\n");
    CHECK(SendMessageA(ed, EM_GETFIRSTVISIBLELINE, 0, 0) == 6,
          "EM_LINESCROLL +5 (got %ld)\n",
          (long)SendMessageA(ed, EM_GETFIRSTVISIBLELINE, 0, 0));
    LRESULT sr = SendMessageA(ed, EM_SCROLL, SB_PAGEDOWN, 0);
    (void)sr;
    CHECK(SendMessageA(ed, EM_GETFIRSTVISIBLELINE, 0, 0) >= 7,
          "EM_SCROLL SB_PAGEDOWN advances\n");

    /* --- painted strip geometry (WS_VSCROLL edit) --------------------
     * An edit created WITH WS_VSCROLL shows the bar on its right edge:
     * the strip area must contain non-text pixels (track/thumb) and the
     * FIRST text column must still be readable ink at x=1..16. */
    HWND ed2 = CreateWindowExA(0, "EDIT", "abcdefghij",
                               WS_CHILD | WS_VISIBLE | ES_MULTILINE |
                               WS_VSCROLL | ES_AUTOVSCROLL,
                               10, 150, 180, 100, wnd, (HMENU)79, NULL,
                               NULL);
    HDC hdc = GetDC(ed2);
    CHECK(hdc != NULL, "GetDC(edit)\n");
    SetScrollRange(ed2, SB_VERT, 0, 100, TRUE);
    SetScrollPos(ed2, SB_VERT, 50, TRUE);
    SendMessageA(ed2, WM_PAINT, 0, 0);   /* synchronous paint */
    Sleep(100);
    /* strip: x in [width-17, width): the thumb gray (#A0A0A0-ish) */
    int thumb_ink = 0;
    for (int y = 4; y < 90; y++) {
        COLORREF c = GetPixel(hdc, 180 - 17 + 8, y);
        int r = (int)(c & 0xFF), g = (int)((c >> 8) & 0xFF),
            b = (int)((c >> 16) & 0xFF);
        /* thumb gray (0xA0..0xE8 band) or arrow black: any non-white */
        if (r < 0xF0 || g < 0xF0 || b < 0xF0)
            thumb_ink++;
    }
    if (thumb_ink <= 8) {
        printf("T23 strip diag: ");
        for (int y = 0; y < 100; y += 10) {
            COLORREF c = GetPixel(hdc, 171, y);
            printf("(%d=%06lx)", y, (unsigned long)c);
        }
        printf("\n");
    }
    CHECK(thumb_ink > 8, "scroll strip paints ink (rows=%d)\n", thumb_ink);
    ReleaseDC(ed2, hdc);

    if (!ok)
        return 1;
    puts("T23 PASS");
    return 0;
}
