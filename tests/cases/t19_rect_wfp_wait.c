/* t19: rect/point + WaitMessage contracts (LuaForWindows field round).
 *
 * The Inno wizard's mouse/rect path crashed or spun under stubs:
 *   - WindowFromPoint's POINT arrives BY VALUE (8 bytes on i386 stdcall);
 *     the 1-word stub pop leaked half the arg frame per call and the next
 *     VCL ret jumped to dead stack (tmp+0x41458b -> 0x40bdc101).
 *   - SetRectEmpty-as-stub left VCL TRects uninitialized.
 *   - WaitMessage-as-stub returned instantly, so Delphi's TApplication.Idle
 *     spin-looped at 100% CPU once the wizard was up (101k calls/min).
 * This case pins the real implementations: rect writes, PtInRect's
 * inclusive-left/top exclusive-right/bottom semantics, WindowFromPoint
 * resolving the deepest visible window (and 0 off-screen), and WaitMessage
 * waking on a queued message.
 */
#include <windows.h>
#include <stdio.h>

int main(void)
{
    /* --- SetRect / SetRectEmpty: real writes into the caller's RECT --- */
    RECT r = { 0x11111111, 0x22222222, 0x33333333, 0x44444444 };
    if (!SetRect(&r, 1, 2, 3, 4))
        { puts("T19 FAIL SetRect ret"); return 1; }
    if (r.left != 1 || r.top != 2 || r.right != 3 || r.bottom != 4)
        { puts("T19 FAIL SetRect values"); return 2; }
    if (!SetRectEmpty(&r))
        { puts("T19 FAIL SetRectEmpty ret"); return 3; }
    if (r.left || r.top || r.right || r.bottom)
        { puts("T19 FAIL SetRectEmpty not zeroed"); return 4; }

    /* --- PtInRect: l/t inclusive, r/b exclusive (Windows contract) --- */
    RECT rc = { 10, 20, 110, 220 };
    POINT pts[] = {
        { 10, 20 }, { 60, 120 }, { 109, 219 },   /* inside  */
        { 110, 120 }, { 60, 220 }, { 9, 120 },  /* outside */
    };
    int want[] = { 1, 1, 1, 0, 0, 0 };
    for (int i = 0; i < 6; i++) {
        BOOL got = PtInRect(&rc, pts[i]);
        if (!!got != !!want[i]) {
            printf("T19 FAIL PtInRect(%d,%d)=%d want %d\n",
                   pts[i].x, pts[i].y, !!got, want[i]);
            return 5;
        }
    }

    /* --- WindowFromPoint: deepest visible window under a screen point --- */
    WNDCLASSA wc = { 0 };
    wc.lpfnWndProc = DefWindowProcA;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
    wc.lpszClassName = "WinNuxT19";
    if (!RegisterClassA(&wc)) { puts("T19 FAIL register"); return 6; }
    HWND parent = CreateWindowExA(0, "WinNuxT19", "T19 parent",
                                  WS_OVERLAPPEDWINDOW,
                                  150, 120, 300, 200, NULL, NULL,
                                  wc.hInstance, NULL);
    if (!parent) { puts("T19 FAIL parent"); return 7; }
    ShowWindow(parent, SW_SHOW);
    HWND child = CreateWindowExA(0, "BUTTON", "T19 child",
                                 WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                 10, 10, 80, 40, parent, (HMENU)77,
                                 wc.hInstance, NULL);
    if (!child) { puts("T19 FAIL child"); return 8; }

    RECT wr = { 0 };
    if (!GetWindowRect(parent, &wr))
        { puts("T19 FAIL GetWindowRect"); return 9; }

    /* Off-window point: no window (or at least not ours). */
    POINT off = { 40, 40 };
    HWND hf = WindowFromPoint(off);
    if (hf == parent || hf == child)
        { puts("T19 FAIL WindowFromPoint hit off-window"); return 10; }

    /* Parent client point outside the child: the parent. (Child rects are
     * CLIENT-relative, so map through ClientToScreen, not GetWindowRect.) */
    POINT pp = { 200, 150 };
    if (!ClientToScreen(parent, &pp))
        { puts("T19 FAIL ClientToScreen"); return 9; }
    if (WindowFromPoint(pp) != parent)
        { puts("T19 FAIL WindowFromPoint(parent area)"); return 11; }

    /* Over the child: the DEEPEST window, not the parent. */
    POINT cp = { 10 + 40, 10 + 20 };
    if (!ClientToScreen(parent, &cp))
        { puts("T19 FAIL ClientToScreen child"); return 9; }
    if (WindowFromPoint(cp) != child)
        { puts("T19 FAIL WindowFromPoint(child deepest)"); return 12; }

    /* --- WaitMessage: must wake (not spin, not block forever) when a
     * message is queued for this thread. --- */
    if (!PostMessageA(parent, WM_USER + 19, 1, 2))
        { puts("T19 FAIL PostMessage"); return 13; }
    if (!WaitMessage())
        { puts("T19 FAIL WaitMessage ret 0 with queued msg"); return 14; }
    MSG m;
    if (!PeekMessageA(&m, NULL, 0, 0, PM_REMOVE))
        { puts("T19 FAIL queued message vanished"); return 15; }
    if (m.message != WM_USER + 19 || (int)m.wParam != 1)
        { puts("T19 FAIL wrong message after WaitMessage"); return 16; }

    puts("T19 OK rects pt wfp wait");
    return 0;
}
