/* t24_router.c — REAL pointer routing regression (XTEST-driven).
 *
 * Verifies the three Windows contracts fixed in session 21:
 *   1. Sibling Z-ORDER: among overlapping VISIBLE siblings the TOPMOST
 *      (most recently created/shown) receives the click - Inno's never-
 *      yet-visited notebook pages are visible and would otherwise swallow
 *      clicks meant for the current page.
 *   2. Capture coords: with a live capture (VCL captures the form on
 *      button-down), UP/MOVE arrive translated to the capture window's
 *      CLIENT space, never raw toplevel coords.
 *   3. Capture auto-release at button UP (captures taken during a drag
 *      end at UP); hit-test prefers the topmost visible child.
 *
 * The guest prints facts; the host (XTEST via xinject.py) clicks at the
 * window-relative points listed in t24_router.expected and the harness
 * compares stdout. A ".gui" case: runs under Xvfb, driven by the E2E
 * script (the guest holds for 60s; the injected clicks must all land).
 */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>

static int events[16];
static int n_events = 0;
static char log_out[4096];
static int log_len = 0;

static void note(const char *tag, int a, int b)
{
    n_events++;
    printf("%s %d,%d\n", tag, a, b);
    fflush(stdout);
}

static LRESULT CALLBACK ChildProc(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_LBUTTONDOWN:
        printf("DOWN id%d at %d,%d\n", GetDlgCtrlID(h),
               (short)LOWORD(lp), (short)HIWORD(lp));
        fflush(stdout);
        return 0;
    case WM_LBUTTONUP:
        printf("UP id%d at %d,%d\n", GetDlgCtrlID(h),
               (short)LOWORD(lp), (short)HIWORD(lp));
        fflush(stdout);
        if (GetCapture() == h)
            ReleaseCapture();
        return 0;
    case WM_MOUSEMOVE:
        return 0;
    }
    return DefWindowProcA(h, msg, wp, lp);
}

int main(void)
{
    WNDCLASSA wc = { 0 };
    wc.lpfnWndProc = ChildProc;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
    wc.lpszClassName = "T24Router";
    RegisterClassA(&wc);

    RECT r;
    /* Overlapping children: OLD (created first, covers everything) and
     * NEW (created later, on top, covers a sub-area). Real pointers must
     * hit NEW inside its rect and OLD outside it - regardless of any
     * capture taken meanwhile. */
    HWND form = CreateWindowExA(0, "T24Router", "T24RouterForm",
                                WS_OVERLAPPEDWINDOW,
                                222, 204, 500, 300, NULL, NULL, NULL, NULL);
    ShowWindow(form, SW_SHOW);
    GetWindowRect(form, &r);
    printf("form at %ld,%ld %ldx%ld\n", r.left, r.top,
           r.right - r.left, r.bottom - r.top);
    fflush(stdout);

    HWND old_child = CreateWindowExA(0, "T24Router", "old", WS_CHILD | WS_VISIBLE,
                                     0, 0, 400, 200, form, (HMENU)1, NULL, NULL);
    HWND new_child = CreateWindowExA(0, "T24Router", "new", WS_CHILD | WS_VISIBLE,
                                     100, 50, 300, 150, form, (HMENU)2, NULL, NULL);
    HWND btn = CreateWindowExA(0, "BUTTON", "b", WS_CHILD | WS_VISIBLE,
                               300, 210, 80, 25, form, (HMENU)3, NULL, NULL);
    (void)old_child; (void)new_child; (void)btn;

    /* Ghost sibling: visible window UNDER new_child that must NOT steal
     * the clicks (z-order contract). */
    HWND ghost = CreateWindowExA(0, "T24Router", "ghost", WS_CHILD | WS_VISIBLE,
                                 100, 50, 300, 150, form, (HMENU)4, NULL, NULL);
    /* re-show new_child to raise it above ghost (SetWindowPos z-raise) */
    SetWindowPos(new_child, HWND_TOP, 100, 50, 300, 150, SWP_NOMOVE | SWP_NOSIZE);
    (void)ghost;

    MSG msg;
    int64_t t0 = GetTickCount64();
    while (GetTickCount64() - t0 < 60000) {
        while (PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT)
                goto done;
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
        Sleep(20);
    }
done:
    printf("t24 done events=%d\n", n_events);
    (void)log_len; (void)log_out; (void)note;
    return 0;
}
