/* t11: GUI vertical slice — window, message loop, WM_PAINT with GDI
 * drawing, timer, destroy, quit. Verifiable headless (exit code + stdout);
 * a paint counter proves WM_PAINT actually fired. */
#include <windows.h>
#include <stdio.h>

static int paints = 0;
static int painted_text = 0;

static LRESULT CALLBACK WndProc(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(h, &ps);
        RECT rc = { 0, 0, 400, 300 };
        HBRUSH bg = CreateSolidBrush(RGB(0, 80, 160));
        FillRect(dc, &rc, bg);
        DeleteObject(bg);
        SetTextColor(dc, RGB(255, 255, 255));
        SetBkMode(dc, TRANSPARENT);
        TextOutA(dc, 20, 20, "Hello WinNux GDI", 17);
        painted_text = 1;
        EndPaint(h, &ps);
        paints++;
        return 0;
    }
    case WM_TIMER:
        DestroyWindow(h);
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    case WM_CLOSE:
        DestroyWindow(h);
        return 0;
    }
    return DefWindowProcA(h, msg, wp, lp);
}

int main(void)
{
    WNDCLASSA wc = { 0 };
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
    wc.lpszClassName = "WinNuxT11";
    if (!RegisterClassA(&wc)) { puts("T11 FAIL register"); return 1; }

    HWND hwnd = CreateWindowExA(0, "WinNuxT11", "T11 GUI Hello",
                                WS_OVERLAPPEDWINDOW,
                                10, 10, 400, 300, NULL, NULL, wc.hInstance, NULL);
    if (!hwnd) { puts("T11 FAIL create"); return 2; }
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);
    SetTimer(hwnd, 1, 200, NULL);

    MSG msg;
    while (GetMessageA(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }

    printf("T11 paints=%d text=%d\n", paints, painted_text);
    if (paints == 0) { puts("T11 FAIL no paint"); return 3; }
    puts("T11 GUI OK");
    return 0;
}
