/* t25_scroll_input.c — REAL-input scrollbar regression (XTEST-driven).
 *
 * The session-20 scrollbar tests passed because XSendEvent delivered
 * events DIRECTLY to the target window, bypassing the server delivery
 * path (implicit grab, capture routing, client-coord translation). On
 * the user's real machine scrollbars did nothing. This guest exposes a
 * multiline edit (with WS_VSCROLL adornment) + a standalone ScrollBar
 * control and prints state after every injected gesture; the host E2E
 * (run_e2e.sh) clicks arrows, clicks the trough, DRAGS THE THUMB WITH
 * MOTION OUTSIDE THE BAR (pointer grab), and wheels (buttons 4/5),
 * asserting the positions actually moved.
 */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

int main(void)
{
    /* Standalone scrollbar on the right, multiline edit filling the rest. */
    HWND form = CreateWindowExA(0, "#32770", "T25ScrollForm",
                                WS_OVERLAPPEDWINDOW,
                                100, 100, 420, 300, NULL, NULL, NULL, NULL);
    ShowWindow(form, SW_SHOW);

    HWND sb = CreateWindowExA(0, "SCROLLBAR", "", WS_CHILD | WS_VISIBLE | SBS_VERT,
                              380, 10, 17, 260, form, (HMENU)1, NULL, NULL);
    SetScrollRange(sb, SB_CTL, 0, 100, FALSE);
    SetScrollPos(sb, SB_CTL, 0, TRUE);

    HWND ed = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
                              WS_CHILD | WS_VISIBLE | WS_VSCROLL |
                              ES_MULTILINE | ES_AUTOVSCROLL,
                              10, 10, 360, 260, form, (HMENU)2, NULL, NULL);
    char text[4096];
    text[0] = 0;
    for (int i = 0; i < 200; i++) {
        char line[32];
        _snprintf(line, sizeof line, "line %03d\r\n", i);
        strcat(text, line);
    }
    SetWindowTextA(ed, text);

    printf("form up; sb=%p ed=%p\n", (void *)(uintptr_t)sb,
           (void *)(uintptr_t)ed);
    fflush(stdout);

    MSG msg;
    int64_t t0 = GetTickCount64();
    int64_t hold = 60000;
    const char *h = getenv("T25_HOLD");
    if (h)
        hold = atoi(h);
    while (GetTickCount64() - t0 < hold) {
        while (PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT)
                goto done;
            /* Report every WM_VSCROLL the form tree receives (Windows
             * sends an edit's WM_VSCROLL to its PARENT). */
            if (msg.message == WM_VSCROLL) {
                printf("vscroll hwnd=%lx code=%d pos=%d\n",
                       (unsigned long)(uintptr_t)msg.hwnd,
                       (int)LOWORD(msg.wParam), (int)HIWORD(msg.wParam));
                fflush(stdout);
            }
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
        Sleep(15);
    }
done:
    printf("sb pos final=%d\n", GetScrollPos(sb, SB_CTL));
    printf("edit first visible=%d\n",
           (int)SendMessageA(ed, EM_GETFIRSTVISIBLELINE, 0, 0));
    fflush(stdout);
    printf("t25 done\n");
    return 0;
}
