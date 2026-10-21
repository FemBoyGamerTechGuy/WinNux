/* t26_check_input.c — REAL-input checkbox regression (XTEST-driven).
 *
 * The field report: "the 'Don't create a Start Menu folder' checkbox
 * doesn't seem clickable, or I can't tell whether it changed." Verify
 * click, Space, and Alt+mnemonic toggling through the DIALOG MANAGER
 * (IsDialogMessage owns keyboard/mnemonics on Windows); BM_GETCHECK;
 * BN_CLICKED notification; and the checked state REPAINTS IMMEDIATELY —
 * the guest reads the check-glyph pixels back with GetPixel so the
 * harness can assert they actually changed.
 *
 * The checkbox is a real DLGTEMPLATE-created AUTOCHECKBOX (id 100) with
 * an Alt-mnemonic in its caption ("&Dont..."). Created via
 * CreateDialogParamA with an in-memory template pointer (the
 * IndirectParam variants are stubs).
 */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>

static int bn_clicked = 0;
static int check_state = -1;

static INT_PTR CALLBACK DlgProc(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
    (void)h; (void)lp;
    switch (msg) {
    case WM_INITDIALOG:
        return 1;
    case WM_COMMAND:
        if (HIWORD(wp) == BN_CLICKED && LOWORD(wp) == 100) {
            bn_clicked++;
            HWND cb = GetDlgItem(h, 100);
            check_state = (int)SendMessageA(cb, BM_GETCHECK, 0, 0);
            printf("BN_CLICKED #%d check=%d\n", bn_clicked, check_state);
            fflush(stdout);
        }
        return 1;
    }
    return 0;
}

int main(void)
{
    static const char *caption = "&Dont create a Start Menu folder";
    static const char *title = "T26Check";
    BYTE block[512];
    WORD *p = (WORD *)block;
    p = (WORD *)(((uintptr_t)p + 3) & ~(uintptr_t)3);
    /* DLGTEMPLATE (A variant: strings are byte arrays) */
    *p++ = (WORD)(WS_POPUP | WS_CAPTION | WS_SYSMENU);   /* style lo */
    *p++ = 0;                                            /* style hi */
    *p++ = 0; *p++ = 0;                                  /* exStyle */
    *p++ = 1;                                            /* cdit */
    *p++ = 0; *p++ = 0;                                  /* x, y */
    *p++ = 220; *p++ = 60;                               /* cx, cy */
    *p++ = 0;                                            /* menu: none */
    *p++ = 0;                                            /* class: none */
    { size_t n = strlen(title);
      for (size_t i = 0; i < n; i++) p[i] = (WORD)title[i];
      p += n; }
    *p++ = 0;                                            /* title NUL */
    /* item 1: AUTOCHECKBOX id 100 (DWORD-aligned) */
    p = (WORD *)(((uintptr_t)p + 3) & ~(uintptr_t)3);
    *p++ = (WORD)(WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX);
    *p++ = 0;                        /* style hi */
    *p++ = 0; *p++ = 0;              /* exStyle */
    *p++ = 10; *p++ = 10;            /* x, y */
    *p++ = 190; *p++ = 12;           /* cx, cy */
    *p++ = 100;                      /* id */
    *p++ = 0xFFFF; *p++ = 0x0080;    /* szOrOrd: class ordinal BUTTON */
    { size_t n = strlen(caption);
      for (size_t i = 0; i < n; i++) p[i] = (WORD)caption[i];
      p += n; }
    *p++ = 0;                        /* caption NUL */
    *p++ = 0;                        /* creation data count */

    HWND dlg = CreateDialogParamA(GetModuleHandleA(NULL),
        (LPCSTR)block, NULL, DlgProc, 0);
    if (!dlg) { printf("t26 FAIL dialog\n"); return 1; }
    ShowWindow(dlg, SW_SHOW);
    HWND cb = GetDlgItem(dlg, 100);
    if (!cb) { printf("t26 FAIL checkbox\n"); return 2; }
    SetFocus(cb);

    HDC dc = GetDC(cb);
    COLORREF c0 = GetPixel(dc, 4, 9);
    printf("glyph0=%06x check=%d\n", (unsigned)c0,
           (int)SendMessageA(cb, BM_GETCHECK, 0, 0));
    fflush(stdout);
    ReleaseDC(cb, dc);

    MSG msg;
    int64_t t0 = GetTickCount64();
    int64_t hold = 20000;
    const char *h = getenv("T26_HOLD");
    if (h)
        hold = atoi(h);
    int last_state = 0;
    while (GetTickCount64() - t0 < hold) {
        while (PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT)
                goto done;
            if (!IsDialogMessageA(dlg, &msg)) {
                TranslateMessage(&msg);
                DispatchMessageA(&msg);
            }
        }
        int st = (int)SendMessageA(cb, BM_GETCHECK, 0, 0);
        if (st != last_state) {
            HDC dc2 = GetDC(cb);
            COLORREF c = GetPixel(dc2, 4, 9);
            printf("state %d->%d glyph=%06x\n", last_state, st, (unsigned)c);
            fflush(stdout);
            ReleaseDC(cb, dc2);
            last_state = st;
        }
        Sleep(15);
    }
done:
    printf("t26 done bn=%d check=%d\n", bn_clicked,
           (int)SendMessageA(cb, BM_GETCHECK, 0, 0));
    return 0;
}
