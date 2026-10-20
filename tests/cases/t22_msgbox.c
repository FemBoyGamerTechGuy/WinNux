/* t22: MessageBox contracts — the "closing hangs the wizard" fix.
 *
 * Inno's Exit-Setup confirm asks MessageBoxW(..., MB_YESNO): the old
 * stub printed the text and returned IDOK(1) — neither IDYES(6) nor
 * IDNO(7) — so every close attempt was silently ignored. The engine is
 * now a REAL modal dialog; WINNUX_MSGBOX_AUTO pins deterministic
 * answers (the DEFAULT button) for headless runs: that is what Enter
 * would do, so apps see the same outcome as a human pressing Enter.
 *
 * Interactive behavior (real buttons, owner disabled, Alt+mnemonic) is
 * exercised by the installer E2E run; this case pins the RETURN VALUES
 * and the auto-mode contract.
 */
#include <windows.h>
#include <stdio.h>

int main(void)
{
    /* MB_YESNO, default button 1 = Yes -> IDYES */
    int r1 = MessageBoxA(NULL, "Exit Setup?", "Exit Setup",
                        MB_YESNO | MB_ICONWARNING);
    if (r1 != IDYES) { printf("T22 FAIL YESNO got %d want %d\n", r1, IDYES); return 1; }

    /* MB_OKCANCEL, default 1 = OK -> IDOK */
    int r2 = MessageBoxA(NULL, "b", "c", MB_OKCANCEL);
    if (r2 != IDOK) { printf("T22 FAIL OKCANCEL got %d\n", r2); return 2; }

    /* MB_YESNOCANCEL -> IDYES; MB_RETRYCANCEL -> IDRETRY */
    int r3 = MessageBoxW(NULL, L"w", L"c", MB_YESNOCANCEL);
    if (r3 != IDYES) { printf("T22 FAIL YNC got %d\n", r3); return 3; }
    int r4 = MessageBoxA(NULL, "b", "c", MB_RETRYCANCEL | MB_ICONSTOP);
    if (r4 != IDRETRY) { printf("T22 FAIL RETRYCANCEL got %d\n", r4); return 4; }

    /* MB_DEFBUTTON2: the SECOND button is the default */
    int r5 = MessageBoxA(NULL, "b", "c", MB_OKCANCEL | MB_DEFBUTTON2);
    if (r5 != IDCANCEL) { printf("T22 FAIL DEFBUTTON2 got %d\n", r5); return 5; }
    int r6 = MessageBoxW(NULL, L"w", L"c", MB_YESNOCANCEL | MB_DEFBUTTON3);
    if (r6 != IDCANCEL) { printf("T22 FAIL DEFBUTTON3 got %d\n", r6); return 6; }

    /* MB_ABORTRETRYIGNORE -> default Abort */
    int r7 = MessageBoxA(NULL, "b", "c", MB_ABORTRETRYIGNORE);
    if (r7 != IDABORT) { printf("T22 FAIL ARI got %d\n", r7); return 7; }

    /* MessageBoxIndirectW/A: owner + text INSIDE the params struct */
    static const wchar_t wtxt[] = L"indirect wide";
    static const wchar_t wcap[] = L"indW";
    MSGBOXPARAMSW pw;
    memset(&pw, 0, sizeof pw);
    pw.cbSize = sizeof pw;
    pw.lpszText = wtxt;
    pw.lpszCaption = wcap;
    pw.dwStyle = MB_OK;
    int r8 = MessageBoxIndirectW(&pw);
    if (r8 != IDOK) { printf("T22 FAIL IndirectW got %d\n", r8); return 8; }

    MSGBOXPARAMSA pa;
    memset(&pa, 0, sizeof pa);
    pa.cbSize = sizeof pa;
    pa.lpszText = "indirect ansi";
    pa.lpszCaption = "indA";
    pa.dwStyle = MB_YESNO;
    int r9 = MessageBoxIndirectA(&pa);
    if (r9 != IDYES) { printf("T22 FAIL IndirectA got %d\n", r9); return 9; }

    puts("T22 PASS");
    return 0;
}
