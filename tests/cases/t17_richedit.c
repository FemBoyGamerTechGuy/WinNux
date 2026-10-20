/* t17: RichEdit presence + Restart Manager + honest token contracts.
 *
 * The LuaForWindows Inno wizard died with a Delphi 0x0EEDFACE raise right
 * after LoadLibrary("RICHED20.DLL"/"RICHED32.DLL") and rstrtmgr probes
 * failed, and stub-120 OpenThreadToken fed the RTL garbage (FreeSid(0x1)).
 * This case pins every piece of that chain:
 *   - riched32/riched20/rstrtmgr LoadLibrary probes succeed
 *   - "RichEdit20A" window class creates + holds text (user32 builtin)
 *   - RmStartSession/RmGetList/RmEndSession = clean "no conflicts" chain
 *   - OpenThreadToken = FALSE + ERROR_NO_TOKEN (not stub garbage)
 *   - CheckTokenMembership = call ok, not-a-member
 */
#include <windows.h>
#include <stdio.h>

int main(void)
{
    /* --- DLL presence probes (Inno probes exactly these spellings) --- */
    HMODULE r20 = LoadLibraryA("RICHED20.DLL");
    if (!r20) { puts("T17 FAIL load riched20"); return 1; }
    HMODULE r32 = LoadLibraryA("riched32.dll");
    if (!r32) { puts("T17 FAIL load riched32"); return 2; }
    HMODULE rm = LoadLibraryA("Rstrtmgr.dll");
    if (!rm) { puts("T17 FAIL load rstrtmgr"); return 3; }

    /* --- RichEdit window class as a child control (Inno TRichEditViewer) --- */
    WNDCLASSA wc = { 0 };
    wc.lpfnWndProc = DefWindowProcA;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
    wc.lpszClassName = "WinNuxT17";
    if (!RegisterClassA(&wc)) { puts("T17 FAIL register parent"); return 4; }
    HWND parent = CreateWindowExA(0, "WinNuxT17", "T17", WS_OVERLAPPEDWINDOW,
                                  0, 0, 400, 300, NULL, NULL, wc.hInstance,
                                  NULL);
    if (!parent) { puts("T17 FAIL parent"); return 5; }
    HWND re = CreateWindowExA(0, "RichEdit20A", "license body text",
                              WS_CHILD | WS_VISIBLE | ES_READONLY,
                              0, 0, 380, 200, parent, (HMENU)101,
                              wc.hInstance, NULL);
    if (!re) { puts("T17 FAIL richedit20A create"); return 6; }
    char buf[64] = { 0 };
    int got = GetWindowTextA(re, buf, sizeof buf);
    if (got <= 0 || !buf[0]) { puts("T17 FAIL richedit text"); return 7; }
    printf("T17 richedit class text: %s\n", buf);
    DestroyWindow(re);
    DestroyWindow(parent);

    /* --- Restart Manager: clean zero-conflict session --- */
    DWORD (WINAPI *pStart)(DWORD *, DWORD, WCHAR *);
    DWORD (WINAPI *pGetList)(DWORD, UINT *, UINT *, void *, LPDWORD);
    DWORD (WINAPI *pEnd)(DWORD);
    pStart = (void *)GetProcAddress(rm, "RmStartSession");
    pGetList = (void *)GetProcAddress(rm, "RmGetList");
    pEnd = (void *)GetProcAddress(rm, "RmEndSession");
    if (!pStart || !pGetList || !pEnd) {
        puts("T17 FAIL rstrtmgr procs"); return 8;
    }
    DWORD session = 0;
    WCHAR key[33] = { 0 };
    DWORD rc = pStart(&session, 0, key);
    if (rc != 0 || !session) { puts("T17 FAIL RmStartSession"); return 9; }
    UINT needed = 99, count = 99;
    rc = pGetList(session, &needed, &count, NULL, NULL);
    if (rc != 0 || needed != 0 || count != 0) {
        puts("T17 FAIL RmGetList"); return 10;
    }
    rc = pEnd(session);
    if (rc != 0) { puts("T17 FAIL RmEndSession"); return 11; }
    puts("T17 restart manager: no files in use");

    /* --- Token honesty: not impersonating, not a member --- */
    SetLastError(0);
    HANDLE tok = (HANDLE)0x1234;
    BOOL ok = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, FALSE, &tok);
    if (ok || GetLastError() != 1008 /*ERROR_NO_TOKEN*/) {
        puts("T17 FAIL OpenThreadToken contract"); return 12;
    }
    BOOL member = 99;
    ok = CheckTokenMembership(NULL, (PSID)0x1234, &member);
    if (!ok || member) { puts("T17 FAIL CheckTokenMembership"); return 13; }
    puts("T17 tokens: plain user, no impersonation");

    puts("T17 OK");
    return 0;
}
