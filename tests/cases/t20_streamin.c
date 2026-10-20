/* t20: EM_STREAMIN (license body feed) + VCL caption/class contracts.
 *
 * The Inno license page was blank because EM_STREAMIN was silently
 * ignored, and the wizard's controls drew wrong (raw '&' captions, no
 * radio glyph) because VCL subclass class names ('TNewRadioButton'...)
 * missed the standard-control kind table. This case pins the chain:
 *   - EM_STREAMIN with a guest EDITSTREAM callback pulls chunks to EOF
 *   - plain-text bytes under the SF_RTF flag (Inno's exact feed) render
 *     as text with CRLF collapsed to LF and paragraphs kept apart
 *   - real RTF reduces to visible text (fonttbl dropped, \par -> LF)
 *   - WM_GETTEXTLENGTH reports the FULL streamed length
 *   - WM_SETTEXT through DefWindowProc titles a top-level window (the
 *     VCL Perform(WM_SETTEXT) path that the wizard uses for its caption)
 *   - a VCL-style superclassed class ('TNewFakeRadio' wrapping the
 *     original BUTTON proc) keeps radio semantics (BM_SETCHECK/GETCHECK)
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define EM_STREAMIN_W 1097           /* WM_USER + 73 = 0x449 */
#define SF_RTF_W     0x0002
#define SF_TEXT_W    0x0001

typedef struct {
    DWORD dwCookie;
    DWORD dwError;
    DWORD (CALLBACK *pfnCallback)(DWORD, BYTE *, LONG, LONG *);
} EDITSTREAM_W32;                   /* x64 build: pointer-width pfn */

static const char *g_feed;          /* callback's source */
static DWORD g_pos;

static DWORD CALLBACK feed_cb(DWORD cookie, BYTE *buf, LONG cb, LONG *pcb)
{
    (void)cookie;
    size_t left = strlen(g_feed) - g_pos;
    size_t n = left < (size_t)cb ? left : (size_t)cb;
    memcpy(buf, g_feed + g_pos, n);
    g_pos += n;
    *pcb = (LONG)n;
    return 0;
}

static int stream_in(HWND re, const char *data, DWORD flags)
{
    EDITSTREAM_W32 es;
    g_feed = data;
    g_pos = 0;
    es.dwCookie = 0;
    es.dwError = 0;
    es.pfnCallback = feed_cb;
    LRESULT r = SendMessageA(re, EM_STREAMIN_W, flags, (LPARAM)&es);
    if (es.dwError != 0) {
        printf("T20 stream dwError=%lu\n", (unsigned long)es.dwError);
        return 0;
    }
    return r > 0;
}

static LRESULT CALLBACK radio_sub_proc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    static WNDPROC orig;
    if (m == 0x0001 && !orig)        /* WM_CREATE stash (never fires here) */
        return 0;
    if (!orig) {
        WNDCLASSA wc;
        GetClassInfoA(GetModuleHandleA(NULL), "BUTTON", &wc);
        orig = wc.lpfnWndProc;
    }
    return CallWindowProcA(orig, h, m, w, l);
}

int main(void)
{
    WNDCLASSA wc;
    memset(&wc, 0, sizeof wc);
    wc.lpfnWndProc = DefWindowProcA;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
    wc.lpszClassName = "WinNuxT20";
    if (!RegisterClassA(&wc)) { puts("T20 FAIL register"); return 1; }
    HWND parent = CreateWindowExA(0, "WinNuxT20", "", WS_OVERLAPPEDWINDOW,
                                  0, 0, 500, 400, NULL, NULL, wc.hInstance,
                                  NULL);
    if (!parent) { puts("T20 FAIL parent"); return 2; }

    /* --- the VCL caption contract: Perform(WM_SETTEXT) -> DefWindowProc --- */
    SendMessageA(parent, WM_SETTEXT, 0, (LPARAM)"T20 Wizard Title");
    char cap[64] = { 0 };
    GetWindowTextA(parent, cap, sizeof cap);
    if (strcmp(cap, "T20 Wizard Title") != 0) {
        printf("T20 FAIL wm_settext title='%s'\n", cap);
        return 3;
    }
    puts("T20 WM_SETTEXT titles the toplevel");

    HWND re = CreateWindowExA(0, "RichEdit20A", "", WS_CHILD | WS_VISIBLE |
                              ES_MULTILINE | ES_READONLY, 0, 0, 480, 200,
                              parent, (HMENU)201, wc.hInstance, NULL);
    if (!re) { puts("T20 FAIL richedit create"); return 4; }

    /* --- Inno's exact feed: PLAIN TEXT under the SF_RTF flag --- */
    if (!stream_in(re, "Alpha line one.\r\n\r\nBeta line two.\r\n",
                   SF_RTF_W)) {
        puts("T20 FAIL plain-under-rtf stream");
        return 5;
    }
    char body[256] = { 0 };
    SendMessageA(re, WM_GETTEXT, sizeof body, (LPARAM)body);
    if (strstr(body, "Alpha line one.") == NULL ||
        strstr(body, "Beta line two.") == NULL ||
        strchr(body, '\r') != NULL ||
        strstr(body, "\n\n") == NULL) {
        printf("T20 FAIL plain body='");
        for (char *p = body; *p; p++)
            putchar(*p == '\n' ? '~' : *p);
        printf("'\n");
        return 6;
    }
    LRESULT len = SendMessageA(re, WM_GETTEXTLENGTH, 0, 0);
    if (len != (LRESULT)strlen("Alpha line one.\n\nBeta line two.\n")) {
        printf("T20 FAIL plain len=%ld\n", (long)len);
        return 7;
    }
    puts("T20 plain text under SF_RTF: paragraphs intact, CRLF->LF");

    /* --- real RTF: destinations dropped, \par becomes LF --- */
    if (!stream_in(re,
        "{\\rtf1\\ansi{\\fonttbl{\\f0\\fnil;}}\\pard Hello RTF world."
        "\\par Second \\b bold\\b0  word.\\par}",
        SF_RTF_W)) {
        puts("T20 FAIL rtf stream");
        return 8;
    }
    memset(body, 0, sizeof body);
    SendMessageA(re, WM_GETTEXT, sizeof body, (LPARAM)body);
    if (strcmp(body, "Hello RTF world.\nSecond bold word.\n") != 0) {
        printf("T20 FAIL rtf body='");
        for (char *p = body; *p; p++)
            putchar(*p == '\n' ? '~' : *p);
        printf("'\n");
        return 9;
    }
    puts("T20 RTF stripped: fonttbl gone, \\par -> LF");

    /* --- SF_TEXT explicit plain stream --- */
    if (!stream_in(re, "Plain via SF_TEXT.", SF_TEXT_W)) {
        puts("T20 FAIL sf_text stream");
        return 10;
    }
    memset(body, 0, sizeof body);
    SendMessageA(re, WM_GETTEXT, sizeof body, (LPARAM)body);
    if (strcmp(body, "Plain via SF_TEXT.") != 0) {
        printf("T20 FAIL sf_text body='%s'\n", body);
        return 11;
    }
    puts("T20 SF_TEXT stream round-trips");

    /* --- VCL superclass name -> standard control semantics --- */
    {
        WNDCLASSA base, sub;
        memset(&base, 0, sizeof base);
        if (!GetClassInfoA(NULL, "BUTTON", &base)) {
            puts("T20 FAIL GetClassInfo BUTTON");
            return 12;
        }
        memset(&sub, 0, sizeof sub);
        sub.lpfnWndProc = radio_sub_proc;   /* forwards to the orig proc */
        sub.hInstance = wc.hInstance;
        sub.lpszClassName = "TNewFakeRadio"; /* VCL-style subclass name */
        if (!RegisterClassA(&sub)) {
            puts("T20 FAIL register TNewFakeRadio");
            return 13;
        }
        HWND radio = CreateWindowExA(0, "TNewFakeRadio", "I &accept it",
                                     WS_CHILD | WS_VISIBLE | 0x00000009L,
                                     0, 300, 200, 20, parent, (HMENU)301,
                                     wc.hInstance, NULL);
        if (!radio) {
            puts("T20 FAIL radio create");
            return 14;
        }
        SendMessageA(radio, 0x00F1 /* BM_SETCHECK */, 1, 0);
        if (SendMessageA(radio, 0x00F0 /* BM_GETCHECK */, 0, 0) != 1) {
            puts("T20 FAIL radio BM_GETCHECK (kind mapping)");
            return 15;
        }
        puts("T20 VCL-named radio keeps BUTTON semantics");
        DestroyWindow(radio);
    }

    /* --- zero-sized WS_VISIBLE toplevel: visible flag kept, no crash --- */
    HWND ghost = CreateWindowExA(WS_EX_TOOLWINDOW, "WinNuxT20", "ghost",
                                 WS_POPUP | WS_VISIBLE, 10, 10, 0, 0,
                                 NULL, NULL, wc.hInstance, NULL);
    if (!ghost || !IsWindowVisible(ghost)) {
        puts("T20 FAIL zero-sized window contract");
        return 16;
    }
    puts("T20 zero-sized popup: visible flag kept");
    DestroyWindow(ghost);

    DestroyWindow(re);
    DestroyWindow(parent);
    puts("T20 OK");
    return 0;
}
