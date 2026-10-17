/* t15_locale_font — real GetStringTypeW/LCMapStringW, GetUserName,
 * CreateFont/TextOut metrics, DrawText. */
#include <windows.h>
#include <stdio.h>

static int fails = 0;
static void check(int cond, const char *what)
{
    printf("%s: %s\n", cond ? "ok" : "FAIL", what);
    if (!cond) fails++;
}

int main(void)
{
    /* --- GetStringTypeW --- */
    WORD info[16];
    check(GetStringTypeW(CT_CTYPE1, L"Az9 ", 4, info), "GetStringTypeW ctype1");
    check(info[0] == (C1_UPPER | C1_ALPHA | C1_XDIGIT), "A = UPPER|ALPHA|XDIGIT");
    check(info[1] == (C1_LOWER | C1_ALPHA), "z = LOWER|ALPHA");
    check(info[2] == (C1_DIGIT | C1_XDIGIT), "9 = DIGIT|XDIGIT");
    check((info[3] & C1_SPACE) && (info[3] & C1_BLANK), "space = SPACE|BLANK");
    check(GetStringTypeW(CT_CTYPE1, L"\x00e9\x4e2d\x00df", 3, info + 4),
          "GetStringTypeW non-ASCII");
    check((info[4] & C1_LOWER) != 0, "U+00E9 lowercase");
    check((info[5] & C1_ALPHA) != 0, "U+4E2D alpha (CJK)");

    /* --- LCMapStringW case mapping (incl. non-ASCII) --- */
    WCHAR buf[32];
    int n = LCMapStringW(LOCALE_USER_DEFAULT, LCMAP_UPPERCASE,
                         L"abc\x00e9\x00df", -1, buf, 32);
    check(n == 6, "LCMapStringW uppercase len");
    check(!lstrcmpW(buf, L"ABC\x00c9\x1e9e") ||
          !lstrcmpW(buf, L"ABC\x00c9\x00df"),
          "LCMapStringW uppercase content (sharp-s variant)");
    n = LCMapStringW(LOCALE_USER_DEFAULT, LCMAP_LOWERCASE,
                     L"ABC", -1, buf, 32);
    check(n == 4 && !lstrcmpW(buf, L"abc"), "LCMapStringW lowercase");

    /* --- LCMapStringW sortkey --- */
    BYTE k1[64], k2[64];
    int l1 = LCMapStringW(LOCALE_USER_DEFAULT, LCMAP_SORTKEY,
                          L"apple", 5, (WCHAR *)k1, sizeof k1);
    int l2 = LCMapStringW(LOCALE_USER_DEFAULT, LCMAP_SORTKEY,
                          L"Apple", 5, (WCHAR *)k2, sizeof k2);
    check(l1 > 5 && l2 == l1, "sortkey lengths equal");
    int same_primary = l1 == l2 && memcmp(k1, k2, 10) == 0;
    check(same_primary, "sortkey case-insensitive primary weights");
    /* ordering: banana > apple */
    BYTE k3[64];
    LCMapStringW(LOCALE_USER_DEFAULT, LCMAP_SORTKEY, L"banana", 6,
                 (WCHAR *)k3, sizeof k3);
    check(memcmp(k1, k3, 12) < 0, "sortkey apple < banana");

    /* --- GetUserNameA --- */
    char user[256];
    DWORD cap = sizeof user;
    check(GetUserNameA(user, &cap), "GetUserNameA");
    check(cap > 1 && user[0] != '\0' && cap == strlen(user) + 1,
          "GetUserNameA name+length");
    printf("user: present (%d chars)\n", (int)(cap - 1));

    /* --- lstrcmpiW --- */
    check(lstrcmpiW(L"HeLLo", L"hello") == 0, "lstrcmpiW equal");
    check(lstrcmpiW(L"abc", L"abd") < 0, "lstrcmpiW ordering");

    /* --- fonts: CreateFont + metrics + extents --- */
    HFONT f = CreateFontA(-13, 0, 0, 0, 400, 0, 0, 0, 0, 0, 0, 0, 0,
                          "MS Shell Dlg");
    check(f != NULL, "CreateFontA");
    HDC hdc = GetDC(NULL);
    HGDIOBJ old = SelectObject(hdc, f);
    TEXTMETRICA tm;
    check(GetTextMetricsA(hdc, &tm), "GetTextMetricsA");
    check(tm.tmHeight >= 12 && tm.tmAveCharWidth >= 4,
          "metrics sane (cell + advance)");
    SIZE sz;
    check(GetTextExtentPoint32A(hdc, "hello", 5, &sz), "GetTextExtentPoint32A");
    check(sz.cx == 5 * tm.tmAveCharWidth && sz.cy == tm.tmHeight,
          "extent = n * advance");
    RECT rc = { 0, 0, 200, 40 };
    int h = DrawTextA(hdc, "PuTTY", -1, &rc, DT_CALCRECT | DT_LEFT | DT_SINGLELINE);
    check(h == tm.tmHeight && rc.right == 5 * tm.tmAveCharWidth,
          "DrawTextA DT_CALCRECT");
    SelectObject(hdc, old);
    ReleaseDC(NULL, hdc);
    check(DeleteObject(f), "DeleteObject(font)");

    printf("t15 locale+font: %s (%d failures)\n", fails ? "FAIL" : "PASS", fails);
    return fails ? 1 : 0;
}
