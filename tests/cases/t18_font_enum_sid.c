/* t18_font_enum_sid — the LuaForWindows wizard-construction chain, pinned:
 *   - EnumFontsA/W + EnumFontFamiliesA/W must report a real font world
 *     (the old stub answered "not implemented": 0 faces, ERROR 120 garbage;
 *     Inno Setup probes fonts while building the wizard).
 *   - AllocateAndInitializeSid must honor the 11-word Windows contract:
 *     PSID out-param + BOOL return. The 10-word version never wrote pSid,
 *     so the Delphi RTL admin check freed a stale 0x1 stack slot
 *     (FreeSid(0x1) WARNs) and left every caller's stack 4 bytes skewed.
 * Face counts are exact on purpose: the advertised world is our table. */
#include <windows.h>
#include <stdio.h>

static int g_count;
static char g_first_face[64];

static int CALLBACK font_cb_a(const LOGFONTA *lf, const TEXTMETRICA *tm,
                              DWORD type, LPARAM lp)
{
    if (g_count == 0) {
        memcpy(g_first_face, lf->lfFaceName, 32);
        g_first_face[32] = 0;
    }
    (void)tm;
    g_count++;
    if (!(type & TRUETYPE_FONTTYPE))
        return 0;                    /* type must be TRUETYPE_FONTTYPE */
    if (lp != 0x5A5A5A5A)
        return 0;                    /* lparam roundtrip broken */
    return 1;
}

static int CALLBACK font_cb_stop(const LOGFONTA *lf, const TEXTMETRICA *tm,
                                 DWORD type, LPARAM lp)
{
    (void)lf; (void)tm; (void)type; (void)lp;
    return ++g_count > 1 ? 0 : 1;     /* continue once, then stop */
}

static int CALLBACK font_cb_w(const LOGFONTW *lf, const TEXTMETRICW *tm,
                              DWORD type, LPARAM lp)
{
    (void)tm; (void)type; (void)lp;
    if (g_count == 0) {
        int i;
        for (i = 0; i < 40 && lf->lfFaceName[i]; i++)
            g_first_face[i] = (char)lf->lfFaceName[i];
        g_first_face[i] = 0;
    }
    g_count++;
    return 1;
}

int main(void)
{
    HDC hdc = GetDC(NULL);
    if (!hdc) { puts("T18 FAIL no DC"); return 1; }

    /* --- full walk: every advertised face, exact count, lparam roundtrip --- */
    g_count = 0;
    g_first_face[0] = 0;
    int ret = EnumFontsA(hdc, NULL, font_cb_a, 0x5A5A5A5A);
    printf("T18 EnumFontsA: %d faces (ret=%d)\n", g_count, ret);
    if (g_count != 10 || ret != 1) { puts("T18 FAIL enum count"); return 2; }
    printf("T18 first face: %s\n", g_first_face);
    if (!g_first_face[0]) { puts("T18 FAIL empty face name"); return 3; }

    /* --- stop protocol: callback returning 0 halts + is the return --- */
    g_count = 0;
    ret = EnumFontsA(hdc, NULL, font_cb_stop, 0);
    if (ret != 0 || g_count != 2) { puts("T18 FAIL stop protocol"); return 4; }
    puts("T18 stop protocol: ret=0 after 1 continue");

    /* --- face filter: named face, exactly one callback --- */
    g_count = 0;
    ret = EnumFontsA(hdc, "Courier New", font_cb_a, 0x5A5A5A5A);
    if (ret != 1 || g_count != 1) { puts("T18 FAIL face filter"); return 5; }
    printf("T18 filter face: %s\n", g_first_face);
    if (lstrcmpiA(g_first_face, "Courier New"))
        { puts("T18 FAIL filtered name"); return 6; }

    /* --- alias: unknown-but-requested names are still served --- */
    g_count = 0;
    ret = EnumFontsA(hdc, "Wingdings", font_cb_a, 0x5A5A5A5A);
    if (ret != 1 || g_count != 1 || lstrcmpiA(g_first_face, "Wingdings"))
        { puts("T18 FAIL alias face"); return 7; }
    puts("T18 alias face: Wingdings served");

    /* --- W variants --- */
    g_count = 0;
    g_first_face[0] = 0;
    ret = EnumFontsW(hdc, NULL, font_cb_w, 0);
    if (ret != 1 || g_count != 10) { puts("T18 FAIL EnumFontsW count"); return 8; }
    if (lstrcmpiA(g_first_face, "MS Sans Serif"))
        { puts("T18 FAIL EnumFontsW name"); return 9; }
    puts("T18 EnumFontsW: 10 faces, first MS Sans Serif");

    g_count = 0;
    ret = EnumFontFamiliesA(hdc, NULL, font_cb_a, 0x5A5A5A5A);
    if (ret != 1 || g_count != 10) { puts("T18 FAIL families count"); return 10; }
    g_count = 0;
    ret = EnumFontFamiliesW(hdc, NULL, font_cb_w, 0);
    if (ret != 1 || g_count != 10) { puts("T18 FAIL familiesW count"); return 11; }
    puts("T18 EnumFontFamiliesA/W: 10 faces");

    /* --- AllocateAndInitializeSid: 11 words, BOOL return, pSid written --- */
    SID_IDENTIFIER_AUTHORITY nt_auth = SECURITY_NT_AUTHORITY;
    PSID sid = (PSID)0xdeadbeef;     /* sentinel: the call MUST overwrite */
    BOOL ok = AllocateAndInitializeSid(&nt_auth, 2,
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &sid);
    if (ok != TRUE) { puts("T18 FAIL AllocSid return"); return 12; }
    if (sid == (PSID)0xdeadbeef || sid == NULL) {
        puts("T18 FAIL AllocSid pSid not written"); return 13;
    }
    puts("T18 AllocAndInitSid: TRUE + pSid written");

    BYTE raw0 = ((BYTE *)sid)[0];    /* revision */
    BYTE raw1 = ((BYTE *)sid)[1];    /* subauthority count */
    if (raw0 != 1 || raw1 != 2) { puts("T18 FAIL SID bytes"); return 14; }
    puts("T18 SID bytes: rev=1 count=2");

    PSID sid2 = NULL;
    ok = AllocateAndInitializeSid(&nt_auth, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_USERS,
                                  0, 0, 0, 0, 0, 0, &sid2);
    if (!ok || !sid2 || sid2 == sid) { puts("T18 FAIL distinct SID"); return 15; }
    puts("T18 second SID distinct");

    if (FreeSid(sid) != NULL || FreeSid(sid2) != NULL) {
        puts("T18 FAIL FreeSid return"); return 16;
    }
    puts("T18 FreeSid x2: ok (no WARN refusals)");

    puts("T18 OK");
    return 0;
}
