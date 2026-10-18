/* font_ft.c — FreeType text rasterizer, loaded via dlopen at runtime.
 *
 * Fits the project rule (zero compile-time deps beyond libc): we dlopen
 * libfreetype.so.6 and resolve a minimal function set. Struct layouts are
 * hand-derived overlays for x86-64 FreeType 2.x, but NOTHING is trusted
 * blindly: at init we render 'A' and self-verify the overlays by scanning
 * FT_FaceRec for the glyph-slot pointer (GlyphSlotRec.face == the face,
 * format == FT_GLYPH_FORMAT_BITMAP) and the size record (SizeRec.face ==
 * the face, x_ppem == the requested pixel size). If any check fails we
 * fall back to the embedded bitmap atlas and say so in the log.
 *
 * Why not real headers: the product must build on boxes without
 * freetype-dev. The overlay approach keeps that guarantee; the runtime
 * self-check keeps it honest (same philosophy as the X11 wire overlays).
 */
#include "wn_font.h"
#include "wn_log.h"
#include "wn_util.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>

/* --- minimal FreeType API (functions only, no structs needed) ---------------- */

typedef void *ft_library;
typedef void *ft_face;

static int  (*pFT_Init_FreeType)(ft_library *) __attribute__((unused));
static int  (*pFT_Done_FreeType)(ft_library) __attribute__((unused));
static int  (*pFT_New_Face)(ft_library, const char *, long, ft_face *);
static int  (*pFT_Done_Face)(ft_face);
static int  (*pFT_Set_Pixel_Sizes)(ft_face, unsigned, unsigned);
static int  (*pFT_Load_Char)(ft_face, unsigned long, int32_t);

#define FT_LOAD_RENDER 0x4
#define FT_GLYPH_FORMAT_BITMAP 0x62697473 /* 'bits' */

/* --- hand overlays (x64 FreeType 2.x) — offsets PROBED against the real
 * headers via scripts/dev tools (ftprobe) and verified at init by structure
 * signature. Ground truth from freetype 2.20 x86-64:
 *   FT_FaceRec: glyph@0x98, size@0xA0, charmap@0xA8, sizeof 0xF8.
 *   FT_GlyphSlotRec: face@8, metrics@0x30(64), linearAdv@0x70,
 *     advance.x@0x80, advance.y@0x88, format@0x90(4), FT_Bitmap@0x98
 *     (rows@0x98, width@0x9C, pitch@0xA0, buffer@0xA8), bitmap_left@0xC0,
 *     bitmap_top@0xC4, sizeof 0x130.
 *   FT_SizeRec: face@0, metrics@0x18 (x_ppem@0x18(2), x_scale@0x20,
 *     ascender@0x30, descender@0x38, height@0x40, max_advance@0x48,
 *     all 26.6 fixed), sizeof 0x58. */
typedef struct {
    void *library, *face, *next;
    uint32_t glyph_index;
    uint8_t pad20[0x10];
    uint8_t metrics[0x40];             /* 0x30..0x70 (unused) */
    int64_t linear_h, linear_v;        /* 0x70, 0x78 (unused) */
    int64_t advance_x;                 /* 0x80 (26.6) */
    int64_t advance_y;                 /* 0x88 */
    uint32_t format;                   /* 0x90 */
    uint8_t pad94[4];
    uint32_t rows, bwidth, pitch;      /* bitmap: 0x98, 0x9C, 0xA0 */
    uint8_t pada4[4];
    uint8_t *buffer;                   /* 0xA8 */
    uint8_t padb0[0x10];               /* num_grays..palette */
    int32_t bitmap_left;               /* 0xC0 */
    int32_t bitmap_top;                /* 0xC4 */
} ft_glyph_slot;

#if defined(__x86_64__)   /* overlays probed on the 64-bit lib only */
_Static_assert(offsetof(ft_glyph_slot, advance_x) == 0x80, "ft ABI");
_Static_assert(offsetof(ft_glyph_slot, format) == 0x90, "ft ABI");
_Static_assert(offsetof(ft_glyph_slot, rows) == 0x98, "ft ABI");
_Static_assert(offsetof(ft_glyph_slot, buffer) == 0xA8, "ft ABI");
_Static_assert(offsetof(ft_glyph_slot, bitmap_left) == 0xC0, "ft ABI");
#endif

typedef struct {
    void *face;                       /* 0 */
    uint8_t pad8[0x10];
    uint16_t x_ppem, y_ppem;          /* 0x18, 0x1A */
    uint8_t pad1c[4];
    int64_t x_scale, y_scale;         /* 0x20, 0x28 */
    int64_t ascender, descender;      /* 0x30, 0x38 (26.6) */
    int64_t height, max_advance;      /* 0x40, 0x48 (26.6) */
} ft_size;

#define WN_FT_MAX_SLOTS 32
typedef struct {
    ft_face face;
    ft_glyph_slot *slot;
    ft_size *size;
    int px_height;
    int fam;                         /* FT_SANS/SERIF/MONO */
    int want;                        /* 0 reg, 1 bold, 2 oblique */
    int has_bold_variant;            /* bold file exists for this family */
    struct wn_ft_glyph *glyphs[512];        /* hash chains keyed by cp */
    int glyph_count;
} wn_ft_font;

static ft_library g_lib;
static int g_ft_state;                /* 0 unknown, 1 ok, -1 failed */
static wn_ft_font g_slots[WN_FT_MAX_SLOTS];
static int g_slot_count;

int wn_ft_available(void)
{
    return g_ft_state == 1;
}

/* Mapped-memory guard: /proc/self/maps ranges (readable), parsed once.
 * Every candidate pointer must live inside a readable mapping before we
 * deref it — filters alone cannot prove a value is a real pointer (we saw
 * control_len==1, packed int16 metrics, and 0x10000 all get through). */
static struct { uintptr_t lo, hi; } g_maps[4096];
static int g_map_count;

static void load_maps(void)
{
    FILE *f = fopen("/proc/self/maps", "re");
    if (!f)
        return;
    char line[512];
    while (fgets(line, sizeof line, f) && g_map_count < 4096) {
        uintptr_t lo, hi;
        char perms[8] = { 0 };
        if (sscanf(line, "%lx-%lx %4s", (unsigned long *)&lo,
                   (unsigned long *)&hi, perms) != 3)
            continue;
        if (perms[0] != 'r')
            continue;
        g_maps[g_map_count].lo = lo;
        g_maps[g_map_count].hi = hi;
        g_map_count++;
    }
    fclose(f);
}

static int ptr_readable(uintptr_t v)
{
    if (!g_map_count)
        return 0;
    for (int a = 0, b = g_map_count - 1; a <= b; ) {
        int m = (a + b) / 2;
        if (v < g_maps[m].lo)
            b = m - 1;
        else if (v >= g_maps[m].hi)
            a = m + 1;
        else
            return 1;
    }
    return 0;
}

/* Find the glyph-slot and size pointers inside FT_FaceRec. PRIMARY: the
 * probed offsets (glyph@0x98, size@0xA0), validated by signature. FALLBACK:
 * scan the pointer-rich tail with the maps guard (covers other builds).
 * Every candidate must be inside a readable mapping — filters alone cannot
 * prove a value is a real pointer. */
static void scan_face(ft_face face, int px, ft_glyph_slot **slot_out,
                      ft_size **size_out)
{
    *slot_out = NULL;
    *size_out = NULL;
    /* The map snapshot goes STALE: FT_New_Face may extend the heap into
    * fresh pages after the table was loaded (this made verification flaky
    * — putty's late-init worked, an early CreateFont failed). Refresh. */
    g_map_count = 0;
    load_maps();
    /* primary: known offsets */
    {
        void *g = *(void **)((char *)face + 0x98);
        if (ptr_readable((uintptr_t)g) && ptr_readable((uintptr_t)g + 0xC8) &&
            *(void **)((char *)g + 8) == (void *)face) {
            ft_glyph_slot *c = (ft_glyph_slot *)g;
            if (c->format == FT_GLYPH_FORMAT_BITMAP &&
                c->advance_x > 0 && c->advance_x < 0x100000 &&
                c->bwidth < 512 && c->rows < 512)
                *slot_out = c;
        }
        void *z = *(void **)((char *)face + 0xA0);
        if (ptr_readable((uintptr_t)z) && ptr_readable((uintptr_t)z + 0x50) &&
            *(void **)z == (void *)face) {
            ft_size *s = (ft_size *)z;
            if (s->x_ppem == (uint16_t)px && s->y_ppem == (uint16_t)px &&
                s->x_scale > 16 &&
                (uint64_t)s->x_scale < 0x1000000000000ULL)
                *size_out = s;
        }
        if (*slot_out && *size_out)
            return;
    }
    /* fallback: scan the tail region (0x98..0xF0) */
    for (int off = 0x98; off <= 0xF0; off += 8) {
        uintptr_t v = *(uintptr_t *)((char *)face + off);
        if (v < 0x10000 || v == (uintptr_t)face || (v & 7))
            continue;
        if (!ptr_readable(v) || !ptr_readable(v + 0xC8))
            continue;
        void *p = (void *)v;
        if (!*slot_out && *(void **)((char *)p + 8) == (void *)face) {
            ft_glyph_slot *c = (ft_glyph_slot *)p;
            if (c->format == FT_GLYPH_FORMAT_BITMAP &&
                c->advance_x > 0 && c->advance_x < 0x100000 &&
                c->bwidth < 512 && c->rows < 512)
                *slot_out = c;
        }
        if (!*size_out && *(void **)p == (void *)face) {
            ft_size *s = (ft_size *)p;
            if (s->x_ppem == (uint16_t)px && s->y_ppem == (uint16_t)px &&
                s->x_scale > 16 &&
                (uint64_t)s->x_scale < 0x1000000000000ULL)
                *size_out = s;
        }
        if (*slot_out && *size_out)
            return;
    }
}

/* --- font file candidates ------------------------------------------------------
 * Probed in order; first readable wins. Arch (/usr/share/fonts/TTF) and
 * Debian (/usr/share/fonts/truetype/...) layouts both covered. */
typedef enum { FT_SANS, FT_SERIF, FT_MONO } ft_family;

static const char *const g_files[3][3] = {   /* [family][regular|bold|oblique] */
    {
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
        ";/usr/share/fonts/TTF/DejaVuSans.ttf"
        ";/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf"
        ";/usr/share/fonts/truetype/freefont/FreeSans.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
        ";/usr/share/fonts/TTF/DejaVuSans-Bold.ttf"
        ";/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf"
        ";/usr/share/fonts/truetype/freefont/FreeSansBold.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Oblique.ttf"
        ";/usr/share/fonts/TTF/DejaVuSans-Oblique.ttf"
        ";/usr/share/fonts/truetype/liberation/LiberationSans-Italic.ttf"
        ";/usr/share/fonts/truetype/freefont/FreeSansOblique.ttf",
    },
    {
        "/usr/share/fonts/truetype/dejavu/DejaVuSerif.ttf"
        ";/usr/share/fonts/TTF/DejaVuSerif.ttf"
        ";/usr/share/fonts/truetype/liberation/LiberationSerif-Regular.ttf"
        ";/usr/share/fonts/truetype/freefont/FreeSerif.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSerif-Bold.ttf"
        ";/usr/share/fonts/TTF/DejaVuSerif-Bold.ttf"
        ";/usr/share/fonts/truetype/liberation/LiberationSerif-Bold.ttf"
        ";/usr/share/fonts/truetype/freefont/FreeSerifBold.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSerif-Italic.ttf"
        ";/usr/share/fonts/TTF/DejaVuSerif-Italic.ttf"
        ";/usr/share/fonts/truetype/liberation/LiberationSerif-Italic.ttf"
        ";/usr/share/fonts/truetype/freefont/FreeSerifItalic.ttf",
    },
    {
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
        ";/usr/share/fonts/TTF/DejaVuSansMono.ttf"
        ";/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf"
        ";/usr/share/fonts/truetype/noto/NotoSansMono-Regular.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
        ";/usr/share/fonts/TTF/DejaVuSansMono-Bold.ttf"
        ";/usr/share/fonts/truetype/liberation/LiberationMono-Bold.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Oblique.ttf"
        ";/usr/share/fonts/TTF/DejaVuSansMono-Oblique.ttf"
        ";/usr/share/fonts/truetype/liberation/LiberationMono-Italic.ttf",
    },
};

static const char *first_readable(const char *list)
{
    static char buf[512];
    snprintf(buf, sizeof buf, "%s", list);
    char *save = NULL;
    for (char *p = strtok_r(buf, ";", &save); p;
         p = strtok_r(NULL, ";", &save))
        if (access(p, R_OK) == 0)
            return p;
    return NULL;
}

/* Map a Windows face name to a family bucket. */
static ft_family family_of(const char *face)
{
    if (!face || !*face)
        return FT_SANS;
    static const char *const mono[] = {
        "Courier New", "Consolas", "Lucida Console", "Fixedsys",
        "Courier", "Mono", "DejaVu Sans Mono", NULL,
    };
    static const char *const serif[] = {
        "Times New Roman", "MS Serif", "Georgia", "Cambria", "Garamond",
        "Book Antiqua", "Palatino Linotype", "DejaVu Serif", NULL,
    };
    for (int i = 0; mono[i]; i++)
        if (!strcasecmp(face, mono[i]))
            return FT_MONO;
    for (int i = 0; serif[i]; i++)
        if (!strcasecmp(face, serif[i]))
            return FT_SERIF;
    return FT_SANS;    /* MS Sans Serif, Tahoma, Segoe UI, MS Shell Dlg... */
}

static int ft_init(void)
{
#if !defined(__x86_64__)
    /* The struct overlays above were probed against the LP64 build of
     * libfreetype; a 32-bit lib has different offsets and the /maps-guided
     * signature scan would be wrong. 32-bit builds fall back to the bitmap
     * atlas (32-bit GUI fidelity is a later milestone). */
    return -1;
#else
    if (g_ft_state)
        return g_ft_state;
    void *h = dlopen("libfreetype.so.6", RTLD_LAZY | RTLD_LOCAL);
    if (!h) {
        wn_log(WN_LOG_INFO, "font: libfreetype.so.6 unavailable (%s) — "
               "using embedded bitmap font", dlerror());
        g_ft_state = -1;
        return -1;
    }
    load_maps();   /* initial snapshot; refreshed per scan */
    pFT_Init_FreeType = dlsym(h, "FT_Init_FreeType");
    pFT_Done_FreeType = dlsym(h, "FT_Done_FreeType");
    pFT_New_Face = dlsym(h, "FT_New_Face");
    pFT_Done_Face = dlsym(h, "FT_Done_Face");
    pFT_Set_Pixel_Sizes = dlsym(h, "FT_Set_Pixel_Sizes");
    pFT_Load_Char = dlsym(h, "FT_Load_Char");
    if (!pFT_Init_FreeType || !pFT_New_Face || !pFT_Done_Face ||
        !pFT_Set_Pixel_Sizes || !pFT_Load_Char) {
        wn_log(WN_LOG_WARN, "font: freetype symbols incomplete — bitmap only");
        g_ft_state = -1;
        return -1;
    }
    if (pFT_Init_FreeType(&g_lib) != 0) {
        g_ft_state = -1;
        return -1;
    }
    /* Self-verify the struct overlays with a real face before trusting. */
    const char *probe = first_readable(g_files[FT_SANS][0]);
    if (!probe)
        probe = first_readable(g_files[FT_MONO][0]);
    if (!probe)
        probe = first_readable(g_files[FT_SERIF][0]);
    if (probe) {
        ft_face f = NULL;
        if (pFT_New_Face(g_lib, probe, 0, &f) == 0 && f) {
            if (pFT_Set_Pixel_Sizes(f, 0, 16) == 0 &&
                pFT_Load_Char(f, 'A', FT_LOAD_RENDER) == 0) {
                ft_glyph_slot *slot = NULL;
                ft_size *size = NULL;
                scan_face(f, 16, &slot, &size);
                if (slot && size) {
                    g_ft_state = 1;
                    wn_log(WN_LOG_INFO, "font: FreeType active via '%s' "
                           "(overlays verified: %dx%d 'A')", probe,
                           (int)slot->bwidth, (int)slot->rows);
                } else {
                    wn_log(WN_LOG_WARN, "font: freetype struct verification "
                           "FAILED — bitmap font only");
                    g_ft_state = -1;
                }
            }
            pFT_Done_Face(f);
        }
    } else {
        wn_log(WN_LOG_INFO, "font: no system TTF files found — bitmap only");
        g_ft_state = -1;
    }
    if (g_ft_state != 1 && g_lib) {
        pFT_Done_FreeType(g_lib);
        g_lib = NULL;
    }
    return g_ft_state;
#endif
}

/* --- slot management ----------------------------------------------------------- */

/* Face selection: returns a slot index (>=0) or -1. Heights <= 0 or huge
 * are rejected (the bitmap atlas handles those). */
int wn_ft_select(const char *face_name, int px_height, int bold, int italic)
{
    if (ft_init() != 1)
        return -1;
    if (px_height < 5 || px_height > 200)
        return -1;
    ft_family fam = family_of(face_name);
    /* exact style match first, then degrade: bold->reg, italic->reg */
    static const int order[3][3] = {
        { 0, 1, 2 },   /* want regular: reg, bold, oblique */
        { 1, 0, 2 },   /* want bold:     bold, reg, oblique */
        { 2, 0, 1 },   /* want oblique:  oblique, reg, bold */
    };
    int want = bold ? 1 : (italic ? 2 : 0);
    const char *file = NULL;
    for (int i = 0; i < 3 && !file; i++)
        file = first_readable(g_files[fam][order[want][i]]);
    if (!file)
        return -1;

    /* reuse slot with identical (family, style, height) */
    for (int i = 0; i < g_slot_count; i++)
        if (g_slots[i].px_height == px_height && g_slots[i].slot &&
            g_slots[i].fam == (int)fam && g_slots[i].want == want)
            return i;
    if (g_slot_count >= WN_FT_MAX_SLOTS)
        return -1;

    ft_face f = NULL;
    if (pFT_New_Face(g_lib, file, 0, &f) != 0 || !f)
        return -1;
    if (pFT_Set_Pixel_Sizes(f, 0, (unsigned)px_height) != 0) {
        pFT_Done_Face(f);
        return -1;
    }
    /* trigger a render so the glyph slot exists, then scan it out */
    if (pFT_Load_Char(f, 'A', FT_LOAD_RENDER) != 0) {
        pFT_Done_Face(f);
        return -1;
    }
    ft_glyph_slot *slot = NULL;
    ft_size *size = NULL;
    scan_face(f, px_height, &slot, &size);
    if (!slot || !size) {
        pFT_Done_Face(f);
        return -1;
    }
    wn_ft_font *s = &g_slots[g_slot_count];
    memset(s, 0, sizeof *s);
    s->face = f;
    s->slot = slot;
    s->size = size;
    s->px_height = px_height;
    s->fam = fam;
    s->want = want;
    s->has_bold_variant = first_readable(g_files[fam][1]) != NULL;
    g_slot_count++;
    wn_log(WN_LOG_DEBUG, "font: slot %d = %s %dpx (fam=%d want=%d)",
           g_slot_count - 1, file, px_height, fam, want);
    return g_slot_count - 1;
}

/* --- glyph rendering ------------------------------------------------------------ */

static struct wn_ft_glyph *render_glyph(wn_ft_font *s, uint32_t cp)
{
    if (pFT_Load_Char(s->face, cp, FT_LOAD_RENDER) != 0)
        return NULL;
    ft_glyph_slot *g = s->slot;
    if (g->format != FT_GLYPH_FORMAT_BITMAP)
        return NULL;
    int w = (int)g->bwidth, h = (int)g->rows;
    struct wn_ft_glyph *out = wn_xcalloc(1, sizeof *out);
    out->cp = cp;
    out->left = (int16_t)g->bitmap_left;
    out->top = (int16_t)g->bitmap_top;
    out->w = (int16_t)(w > 0 ? w : 0);
    out->h = (int16_t)(h > 0 ? h : 0);
    out->adv_x = (int32_t)(g->advance_x >> 6);
    if (out->w > 0 && out->h > 0 && g->buffer) {
        out->alpha = wn_xmalloc((size_t)out->w * out->h);
        int pitch = (int)g->pitch;
        if (pitch < 0)
            pitch = -pitch;
        for (int y = 0; y < out->h; y++)
            memcpy(out->alpha + (size_t)y * out->w,
                   g->buffer + (size_t)y * pitch, (size_t)out->w);
    }
    return out;
}

const wn_ft_glyph_t *wn_ft_glyph(int slot_idx, uint32_t cp)
{
    if (slot_idx < 0 || slot_idx >= g_slot_count || ft_init() != 1)
        return NULL;
    wn_ft_font *s = &g_slots[slot_idx];
    uint32_t b = cp & 511;
    for (struct wn_ft_glyph *g = s->glyphs[b]; g; g = g->next)
        if (g->cp == cp)
            return g;
    if (s->glyph_count > 8192) {
        wn_log(WN_LOG_WARN, "font: glyph cache full (slot %d) — clearing",
               slot_idx);
        for (int i = 0; i < 512; i++) {
            for (struct wn_ft_glyph *g = s->glyphs[i]; g; ) {
                struct wn_ft_glyph *n = g->next;
                free(g->alpha);
                free(g);
                g = n;
            }
            s->glyphs[i] = NULL;
        }
        s->glyph_count = 0;
    }
    struct wn_ft_glyph *g = render_glyph(s, cp);
    if (!g) {   /* missing glyph: use the box/notdef via cp 0 */
        g = wn_xcalloc(1, sizeof *g);
        g->cp = cp;
        g->adv_x = s->px_height / 2;
    }
    g->next = s->glyphs[b];
    s->glyphs[b] = g;
    s->glyph_count++;
    return g;
}

void wn_ft_metrics(int slot_idx, int *ascent, int *descent, int *height,
                   int *avg_adv)
{
    if (slot_idx < 0 || slot_idx >= g_slot_count || !g_slots[slot_idx].size) {
        *ascent = 12;
        *descent = 3;
        *height = 15;
        *avg_adv = 8;
        return;
    }
    ft_size *z = g_slots[slot_idx].size;
    /* 26.6 fixed -> pixels, rounded */
    *ascent = (int)((z->ascender + 32) >> 6);
    *descent = (int)((-z->descender + 32) >> 6);
    *height = (int)((z->height + 32) >> 6);
    if (*ascent < 1) *ascent = 1;
    if (*descent < 0) *descent = 0;
    if (*height < *ascent + *descent)
        *height = *ascent + *descent;
    /* tmAveCharWidth: the face's max_advance is a TERRIBLE average (DejaVu
     * Bold reports 4129 units = 2x the em!). Windows uses the 'x' width. */
    const wn_ft_glyph_t *gx = wn_ft_glyph(slot_idx, 'x');
    int avg = gx ? gx->adv_x : (int)((z->max_advance + 32) >> 6);
    if (avg < 1)
        avg = 1;
    *avg_adv = avg;
}

int wn_ft_slot_bold(int slot_idx)
{
    if (slot_idx < 0 || slot_idx >= g_slot_count)
        return 0;
    return g_slots[slot_idx].want == 1 &&
           g_slots[slot_idx].has_bold_variant == 0;  /* fake bold needed */
}
