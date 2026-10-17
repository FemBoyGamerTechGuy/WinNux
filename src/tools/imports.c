/* imports.c — `winnux imports <exe>`: static import analysis.
 *
 * Walks the import tables (regular + delay-load) of a PE32 or PE32+ image and
 * classifies every imported function:
 *
 *   ok           builtin DLL provides a real export
 *   stub         builtin DLL known, function missing -> loud stub at call time
 *   native       resolved from a real PE DLL found on disk (app dir/system32)
 *   native-miss  real PE DLL on disk but the export is absent -> stub at load
 *   MISSING DLL  the DLL itself is nowhere -> `winnux run` will fail to load
 *
 * 32-bit (i386) images are parsed and analyzed (their import lists still drive
 * priorities) but flagged: WinNux does not load them yet (WoW64-style 32-bit
 * support is a major TODO item, tracked in TODO.md).
 *
 * Exit code: 0 = image loadable, 1 = missing DLL / malformed table / 32-bit
 * image, 2 = usage or parse error.
 */
#include "wn_dll.h"
#include "wn_module.h"
#include "wn_process.h"
#include "wn_util.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

typedef enum {
    ST_OK = 0,
    ST_STUB,
    ST_NATIVE,
    ST_NATIVE_MISS,
    ST_MISS_DLL,
    ST_BAD
} imp_status;

static const char *st_name(imp_status s)
{
    switch (s) {
    case ST_OK:          return "ok";
    case ST_STUB:        return "stub";
    case ST_NATIVE:      return "native";
    case ST_NATIVE_MISS: return "native-miss";
    case ST_MISS_DLL:    return "MISSING DLL";
    default:             return "bad-rva";
    }
}

typedef struct {
    char       dll[128];
    char       sym[192];
    uint32_t   ordinal;
    int        by_ordinal;
    int        delay;
    int        grouped;
    imp_status st;
} imp_rec;

static imp_rec *g_recs;
static size_t   g_nrecs, g_cap;

static void add_rec(const char *dll, const char *sym, uint32_t ordinal,
                    int by_ordinal, int delay)
{
    if (g_nrecs == g_cap) {
        g_cap = g_cap ? g_cap * 2 : 64;
        g_recs = wn_xrealloc(g_recs, g_cap * sizeof *g_recs);
    }
    imp_rec *r = &g_recs[g_nrecs++];
    memset(r, 0, sizeof *r);
    snprintf(r->dll, sizeof r->dll, "%.100s", dll ? dll : "?");
    snprintf(r->sym, sizeof r->sym, "%.180s", sym ? sym : "");
    r->ordinal = ordinal;
    r->by_ordinal = by_ordinal;
    r->delay = delay;
    r->st = ST_BAD;
}

/* --- raw-file PE view ------------------------------------------------------ */

typedef struct {
    const uint8_t *buf;
    size_t         size;
    const wn_image_section_header *sec;
    uint32_t       nsec;
    uint32_t       size_of_headers;
    uint64_t       image_base;
    uint32_t       entry_rva;
    uint16_t       machine;
    uint16_t       subsystem;
    int            is64;
    int            is_dll;
    const uint8_t *opt_base;   /* optional header start in the raw file */
} pe_view;

static const wn_image_data_directory *pe_dir(const pe_view *v, uint32_t index)
{
    size_t off = v->is64 ? offsetof(wn_image_optional_header64, dirs)
                         : offsetof(wn_image_optional_header32, dirs);
    return (const wn_image_data_directory *)(v->opt_base + off
           + (size_t)index * sizeof(wn_image_data_directory));
}

/* Map an RVA to a pointer into the raw file image (headers region maps 1:1).
 * Virtual-only (bss) ranges return NULL, as do any bounds violations. */
static const uint8_t *rva_ptr(const pe_view *v, uint32_t rva, uint64_t len)
{
    if (!rva)
        return NULL;
    uint64_t r = rva;
    if (r >= v->size_of_headers) {
        const wn_image_section_header *hit = NULL;
        for (uint32_t i = 0; i < v->nsec; i++) {
            const wn_image_section_header *s = &v->sec[i];
            uint32_t vsz = s->virtual_size ? s->virtual_size : s->size_of_raw_data;
            if (r >= s->virtual_address && r < s->virtual_address + (uint64_t)vsz) {
                hit = s;
                break;
            }
        }
        if (!hit)
            return NULL;
        uint64_t insec = r - hit->virtual_address;
        if (hit->size_of_raw_data == 0 || insec >= hit->size_of_raw_data)
            return NULL;   /* zero-fill part: no file backing */
        r = insec + hit->pointer_to_raw_data;
    }
    if (r + len > v->size || r + len < r)
        return NULL;
    return v->buf + r;
}

/* Bounded C-string copy out of the raw image (never runs off the file). */
static int cstr_at(const pe_view *v, const uint8_t *p, char *out, size_t cap)
{
    if (!p || cap == 0)
        return -1;
    const uint8_t *end = v->buf + v->size;
    size_t i = 0;
    while (p + i < end && p[i] && i + 1 < cap) {
        out[i] = (char)p[i];
        i++;
    }
    out[i] = '\0';
    return 0;
}

static uint8_t *read_whole(const char *path, size_t *out_size)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long sz = ftell(f);
    if (sz <= 0 || fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }
    uint8_t *b = wn_xmalloc((size_t)sz);
    size_t got = fread(b, 1, (size_t)sz, f);
    fclose(f);
    if (got != (size_t)sz) {
        free(b);
        return NULL;
    }
    *out_size = (size_t)sz;
    return b;
}

/* Validate + index a PE image. Returns 0, or -1 with a message. */
static int pe_open(const char *path, pe_view *v, uint8_t **buf, size_t *size)
{
    memset(v, 0, sizeof *v);
    *buf = read_whole(path, size);
    if (!*buf) {
        fprintf(stderr, "winnux imports: cannot read '%s'\n", path);
        return -1;
    }
    v->buf = *buf;
    v->size = *size;
    if (v->size < sizeof(wn_image_dos_header)) {
        fprintf(stderr, "winnux imports: file too small\n");
        return -1;
    }
    const wn_image_dos_header *dos = (const void *)v->buf;
    if (dos->e_magic != WN_IMAGE_DOS_SIGNATURE) {
        fprintf(stderr, "winnux imports: no MZ signature\n");
        return -1;
    }
    if (dos->e_lfanew <= 0 || (size_t)dos->e_lfanew + 24 > v->size) {
        fprintf(stderr, "winnux imports: bad e_lfanew\n");
        return -1;
    }
    uint32_t sig;
    memcpy(&sig, v->buf + dos->e_lfanew, 4);
    if (sig != WN_IMAGE_NT_SIGNATURE) {
        fprintf(stderr, "winnux imports: no PE signature\n");
        return -1;
    }
    const wn_image_file_header *fh =
        (const void *)(v->buf + dos->e_lfanew + 4);
    v->machine = fh->machine;
    v->nsec = fh->number_of_sections;
    v->is_dll = (fh->characteristics & WN_IMAGE_FILE_DLL) != 0;
    v->opt_base = v->buf + dos->e_lfanew + 4 + sizeof(wn_image_file_header);
    if (fh->size_of_optional_header < sizeof(wn_image_optional_header32)) {
        fprintf(stderr, "winnux imports: optional header too small\n");
        return -1;
    }
    uint16_t magic;
    memcpy(&magic, v->opt_base, 2);
    if (magic == WN_IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        v->is64 = 1;
        const wn_image_optional_header64 *oh = (const void *)v->opt_base;
        v->image_base = oh->image_base;
        v->entry_rva = oh->address_of_entry_point;
        v->subsystem = oh->subsystem;
        v->size_of_headers = oh->size_of_headers;
    } else if (magic == WN_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        v->is64 = 0;
        const wn_image_optional_header32 *oh = (const void *)v->opt_base;
        v->image_base = oh->image_base;
        v->entry_rva = oh->address_of_entry_point;
        v->subsystem = oh->subsystem;
        v->size_of_headers = oh->size_of_headers;
    } else {
        fprintf(stderr, "winnux imports: unknown optional header magic 0x%x\n",
                magic);
        return -1;
    }
    /* Section table follows the optional header. */
    const uint8_t *sectab = v->opt_base + fh->size_of_optional_header;
    if ((size_t)(sectab - v->buf) + (size_t)v->nsec * 40 > v->size) {
        fprintf(stderr, "winnux imports: section table out of bounds\n");
        return -1;
    }
    v->sec = (const wn_image_section_header *)sectab;
    return 0;
}

/* --- import walking ---------------------------------------------------------- */

static void walk_thunk_array(const pe_view *v, const char *dll, uint32_t rva,
                             int delay)
{
    for (uint32_t k = 0; ; k++) {
        if (v->is64) {
            const uint8_t *p = rva_ptr(v, rva + (uint64_t)k * 8, 8);
            if (!p)
                return;
            uint64_t t;
            memcpy(&t, p, 8);
            if (!t)
                return;
            if (t & WN_IMAGE_ORDINAL_FLAG64) {
                add_rec(dll, "", (uint32_t)(t & 0xFFFF), 1, delay);
            } else {
                const wn_image_import_by_name *ibn = (const void *)rva_ptr(v, (uint32_t)t, 3);
                char name[192];
                if (!ibn || cstr_at(v, (const uint8_t *)ibn->name, name,
                                    sizeof name) != 0) {
                    add_rec(dll, "<bad import-by-name RVA>", 0, 0, delay);
                    continue;
                }
                add_rec(dll, name, 0, 0, delay);
            }
        } else {
            const uint8_t *p = rva_ptr(v, rva + (uint64_t)k * 4, 4);
            if (!p)
                return;
            uint32_t t;
            memcpy(&t, p, 4);
            if (!t)
                return;
            if (t & WN_IMAGE_ORDINAL_FLAG32) {
                add_rec(dll, "", t & 0xFFFF, 1, delay);
            } else {
                const wn_image_import_by_name *ibn = (const void *)rva_ptr(v, t, 3);
                char name[192];
                if (!ibn || cstr_at(v, (const uint8_t *)ibn->name, name,
                                    sizeof name) != 0) {
                    add_rec(dll, "<bad import-by-name RVA>", 0, 0, delay);
                    continue;
                }
                add_rec(dll, name, 0, 0, delay);
            }
        }
    }
}

static void walk_regular_imports(const pe_view *v)
{
    const wn_image_data_directory *d = pe_dir(v, WN_IMAGE_DIR_IMPORT);
    if (!d->virtual_address || !d->size)
        return;
    for (uint32_t off = d->virtual_address; ; off += 20) {
        const uint8_t *p = rva_ptr(v, off, 20);
        if (!p)
            return;
        const wn_image_import_descriptor *desc = (const void *)p;
        if (!desc->name)
            return;
        char dll[128];
        if (cstr_at(v, rva_ptr(v, desc->name, 1), dll, sizeof dll) != 0) {
            add_rec("<bad DLL name RVA>", "", 0, 0, 0);
            continue;
        }
        uint32_t trva = desc->original_first_thunk
                      ? desc->original_first_thunk : desc->first_thunk;
        walk_thunk_array(v, dll, trva, 0);
    }
}

static void walk_delay_imports(const pe_view *v)
{
    const wn_image_data_directory *d = pe_dir(v, WN_IMAGE_DIR_DELAY_IMPORT);
    if (!d->virtual_address || !d->size)
        return;
    const uint32_t sz_desc = 32;   /* ImgDelayDescr is 8x uint32 */
    for (uint32_t off = d->virtual_address; ; off += sz_desc) {
        const uint8_t *p = rva_ptr(v, off, sz_desc);
        if (!p)
            return;
        const wn_image_delayload_descriptor *did = (const void *)p;
        if (!did->sz_name)
            return;
        uint32_t name_rva = did->sz_name;
        uint32_t int_rva = did->p_int;
        if (did->gr_attrs & 1) {   /* VAs instead of RVAs (old toolchains) */
            if (name_rva >= (uint64_t)v->image_base)
                name_rva = (uint32_t)(name_rva - v->image_base);
            if (int_rva >= (uint64_t)v->image_base)
                int_rva = (uint32_t)(int_rva - v->image_base);
        }
        char dll[128];
        if (cstr_at(v, rva_ptr(v, name_rva, 1), dll, sizeof dll) != 0) {
            add_rec("<bad delay DLL name RVA>", "", 0, 0, 1);
            continue;
        }
        uint32_t trva = int_rva ? int_rva : did->p_iat;
        walk_thunk_array(v, dll, trva, 1);
    }
}

/* --- classification ------------------------------------------------------------ */

static const wn_builtin_dll *find_builtin(const char *dll)
{
    const char *norm = wn_dll_normalize_name(dll);
    char low[128];
    wn_strlower(low, sizeof low, norm);
    for (const wn_builtin_dll *b = wn_builtin_table; b->name; b++)
        if (wn_strcaseeq(b->name, low))
            return b;
    return NULL;
}

static int builtin_has(const wn_builtin_dll *b, const char *sym)
{
    for (const wn_export_entry *e = b->exports; e && e->name; e++)
        if (!strcmp(e->name, sym))
            return 1;
    return 0;
}

/* Does the native PE file export this name/ordinal? 1/0, -1 = cannot open. */
static int native_export_check(const char *path, const char *sym,
                               uint32_t ordinal, int by_ordinal)
{
    pe_view v;
    uint8_t *buf;
    size_t size;
    if (pe_open(path, &v, &buf, &size) != 0)
        return -1;
    int found = 0;
    const wn_image_data_directory *d = pe_dir(&v, WN_IMAGE_DIR_EXPORT);
    if (d->virtual_address && d->size) {
        const wn_image_export_directory *ed =
            (const void *)rva_ptr(&v, d->virtual_address, sizeof *ed);
        if (ed) {
            if (by_ordinal) {
                uint64_t idx = ordinal - ed->ordinal_base;
                if (idx < ed->number_of_functions) {
                    const uint8_t *fp = rva_ptr(&v, ed->address_of_functions
                        + (uint32_t)(idx * 4), 4);
                    if (fp) {
                        uint32_t frva;
                        memcpy(&frva, fp, 4);
                        found = frva != 0;
                    }
                }
            } else {
                for (uint32_t k = 0; k < ed->number_of_names && !found; k++) {
                    const uint8_t *np = rva_ptr(&v, ed->address_of_names
                        + k * 4, 4);
                    if (!np)
                        break;
                    uint32_t nrva;
                    memcpy(&nrva, np, 4);
                    char name[192];
                    if (cstr_at(&v, rva_ptr(&v, nrva, 1), name, sizeof name) == 0
                        && !strcmp(name, sym))
                        found = 1;
                }
            }
        }
    }
    free(buf);
    return found;
}

static int find_dll_file(const char *dll, const char *exedir,
                         char *out, size_t cap)
{
    const char *base = strrchr(dll, '\\');
    base = base ? base + 1 : dll;
    const char *slash = strrchr(base, '/');
    if (slash)
        base = slash + 1;
    char prefix[1024];
    wn_prefix_default(prefix, sizeof prefix);
    const char *dirs[5];
    int n = 0;
    dirs[n++] = exedir;
    char sysdir[1100];
    snprintf(sysdir, sizeof sysdir, "%s/drive_c/windows/system32", prefix);
    dirs[n++] = sysdir;
    char windir[1100];
    snprintf(windir, sizeof windir, "%s/drive_c/windows", prefix);
    dirs[n++] = windir;
    dirs[n++] = ".";
    for (int i = 0; i < n; i++) {
        snprintf(out, cap, "%s/%s", dirs[i], base);
        struct stat st;
        if (stat(out, &st) == 0 && S_ISREG(st.st_mode))
            return 1;
    }
    return 0;
}

static void classify_rec(imp_rec *r, const char *exedir)
{
    const wn_builtin_dll *b = find_builtin(r->dll);
    if (b) {
        if (r->by_ordinal) {
            char key[16];
            snprintf(key, sizeof key, "#%u", r->ordinal);
            r->st = builtin_has(b, key) ? ST_OK : ST_STUB;
        } else {
            r->st = builtin_has(b, r->sym) ? ST_OK : ST_STUB;
        }
        return;
    }
    char path[1400];
    if (find_dll_file(r->dll, exedir, path, sizeof path)) {
        int has = native_export_check(path, r->sym, r->ordinal, r->by_ordinal);
        r->st = has == 1 ? ST_NATIVE : ST_NATIVE_MISS;
        return;
    }
    r->st = ST_MISS_DLL;
}

/* --- report --------------------------------------------------------------------- */

int wn_cmd_imports(int argc, char **argv)
{
    int verbose = 0;
    int argi = 0;
    while (argi < argc && argv[argi][0] == '-') {
        if (!strcmp(argv[argi], "-v") || !strcmp(argv[argi], "--verbose")) {
            verbose = 1;
            argi++;
        } else if (!strcmp(argv[argi], "--prefix") && argi + 1 < argc) {
            setenv("WINNUX_PREFIX", argv[++argi], 1);
            argi++;
        } else {
            fprintf(stderr, "winnux imports: unknown option '%s'\n",
                    argv[argi]);
            return 2;
        }
    }
    if (argi >= argc) {
        fprintf(stderr, "usage: winnux imports [-v] app.exe\n");
        return 2;
    }
    const char *path = argv[argi];

    pe_view v;
    uint8_t *buf;
    size_t size;
    if (pe_open(path, &v, &buf, &size) != 0) {
        free(buf);
        return 2;
    }

    const char *arch = v.is64 ? "PE32+ (x86_64)"
                    : "PE32 (i386, 32-bit — not loadable yet, see TODO.md)";
    printf("%s: %s%s, subsystem %u, %u sections, entry rva 0x%x\n",
           path, arch, v.is_dll ? " DLL" : "", v.subsystem, v.nsec,
           v.entry_rva);
    if (v.machine != WN_IMAGE_FILE_MACHINE_I386 &&
        v.machine != WN_IMAGE_FILE_MACHINE_AMD64)
        printf("  note: unusual machine 0x%x\n", v.machine);

    walk_regular_imports(&v);
    walk_delay_imports(&v);

    if (g_nrecs == 0)
        printf("  no imports\n");

    /* exe directory for native-DLL search. */
    char exedir[1100] = ".";
    {
        size_t dl;
        const char *base = wn_path_basename(path, &dl);
        if (base && dl > 0 && dl < sizeof exedir) {
            memcpy(exedir, path, dl);
            exedir[dl] = '\0';
        }
    }

    for (size_t i = 0; i < g_nrecs; i++)
        classify_rec(&g_recs[i], exedir);

    /* Group by DLL in first-appearance order. */
    int rc = 0;
    unsigned total = 0, c_ok = 0, c_stub = 0, c_native = 0, c_nmiss = 0,
             c_missdll = 0, c_bad = 0;
    for (size_t i = 0; i < g_nrecs; i++) {
        if (g_recs[i].grouped)
            continue;
        const char *dll = g_recs[i].dll;
        const wn_builtin_dll *b = find_builtin(dll);
        char native_path[1400];
        int has_native = 0;
        if (!b)
            has_native = find_dll_file(dll, exedir, native_path, sizeof native_path);

        unsigned nrec = 0, nok = 0, nstub = 0, nnat = 0, nnmiss = 0, nbad = 0;
        for (size_t j = i; j < g_nrecs; j++) {
            if (g_recs[j].grouped || !wn_strcaseeq(g_recs[j].dll, dll))
                continue;
            imp_rec *r = &g_recs[j];
            r->grouped = 1;
            nrec++;
            total++;
            switch (r->st) {
            case ST_OK:          nok++; c_ok++; break;
            case ST_STUB:        nstub++; c_stub++; break;
            case ST_NATIVE:      nnat++; c_native++; break;
            case ST_NATIVE_MISS: nnmiss++; c_nmiss++; break;
            case ST_MISS_DLL:    break;   /* counted per DLL below */
            default:             nbad++; c_bad++; break;
            }
        }

        const char *src = b ? "builtin" : has_native ? "native file" : "MISSING DLL";
        (void)src;
        if (b) {
            printf("  %-32s builtin    %3u fns: %u ok, %u stub\n",
                   dll, nrec, nok, nstub + nbad);
        } else if (has_native) {
            printf("  %-32s native     %3u fns: %u ok, %u absent (%s)\n",
                   dll, nrec, nnat, nnmiss + nstub + nbad, native_path);
        } else {
            printf("  %-32s MISSING DLL  (%u fns; load will fail)\n",
                   dll, nrec);
            c_missdll++;
            rc = 1;
        }

        int show = verbose ? 1 : 0;
        if (!b && !has_native)
            show = 1;   /* always show what a missing DLL wants */
        for (size_t j = i; j < g_nrecs; j++) {
            const imp_rec *r = &g_recs[j];
            if (!wn_strcaseeq(r->dll, dll))
                continue;
            if (!show && r->st != ST_STUB && r->st != ST_NATIVE_MISS &&
                r->st != ST_BAD)
                continue;
            char sym[224];
            if (r->by_ordinal)
                snprintf(sym, sizeof sym, "#%u", r->ordinal);
            else
                snprintf(sym, sizeof sym, "%s", r->sym);
            printf("      [%-11s] %-60s %s\n", st_name(r->st), sym,
                   r->delay ? "(delay-load)" : "");
        }
    }

    if (c_bad)
        rc = 1;
    if (!v.is64)
        rc = 1;
    printf("\nsummary: %u imports: %u ok, %u stubbed, %u native, "
           "%u native-missing, %u bad; %u DLLs missing\n",
           total, c_ok, c_stub, c_native, c_nmiss, c_bad, c_missdll);
    if (!v.is64)
        printf("32-bit image: runtime support not implemented yet "
               "(WoW64-style PE32 loading is a major TODO).\n");

    free(buf);
    free(g_recs);
    return rc;
}
