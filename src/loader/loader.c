/* loader.c — module registry + import resolution + the process startup
 * orchestration (exe load, TLS, entry, LDR lists).
 */
#include "wn_module.h"
#include "wn_dll.h"
#include "wn_process.h"
#include "wn_path.h"
#include "wn_files.h"
#include "wn_stub.h"
#include "wn_log.h"
#include "wn_util.h"
#include "wn_registry.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Documented global: module list. */
static wn_module *g_modules;

wn_module *wn_module_list_head(void) { return g_modules; }

/* --- builtin image synthesis --------------------------------------------- */

/* Builtins get a minimal fake PE image so DllBase walks (RtlImageNtHeader)
 * do not explode. MZ + PE\0\0 + file header + PE32+ optional header. */
static uint8_t *builtin_image(void)
{
    uint8_t *b = wn_xcalloc(1, 0x1000);
    wn_image_dos_header *dos = (void *)b;
    dos->e_magic = 0x5A4D;
    dos->e_lfanew = 0x40;
    uint32_t *sig = (void *)(b + 0x40);
    *sig = 0x00004550;
    wn_image_file_header *fh = (void *)(b + 0x44);
    fh->machine = 0x8664;
    fh->size_of_optional_header = sizeof(wn_image_optional_header64);
    wn_image_optional_header64 *oh =
        (void *)(b + 0x44 + sizeof(wn_image_file_header));
    oh->magic = 0x20B;
    oh->image_base = 0x10000000;
    oh->size_of_image = 0x1000;
    return b;
}

/* --- module list ops -------------------------------------------------------- */

static wn_module *module_register(wn_module_kind kind, const char *name,
                                  const char *path)
{
    wn_module *m = wn_xcalloc(1, sizeof *m);
    m->kind = kind;
    wn_strlower(m->name, sizeof m->name, name);
    if (path)
        snprintf(m->path, sizeof m->path, "%s", path);
    m->refcount = 1;
    m->next = g_modules;
    g_modules = m;
    return m;
}

void wn_module_init(void)
{
    for (const wn_builtin_dll *b = wn_builtin_table; b->name; b++)
        wn_log(WN_LOG_DEBUG, "builtin: %s (%d exports)", b->name, 0);
}

wn_module *wn_module_find(const char *name)
{
    const char *norm = wn_dll_normalize_name(name);
    char low[64];
    wn_strlower(low, sizeof low, norm);
    for (wn_module *m = g_modules; m; m = m->next)
        if (!strcmp(m->name, low))
            return m;
    return NULL;
}

/* --- file loading ------------------------------------------------------------ */

static uint8_t *read_file(const char *path, size_t *out_size)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return NULL;
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < 0) {
        close(fd);
        return NULL;
    }
    size_t n = (size_t)st.st_size;
    uint8_t *buf = wn_xmalloc(n ? n : 1);
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, buf + got, n - got);
        if (r <= 0)
            break;
        got += (size_t)r;
    }
    close(fd);
    if (got != n) {
        free(buf);
        return NULL;
    }
    *out_size = n;
    return buf;
}

/* --- import resolution --------------------------------------------------------- */

/* Resolve all imports of a mapped image. Returns 0 or error. */
static uint32_t resolve_imports(wn_module *m)
{
    if (m->kind != WN_MOD_PE)
        return 0;
    wn_pe_image *img = &m->pe;
    const wn_image_dos_header *dos = (const void *)img->base;
    const wn_image_optional_header64 *oh =
        (const void *)(img->base + dos->e_lfanew + 4 + sizeof(wn_image_file_header));

    const wn_image_data_directory *dir = &oh->dirs[WN_IMAGE_DIR_IMPORT];
    if (dir->virtual_address == 0 || dir->size == 0)
        goto delay;

    wn_image_import_descriptor *desc = wn_pe_rva(img, dir->virtual_address,
                                                 sizeof *desc);
    if (!desc) {
        wn_log(WN_LOG_ERR, "loader: import dir out of bounds in '%s'", m->path);
        return WN_ERR_BAD_FORMAT;
    }
    for (; desc->name; desc++) {
        const char *dll_name = wn_pe_rva(img, desc->name, 2);
        if (!dll_name) {
            wn_log(WN_LOG_ERR, "loader: bad import name RVA in '%s'", m->path);
            return WN_ERR_BAD_FORMAT;
        }
        wn_module *dep = wn_module_load_dll(dll_name, NULL);
        if (!dep) {
            wn_log(WN_LOG_ERR, "loader: '%s' imports missing DLL '%s'",
                   m->path, dll_name);
            return WN_ERR_FILE_NOT_FOUND;
        }
        uint64_t *read_thunks = (uint64_t *)wn_pe_rva(img,
            desc->original_first_thunk ? desc->original_first_thunk
                                       : desc->first_thunk, 8);
        uint64_t *write_thunks = (uint64_t *)wn_pe_rva(img, desc->first_thunk, 8);
        if (!write_thunks) {
            wn_log(WN_LOG_ERR, "loader: bad thunk RVA in '%s'", m->path);
            return WN_ERR_BAD_FORMAT;
        }
        for (uint32_t i = 0; read_thunks && write_thunks[i]; i++) {
            uint64_t t = read_thunks[i];
            void *fn;
            if (t & WN_IMAGE_ORDINAL_FLAG64) {
                fn = wn_module_get_proc_ordinal(dep, (uint32_t)(t & 0xFFFF));
            } else {
                wn_image_import_by_name *ibn =
                    wn_pe_rva(img, (uint32_t)t, sizeof *ibn);
                if (!ibn) {
                    wn_log(WN_LOG_ERR, "loader: bad import-by-name RVA");
                    return WN_ERR_BAD_FORMAT;
                }
                fn = wn_module_get_proc(dep, ibn->name, 0, 0);
                if (!fn)
                    fn = wn_stub_for(dep->name, ibn->name);
            }
            write_thunks[i] = (uint64_t)(uintptr_t)fn;
        }
    }

delay:
    /* Delay imports: resolved eagerly (valid simplification, logged). */
    const wn_image_data_directory *dd = &oh->dirs[WN_IMAGE_DIR_DELAY_IMPORT];
    if (dd->virtual_address && dd->size) {
        wn_log(WN_LOG_DEBUG, "loader: '%s' has delay imports (resolved eagerly)",
               m->path);
        wn_image_delayload_descriptor *did =
            wn_pe_rva(img, dd->virtual_address, sizeof *did);
        for (; did && did->sz_name; did++) {
            const char *dll_name = wn_pe_rva(img, did->sz_name, 2);
            if (!dll_name)
                continue;
            wn_module *dep = wn_module_load_dll(dll_name, NULL);
            if (!dep)
                continue;
            uint32_t iat_rva = did->p_iat;
            uint64_t *thunks = (uint64_t *)wn_pe_rva(img, iat_rva, 8);
            uint32_t int_rva = did->p_int;
            uint64_t *names = (uint64_t *)wn_pe_rva(img, int_rva, 8);
            for (uint32_t i = 0; thunks && thunks[i]; i++) {
                void *fn = NULL;
                if (names && names[i] && !(names[i] & WN_IMAGE_ORDINAL_FLAG64)) {
                    wn_image_import_by_name *ibn =
                        wn_pe_rva(img, (uint32_t)names[i], sizeof *ibn);
                    if (ibn)
                        fn = wn_module_get_proc(dep, ibn->name, 0, 0);
                }
                if (!fn)
                    fn = wn_stub_for(dll_name, "delay-import");
                thunks[i] = (uint64_t)(uintptr_t)fn;
            }
        }
    }
    return 0;
}

/* --- DLL/EXE loading ------------------------------------------------------------ */

static wn_module *load_pe(const char *host_path, const char *display_name,
                          int is_exe)
{
    size_t fsz = 0;
    uint8_t *data = read_file(host_path, &fsz);
    if (!data) {
        wn_log(WN_LOG_ERR, "loader: cannot read '%s': %s", host_path,
               strerror(errno));
        wn_last_error_set(WN_ERR_FILE_NOT_FOUND);
        return NULL;
    }
    wn_module *m = module_register(WN_MOD_PE, display_name, host_path);
    uint32_t rc = wn_pe_map(data, fsz, host_path, &m->pe);
    free(data);
    if (rc) {
        wn_last_error_set(rc);
        goto fail;
    }
    m->base = m->pe.base;
    m->size = m->pe.mapped_size;
    m->loading = 1;

    rc = wn_pe_apply_relocations(&m->pe);
    if (rc)
        goto fail;

    rc = resolve_imports(m);
    if (rc)
        goto fail;

    if (!is_exe) {
        rc = wn_pe_tls_setup(&m->pe, &m->tls_index);
        if (rc)
            goto fail;
        if (m->tls_index)
            wn_tls_register_module(m);
    }

    rc = wn_pe_apply_protections(&m->pe);
    if (rc)
        goto fail;

    m->loading = 0;

    if (!is_exe && m->pe.entry_rva) {
        typedef WN_API uint32_t (*dllmain_fn)(uint64_t, uint32_t, uint64_t);
        dllmain_fn entry = (dllmain_fn)(void *)(m->base + m->pe.entry_rva);
        wn_log(WN_LOG_DEBUG, "loader: DllMain('%s', PROCESS_ATTACH)", m->name);
        uint32_t r = entry((uint64_t)(uintptr_t)m->base, 1 /*DLL_PROCESS_ATTACH*/, 0);
        if (!r)
            wn_log(WN_LOG_WARN, "loader: DllMain of '%s' returned FALSE "
                   "(load continues; Windows would fail it)", m->name);
    }
    wn_log(WN_LOG_INFO, "loader: loaded %s '%s' at %p (size 0x%zx)",
           is_exe ? "exe" : "dll", display_name, m->base, m->size);
    return m;

fail:
    wn_log(WN_LOG_ERR, "loader: load of '%s' failed (err %u)", host_path, rc);
    wn_pe_unmap(&m->pe);
    /* unlink from list */
    for (wn_module **pp = &g_modules; *pp; pp = &(*pp)->next) {
        if (*pp == m) {
            *pp = m->next;
            break;
        }
    }
    free(m);
    return NULL;
}

wn_module *wn_module_load_exe(const char *host_path)
{
    size_t dl;
    const char *base = wn_path_basename(host_path, &dl);
    wn_module *m = load_pe(host_path, base, 1);
    if (!m)
        return NULL;
    uint32_t rc2 = wn_pe_tls_setup(&m->pe, &m->tls_index);
    if (rc2)
        return NULL;
    if (m->tls_index)
        wn_tls_register_module(m);
    /* Protections were applied inside load_pe; the TLS index slot lives in
     * .data which stays writable. */
    return m;
}

/* DLL search: builtin registry first, then filesystem. */
wn_module *wn_module_load_dll(const char *name, const char *dir)
{
    const char *norm = wn_dll_normalize_name(name);

    wn_module *found = wn_module_find(norm);
    if (found) {
        found->refcount++;
        if (found->loading) {
            wn_log(WN_LOG_WARN, "loader: circular import of '%s'", norm);
        }
        return found;
    }

    /* Builtin? */
    for (const wn_builtin_dll *b = wn_builtin_table; b->name; b++) {
        if (wn_strcaseeq(b->name, norm)) {
            wn_module *m = module_register(WN_MOD_BUILTIN, b->name, NULL);
            m->builtin = b;
            m->base = builtin_image();
            m->size = 0x1000;
            extern void wn_builtin_subsys_init(void);
            wn_builtin_subsys_init();
            if (b->init)
                b->init();
            wn_log(WN_LOG_DEBUG, "loader: builtin '%s' activated", m->name);
            return m;
        }
    }

    /* Filesystem search. */
    char cand[1100];
    const char *fname = strrchr(name, '\\');
    if (fname)
        name = fname + 1;
    const char *dirs[6];
    int n = 0;
    if (dir && *dir) {
        dirs[n++] = dir;
    }
    char sysdir[1100];
    snprintf(sysdir, sizeof sysdir, "%s/drive_c/windows/system32",
             g_proc.prefix);
    dirs[n++] = sysdir;
    char windir[1100];
    snprintf(windir, sizeof windir, "%s/drive_c/windows", g_proc.prefix);
    dirs[n++] = windir;
    char exedir[1100];
    if (g_proc.exe) {
        size_t dl;
        wn_path_basename(g_proc.exe->path, &dl);
        if (dl < sizeof exedir) {
            memcpy(exedir, g_proc.exe->path, dl);
            exedir[dl] = '\0';
            dirs[n++] = exedir;
        }
    }
    dirs[n++] = ".";
    /* PATH entries. */
    for (int i = 0; i < n; i++) {
        snprintf(cand, sizeof cand, "%s/%s", dirs[i], name);
        struct stat st;
        if (stat(cand, &st) == 0 && S_ISREG(st.st_mode)) {
            wn_module *m = load_pe(cand, name, 0);
            if (m)
                return m;
            return NULL;   /* load error already logged */
        }
    }
    wn_last_error_set(WN_ERR_FILE_NOT_FOUND);
    wn_log(WN_LOG_ERR, "loader: DLL '%s' not found (searched builtin, app "
           "dir, system32, windows, cwd)", name);
    return NULL;
}

/* --- exports ------------------------------------------------------------------ */

void *wn_module_get_proc(wn_module *mod, const char *name, uint16_t ordinal,
                         int by_ordinal)
{
    (void)ordinal;
    (void)by_ordinal;   /* builtin DLLs are name-indexed (ordinals logged) */
    if (!mod || !name)
        return NULL;
    if (mod->kind == WN_MOD_BUILTIN) {
        for (const wn_export_entry *e = mod->builtin->exports; e && e->name; e++)
            if (!strcmp(e->name, name))
                return e->fn;
        wn_log(WN_LOG_TRACE, "exports: %s!%s -> MISSING (stub)", mod->name, name);
        return NULL;
    }
    void *fn = wn_pe_resolve_export(&mod->pe, name, 0, 0, 0);
    if (!fn)
        wn_log(WN_LOG_TRACE, "exports: %s!%s -> MISSING (stub)", mod->name, name);
    return fn;
}

void *wn_module_get_proc_ordinal(wn_module *mod, uint32_t ordinal)
{
    if (!mod)
        return NULL;
    if (mod->kind == WN_MOD_BUILTIN) {
        for (const wn_export_entry *e = mod->builtin->exports; e && e->name; e++)
            ;   /* builtins are name-indexed only */
        wn_log(WN_LOG_WARN, "exports: ordinal %u import from builtin '%s' "
               "(name exports only)", ordinal, mod->name);
        return NULL;
    }
    return wn_pe_resolve_export(&mod->pe, NULL, (uint16_t)ordinal, 1, 0);
}

/* --- address helpers ------------------------------------------------------------- */

wn_module *wn_module_from_addr(const void *addr, uint32_t *rva_out)
{
    uint64_t a = (uint64_t)(uintptr_t)addr;
    for (wn_module *m = g_modules; m; m = m->next) {
        if ((uint64_t)(uintptr_t)m->base <= a &&
            a < (uint64_t)(uintptr_t)m->base + m->size) {
            if (rva_out)
                *rva_out = (uint32_t)(a - (uint64_t)(uintptr_t)m->base);
            return m;
        }
    }
    return NULL;
}

const char *wn_module_describe_addr(const void *addr, char *buf, size_t cap)
{
    uint32_t rva;
    wn_module *m = wn_module_from_addr(addr, &rva);
    if (!m) {
        snprintf(buf, cap, "host:%p", addr);
        return buf;
    }
    snprintf(buf, cap, "%s+0x%x (0x%llx)", m->name, rva,
             (unsigned long long)(uintptr_t)addr);
    return buf;
}

/* --- LDR lists --------------------------------------------------------------------- */

void wn_module_build_ldr(void)
{
    /* Insert order: exe first, then everything else (ntdll convention). */
    wn_module *order[64];
    int n = 0;
    if (g_proc.exe)
        order[n++] = g_proc.exe;
    for (wn_module *m = g_modules; m && n < 64; m = m->next)
        if (m != g_proc.exe)
            order[n++] = m;

    for (int i = 0; i < n; i++) {
        wn_module *m = order[i];
        wn_ldr_entry *e = wn_xcalloc(1, sizeof *e);
        m->ldr_entry = e;
        e->dll_base = (uint64_t)(uintptr_t)m->base;
        e->entry_point = m->kind == WN_MOD_PE && m->pe.entry_rva
                       ? (uint64_t)(uintptr_t)(m->base + m->pe.entry_rva) : 0;
        e->size_of_image = (uint32_t)m->size;

        char winpath[1100];
        if (m->path[0])
            wn_path_host_to_win(m->path, winpath, sizeof winpath);
        else
            snprintf(winpath, sizeof winpath, "C:\\windows\\system32\\%s", m->name);
        uint16_t *full = wn_utf8_to_utf16(winpath, NULL);
        uint16_t *base = wn_utf8_to_utf16(m->name, NULL);
        if (full) {
            size_t l = 0;
            while (full[l]) l++;
            e->full_dll_name.length = (uint16_t)(l * 2);
            e->full_dll_name.maximum_length = (uint16_t)(l * 2 + 2);
            e->full_dll_name.buffer = full;
        }
        if (base) {
            size_t l = 0;
            while (base[l]) l++;
            e->base_dll_name.length = (uint16_t)(l * 2);
            e->base_dll_name.maximum_length = (uint16_t)(l * 2 + 2);
            e->base_dll_name.buffer = base;
        }

        /* Link into all three lists at the tail. */
        struct { uint64_t *head; size_t off; } lists[3] = {
            { g_proc.ldr->in_load_order,    offsetof(wn_ldr_entry, in_load_order) },
            { g_proc.ldr->in_memory_order,  offsetof(wn_ldr_entry, in_memory_order) },
            { g_proc.ldr->in_init_order,    offsetof(wn_ldr_entry, in_init_order) },
        };
        for (int li = 0; li < 3; li++) {
            uint64_t *head = lists[li].head;
            uint64_t *mylinks = (uint64_t *)((char *)e + lists[li].off);
            /* head's Flink = first element; walk to tail. */
            uint64_t *tail = (uint64_t *)head[1];
            if (!tail || (void *)tail == (void *)head) {
                head[0] = (uint64_t)(uintptr_t)mylinks;
                head[1] = (uint64_t)(uintptr_t)mylinks;
                mylinks[0] = (uint64_t)(uintptr_t)head;
                mylinks[1] = (uint64_t)(uintptr_t)head;
            } else {
                mylinks[0] = tail[0];
                mylinks[1] = (uint64_t)(uintptr_t)tail;
                tail[0] = (uint64_t)(uintptr_t)mylinks;
                head[1] = (uint64_t)(uintptr_t)mylinks;
            }
        }
    }
}

wn_module *wn_module_ref(wn_module *m)
{
    if (m)
        m->refcount++;
    return m;
}

void wn_module_unref(wn_module *m)
{
    if (!m)
        return;
    if (--m->refcount > 0)
        return;
    /* Deferred unload (documented): keep the mapping, raw pointers may live
     * in guest code. Windows unmaps; we log at debug. */
    wn_log(WN_LOG_DEBUG, "loader: module '%s' refcount 0 (kept mapped)", m->name);
    m->refcount = 1;
}

void wn_module_win_path(const wn_module *m, char *out, size_t cap)
{
    if (m->path[0])
        wn_path_host_to_win(m->path, out, cap);
    else
        snprintf(out, cap, "C:\\windows\\system32\\%s", m->name);
}
