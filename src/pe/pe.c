/* wn_pe.c — PE32/PE32+ parser and image mapper.
 *
 * Hardened: every header field is validated before use; malformed images are
 * rejected with a loud log and an error code, never silently accepted.
 * Both PE32 (i386, magic 0x10b) and PE32+ (x64, magic 0x20b) are parsed;
 * is_64 selects the optional-header layout everywhere it is read.
 */
#include "wn_pe.h"
#include "wn_log.h"
#include "wn_util.h"
#include "wn_types.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

/* Page helpers. */
static size_t page_up(size_t n) { return (n + 0xFFF) & ~0xFFFULL; }
static size_t page_down(size_t n) { return n & ~0xFFFULL; }

/* Process-global static-TLS index allocator (documented global: one counter
 * per process; indices are assigned to images in load order, matching the
 * Windows loader contract for static TLS). */
static uint32_t g_tls_next_index = 1;

uint32_t wn_pe_tls_next_index(void) { return g_tls_next_index++; }

/* --- optional-header accessors (arch-agnostic) ---------------------------- */

/* Offset of the optional header inside the MAPPING (works on the mapped
 * copy too, where e_lfanew is at the same place). */
static size_t opt_off(const uint8_t *base_or_file)
{
    int32_t lfa = ((const wn_image_dos_header *)(const void *)base_or_file)
                      ->e_lfanew;
    return (size_t)lfa + 4 + sizeof(wn_image_file_header);
}

const wn_image_data_directory *wn_pe_dirs(const wn_pe_image *img)
{
    const uint8_t *p = img->base + opt_off(img->base);
    if (img->is_64)
        return ((const wn_image_optional_header64 *)(const void *)p)->dirs;
    return ((const wn_image_optional_header32 *)(const void *)p)->dirs;
}

/* --- validation + parse -------------------------------------------------- */

static uint32_t read_headers(const uint8_t *f, size_t fs, const char *path,
                             wn_pe_image *img)
{
    if (fs < sizeof(wn_image_dos_header)) {
        wn_log(WN_LOG_ERR, "pe: '%s': file too small for DOS header (%zu)", path, fs);
        return WN_ERR_BAD_FORMAT;
    }
    const wn_image_dos_header *dos = (const void *)f;
    if (dos->e_magic != WN_IMAGE_DOS_SIGNATURE) {
        wn_log(WN_LOG_ERR, "pe: '%s': bad MZ signature 0x%04x", path, dos->e_magic);
        return WN_ERR_BAD_FORMAT;
    }
    if (dos->e_lfanew < 0 || (size_t)dos->e_lfanew + 4 + sizeof(wn_image_file_header) > fs) {
        wn_log(WN_LOG_ERR, "pe: '%s': e_lfanew %d out of range", path, dos->e_lfanew);
        return WN_ERR_BAD_FORMAT;
    }
    const uint8_t *p = f + dos->e_lfanew;
    uint32_t sig;
    memcpy(&sig, p, 4);
    if (sig != WN_IMAGE_NT_SIGNATURE) {
        wn_log(WN_LOG_ERR, "pe: '%s': bad PE signature 0x%08x", path, sig);
        return WN_ERR_BAD_FORMAT;
    }
    const wn_image_file_header *fh = (const void *)(p + 4);
    int is_64;
    if (fh->machine == WN_IMAGE_FILE_MACHINE_AMD64)
        is_64 = 1;
    else if (fh->machine == WN_IMAGE_FILE_MACHINE_I386)
        is_64 = 0;
    else {
        wn_log(WN_LOG_ERR, "pe: '%s': unknown machine 0x%04x", path, fh->machine);
        return WN_ERR_BAD_FORMAT;
    }
    if (fh->number_of_sections == 0 || fh->number_of_sections > 96) {
        wn_log(WN_LOG_ERR, "pe: '%s': implausible section count %u", path,
               fh->number_of_sections);
        return WN_ERR_BAD_FORMAT;
    }
    size_t need = (size_t)dos->e_lfanew + 4 + sizeof(wn_image_file_header)
                + fh->size_of_optional_header;
    size_t oh_min = is_64 ? sizeof(wn_image_optional_header64)
                          : sizeof(wn_image_optional_header32);
    if (fh->size_of_optional_header < oh_min || need > fs) {
        wn_log(WN_LOG_ERR, "pe: '%s': optional header truncated (size %u)",
               path, fh->size_of_optional_header);
        return WN_ERR_BAD_FORMAT;
    }
    const uint8_t *ohp = p + 4 + sizeof(wn_image_file_header);
    uint16_t magic;
    memcpy(&magic, ohp, 2);
    if (is_64 && magic != WN_IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        wn_log(WN_LOG_ERR, "pe: '%s': optional header magic 0x%04x (need PE32+ 0x20b)",
               path, magic);
        return WN_ERR_BAD_FORMAT;
    }
    if (!is_64 && magic != WN_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        wn_log(WN_LOG_ERR, "pe: '%s': optional header magic 0x%04x (need PE32 0x10b)",
               path, magic);
        return WN_ERR_BAD_FORMAT;
    }
    /* Common fields at identical offsets in both layouts (up to
     * SizeOfHeaders): read via the 64 struct for 64, the 32 struct for 32. */
    uint32_t size_of_image, size_of_headers, section_alignment, file_alignment;
    uint32_t entry_rva;
    uint64_t preferred_base;
    uint32_t stack_reserve, stack_commit;
    if (is_64) {
        const wn_image_optional_header64 *oh = (const void *)ohp;
        size_of_image = oh->size_of_image;
        size_of_headers = oh->size_of_headers;
        section_alignment = oh->section_alignment;
        file_alignment = oh->file_alignment;
        entry_rva = oh->address_of_entry_point;
        preferred_base = oh->image_base;
        stack_reserve = (uint32_t)(oh->size_of_stack_reserve);
        stack_commit = (uint32_t)(oh->size_of_stack_commit);
    } else {
        const wn_image_optional_header32 *oh = (const void *)ohp;
        size_of_image = oh->size_of_image;
        size_of_headers = oh->size_of_headers;
        section_alignment = oh->section_alignment;
        file_alignment = oh->file_alignment;
        entry_rva = oh->address_of_entry_point;
        preferred_base = oh->image_base;
        stack_reserve = oh->size_of_stack_reserve;
        stack_commit = oh->size_of_stack_commit;
    }
    if (size_of_image == 0 || size_of_image > 0x40000000u) {
        wn_log(WN_LOG_ERR, "pe: '%s': implausible SizeOfImage 0x%x", path,
               size_of_image);
        return WN_ERR_BAD_FORMAT;
    }
    if (section_alignment == 0 || file_alignment == 0 ||
        section_alignment < file_alignment) {
        wn_log(WN_LOG_ERR, "pe: '%s': bad alignments (sec 0x%x file 0x%x)", path,
               section_alignment, file_alignment);
        return WN_ERR_BAD_FORMAT;
    }
    if (size_of_headers > size_of_image) {
        wn_log(WN_LOG_ERR, "pe: '%s': SizeOfHeaders 0x%x > SizeOfImage 0x%x",
               path, size_of_headers, size_of_image);
        return WN_ERR_BAD_FORMAT;
    }

    img->machine = fh->machine;
    img->is_64 = is_64;
    img->is_dll = (fh->characteristics & WN_IMAGE_FILE_DLL) != 0;
    img->entry_rva = entry_rva;
    img->preferred_base = preferred_base;
    img->size_of_image = size_of_image;
    img->headers_size = size_of_headers;
    img->stack_reserve = stack_reserve ? stack_reserve : 0x100000;
    img->stack_commit = stack_commit;
    img->num_sections = fh->number_of_sections;
    return 0;
}

/* --- mapping ------------------------------------------------------------- */

uint32_t wn_pe_map(const uint8_t *f, size_t fs, const char *path,
                   wn_pe_image *img)
{
    memset(img, 0, sizeof *img);
    uint32_t rc = read_headers(f, fs, path, img);
    if (rc)
        return rc;

    size_t o_off = opt_off(f);
    const wn_image_section_header *secs =
        (const void *)((const uint8_t *)f + o_off +
                       (img->is_64 ? sizeof(wn_image_optional_header64)
                                   : sizeof(wn_image_optional_header32)));
    uint32_t hdr_copy_len = img->headers_size;

    /* Validate every section before touching memory. */
    for (uint16_t i = 0; i < img->num_sections; i++) {
        const wn_image_section_header *s = &secs[i];
        uint64_t vs = s->virtual_size ? s->virtual_size : s->size_of_raw_data;
        if (s->virtual_address > img->size_of_image ||
            vs > img->size_of_image ||
            (uint64_t)s->virtual_address + vs > img->size_of_image) {
            wn_log(WN_LOG_ERR, "pe: '%s': section %u '%.8s' VA 0x%x VS 0x%x outside image",
                   path, i, s->name, s->virtual_address, s->virtual_size);
            return WN_ERR_BAD_FORMAT;
        }
        if (s->size_of_raw_data > 0 &&
            ((uint64_t)s->pointer_to_raw_data + s->size_of_raw_data > fs)) {
            wn_log(WN_LOG_ERR, "pe: '%s': section %u raw range 0x%x+0x%x beyond file",
                   path, i, s->pointer_to_raw_data, s->size_of_raw_data);
            return WN_ERR_BAD_FORMAT;
        }
    }

    size_t map_size = page_up(img->size_of_image);
    uint8_t *base = mmap(NULL, map_size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (base == MAP_FAILED) {
        wn_log(WN_LOG_ERR, "pe: '%s': mmap of %zu bytes failed", path, map_size);
        return WN_ERR_NOT_ENOUGH_MEMORY;
    }

    img->base = base;
    img->mapped_size = map_size;
    if (path)
        snprintf(img->path, sizeof img->path, "%s", path);

    /* Headers. */
    size_t hdr_copy = hdr_copy_len < fs ? hdr_copy_len : fs;
    memcpy(base, f, hdr_copy);

    /* Sections (anon mapping is zero-filled; copy raw data on top). */
    for (uint16_t i = 0; i < img->num_sections; i++) {
        const wn_image_section_header *s = &secs[i];
        uint32_t vs = s->virtual_size ? s->virtual_size : s->size_of_raw_data;
        if (s->size_of_raw_data == 0 || s->pointer_to_raw_data == 0)
            continue; /* BSS */
        size_t copy = s->size_of_raw_data < vs ? s->size_of_raw_data : vs;
        memcpy(base + s->virtual_address, f + s->pointer_to_raw_data, copy);
        if (s->size_of_raw_data > vs)
            wn_log(WN_LOG_DEBUG, "pe: '%s': section '%.8s' raw 0x%x > vsize 0x%x "
                   "(truncated copy, Windows-like)", path, s->name,
                   s->size_of_raw_data, vs);
    }

    /* Section table lives in the mapped headers now. */
    img->sections = (void *)(base + o_off +
                             (img->is_64 ? sizeof(wn_image_optional_header64)
                                         : sizeof(wn_image_optional_header32)));
    return 0;
}

void *wn_pe_rva(const wn_pe_image *img, uint32_t rva, size_t min_size)
{
    if (rva >= img->size_of_image)
        return NULL;
    if (min_size && (uint64_t)rva + min_size > img->size_of_image)
        return NULL;
    return img->base + rva;
}

/* --- relocations ---------------------------------------------------------- */

uint32_t wn_pe_apply_relocations(wn_pe_image *img)
{
    const wn_image_data_directory *dirs = wn_pe_dirs(img);
    const wn_image_data_directory *dir = &dirs[WN_IMAGE_DIR_BASERELOC];
    int64_t delta = (int64_t)((uint64_t)(uintptr_t)img->base - img->preferred_base);
    if (delta == 0) {
        wn_log(WN_LOG_DEBUG, "pe: image mapped at preferred base; relocs skipped");
        return 0;
    }
    if (dir->virtual_address == 0 || dir->size == 0) {
        wn_log(WN_LOG_ERR, "pe: '%s': needs relocation (delta 0x%llx) but has no "
               ".reloc directory", img->path, (long long)delta);
        return WN_ERR_BAD_FORMAT;
    }
    uint8_t *p = wn_pe_rva(img, dir->virtual_address, dir->size);
    if (!p) {
        wn_log(WN_LOG_ERR, "pe: reloc directory out of bounds");
        return WN_ERR_BAD_FORMAT;
    }
    uint8_t *end = p + dir->size;
    while (p + 8 <= end) {
        uint32_t page_rva, block_size;
        memcpy(&page_rva, p, 4);
        memcpy(&block_size, p + 4, 4);
        if (block_size < 8 || p + block_size > end) {
            wn_log(WN_LOG_ERR, "pe: malformed reloc block (size %u)", block_size);
            return WN_ERR_BAD_FORMAT;
        }
        for (uint32_t off = 8; off + 2 <= block_size; off += 2) {
            uint16_t e;
            memcpy(&e, p + off, 2);
            uint32_t type = e >> 12, offs = e & 0xFFF;
            if (type == WN_IMAGE_REL_BASED_ABSOLUTE)
                continue;
            uint64_t spot = (uint64_t)page_rva + offs;
            if (spot + 8 > img->size_of_image) {
                wn_log(WN_LOG_ERR, "pe: reloc entry target 0x%llx outside image",
                       (unsigned long long)spot);
                return WN_ERR_BAD_FORMAT;
            }
            if (type == WN_IMAGE_REL_BASED_DIR64 && img->is_64) {
                uint64_t val;
                memcpy(&val, img->base + spot, 8);
                val += delta;
                memcpy(img->base + spot, &val, 8);
            } else if (type == WN_IMAGE_REL_BASED_HIGHLOW) {
                uint32_t val;
                memcpy(&val, img->base + spot, 4);
                val += (uint32_t)delta;
                memcpy(img->base + spot, &val, 4);
            } else {
                wn_log(WN_LOG_WARN, "pe: reloc type %u unsupported (entry skipped)",
                       type);
            }
        }
        p += block_size;
    }
    return 0;
}

/* --- final protections ----------------------------------------------------- */

uint32_t wn_pe_apply_protections(wn_pe_image *img)
{
    /* Per-page OR of section permissions, then mprotect runs. */
    size_t npages = img->mapped_size >> 12;
    uint8_t *perm = wn_xcalloc(npages, 1); /* bits: 1=R 2=W 4=X */
    for (uint16_t i = 0; i < img->num_sections; i++) {
        const wn_image_section_header *s = &img->sections[i];
        uint32_t vs = s->virtual_size ? s->virtual_size : s->size_of_raw_data;
        if (vs == 0)
            continue;
        size_t start = page_down(s->virtual_address) >> 12;
        size_t end = page_up((size_t)s->virtual_address + vs) >> 12;
        if (end > npages)
            end = npages;
        uint8_t m = 0;
        if (s->characteristics & WN_IMAGE_SCN_MEM_READ)    m |= 1;
        if (s->characteristics & WN_IMAGE_SCN_MEM_WRITE)   m |= 2;
        if (s->characteristics & WN_IMAGE_SCN_MEM_EXECUTE) m |= 4;
        if (m == 0)
            m = 1; /* sections with no access flags default readable */
        for (size_t pg = start; pg < end; pg++)
            perm[pg] |= m;
    }
    int rc = 0;
    for (size_t pg = 0; pg < npages; ) {
        if (perm[pg] == 0) { pg++; continue; }
        size_t run = pg;
        while (run < npages && perm[run] == perm[pg])
            run++;
        int prot = 0;
        if (perm[pg] & 1) prot |= PROT_READ;
        if (perm[pg] & 2) prot |= PROT_WRITE;
        if (perm[pg] & 4) prot |= PROT_EXEC;
        if (mprotect(img->base + (pg << 12), (run - pg) << 12, prot) != 0) {
            wn_log(WN_LOG_ERR, "pe: mprotect failed at page %zu", pg);
            rc = WN_ERR_ACCESS_DENIED;
            break;
        }
        pg = run;
    }
    free(perm);
    return rc;
}

void wn_pe_unmap(wn_pe_image *img)
{
    if (img->base)
        munmap(img->base, img->mapped_size);
    memset(img, 0, sizeof *img);
}

/* --- exports ---------------------------------------------------------------- */

void *wn_pe_resolve_export(wn_pe_image *img, const char *name,
                           uint16_t ordinal, int by_ordinal, int depth)
{
    if (depth > 8) {
        wn_log(WN_LOG_ERR, "pe: export forwarder chain too deep");
        return NULL;
    }
    const wn_image_data_directory *dirs = wn_pe_dirs(img);
    const wn_image_data_directory *dir = &dirs[WN_IMAGE_DIR_EXPORT];
    if (dir->virtual_address == 0)
        return NULL;
    wn_image_export_directory *exp = wn_pe_rva(img, dir->virtual_address, sizeof *exp);
    if (!exp)
        return NULL;

    uint32_t target_rva = 0;
    if (by_ordinal) {
        if (ordinal < exp->ordinal_base ||
            (uint32_t)(ordinal - exp->ordinal_base) >= exp->number_of_functions)
            return NULL;
        uint32_t *funcs = wn_pe_rva(img, exp->address_of_functions, 4 * exp->number_of_functions);
        if (!funcs)
            return NULL;
        target_rva = funcs[ordinal - exp->ordinal_base];
    } else {
        uint32_t *names = wn_pe_rva(img, exp->address_of_names, 4 * exp->number_of_names);
        uint16_t *ords = wn_pe_rva(img, exp->address_of_name_ordinals, 2 * exp->number_of_names);
        uint32_t *funcs = wn_pe_rva(img, exp->address_of_functions, 4 * exp->number_of_functions);
        if (!names || !ords || !funcs)
            return NULL;
        for (uint32_t i = 0; i < exp->number_of_names; i++) {
            const char *en = wn_pe_rva(img, names[i], 2);
            if (!en)
                continue;
            if (wn_strcaseeq(en, name)) {
                target_rva = funcs[ords[i]];
                break;
            }
        }
        if (target_rva == 0)
            return NULL;
    }
    if (target_rva == 0)
        return NULL;

    /* Forwarder? (RVA falls inside the export directory itself.) */
    if (target_rva >= dir->virtual_address &&
        target_rva < dir->virtual_address + dir->size) {
        const char *fwd = wn_pe_rva(img, target_rva, 4);
        if (!fwd)
            return NULL;
        char dll[64], func[128];
        const char *dot = strchr(fwd, '.');
        if (!dot)
            return NULL;
        size_t dl = (size_t)(dot - fwd);
        if (dl >= sizeof dll)
            return NULL;
        memcpy(dll, fwd, dl);
        dll[dl] = '\0';
        snprintf(func, sizeof func, "%s", dot + 1);
        wn_log(WN_LOG_DEBUG, "pe: forwarder %s -> %s!%s (needs loaded module)", fwd, dll, func);
        return NULL; /* resolved by the module layer, not here */
    }
    return wn_pe_rva(img, target_rva, 1);
}

/* --- TLS --------------------------------------------------------------------- */

/* Normalize a VA stored in the image: if it points at the preferred base,
 * translate it to the actual mapping (protects images without relocs). */
static uint64_t norm_va(const wn_pe_image *img, uint64_t va)
{
    if (va >= img->preferred_base &&
        va < img->preferred_base + img->size_of_image)
        return (uint64_t)(uintptr_t)img->base + (va - img->preferred_base);
    return va;
}

uint32_t wn_pe_tls_setup(wn_pe_image *img, uint32_t *out_index)
{
    *out_index = 0;
    const wn_image_data_directory *dirs = wn_pe_dirs(img);
    const wn_image_data_directory *dir = &dirs[WN_IMAGE_DIR_TLS];
    if (dir->virtual_address == 0)
        return 0;
    uint64_t index_va = 0, callbacks_va = 0;
    if (img->is_64) {
        if (dir->size < sizeof(wn_image_tls_directory64))
            return 0;
        const wn_image_tls_directory64 *tls =
            wn_pe_rva(img, dir->virtual_address, sizeof *tls);
        if (!tls)
            return WN_ERR_BAD_FORMAT;
        if (tls->address_of_index == 0)
            return 0;
        index_va = norm_va(img, tls->address_of_index);
        callbacks_va = norm_va(img, tls->address_of_callbacks);
    } else {
        if (dir->size < sizeof(wn_image_tls_directory32))
            return 0;
        const wn_image_tls_directory32 *tls =
            wn_pe_rva(img, dir->virtual_address, sizeof *tls);
        if (!tls)
            return WN_ERR_BAD_FORMAT;
        if (tls->address_of_index == 0)
            return 0;
        index_va = norm_va(img, tls->address_of_index);
        callbacks_va = norm_va(img, tls->address_of_callbacks);
    }

    uint32_t index = wn_pe_tls_next_index();
    uint32_t *slot = (uint32_t *)(uintptr_t)index_va;
    *slot = index;
    *out_index = index;
    wn_log(WN_LOG_DEBUG, "pe: '%s' static TLS index %u (callbacks at 0x%llx)",
           img->path, index, (unsigned long long)callbacks_va);
    return 0;
}

