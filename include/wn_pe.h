/* wn_pe.h — PE32/PE32+ file format definitions and the in-memory loader.
 *
 * Structs are layout-exact for the on-disk format (naturally packed; all
 * fields are explicit-width integers, no padding surprises).
 */
#ifndef WN_PE_H
#define WN_PE_H

#include <stdint.h>
#include <stddef.h>

/* --- DOS header --------------------------------------------------------- */
#define WN_IMAGE_DOS_SIGNATURE 0x5A4D /* "MZ" */

typedef struct {
    uint16_t e_magic, e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc,
             e_maxalloc, e_ss, e_sp, e_csum, e_ip, e_cs, e_lfarlc, e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid, e_oeminfo;
    uint16_t e_res2[10];
    int32_t  e_lfanew;
} wn_image_dos_header; /* 64 bytes */

/* --- NT headers --------------------------------------------------------- */
#define WN_IMAGE_NT_SIGNATURE   0x00004550 /* "PE\0\0" */
#define WN_IMAGE_FILE_MACHINE_I386   0x014c
#define WN_IMAGE_FILE_MACHINE_AMD64  0x8664

typedef struct {
    uint16_t machine;
    uint16_t number_of_sections;
    uint32_t time_date_stamp;
    uint32_t pointer_to_symbol_table;
    uint32_t number_of_symbols;
    uint16_t size_of_optional_header;
    uint16_t characteristics;
} wn_image_file_header; /* 20 bytes */
_Static_assert(sizeof(wn_image_file_header) == 20, "file header ABI");

#define WN_IMAGE_FILE_DLL 0x2000
#define WN_IMAGE_FILE_EXECUTABLE_IMAGE 0x0002

#define WN_IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10b
#define WN_IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20b

/* Data directory indices. */
#define WN_IMAGE_DIR_EXPORT    0
#define WN_IMAGE_DIR_IMPORT    1
#define WN_IMAGE_DIR_RESOURCE  2
#define WN_IMAGE_DIR_EXCEPTION 3
#define WN_IMAGE_DIR_SECURITY  4
#define WN_IMAGE_DIR_BASERELOC 5
#define WN_IMAGE_DIR_DEBUG     6
#define WN_IMAGE_DIR_TLS       9
#define WN_IMAGE_DIR_LOAD_CONFIG 10
#define WN_IMAGE_DIR_IAT       12
#define WN_IMAGE_DIR_DELAY_IMPORT 13
#define WN_IMAGE_NUM_DIRS 16

typedef struct {
    uint32_t virtual_address;
    uint32_t size;
} wn_image_data_directory;

/* PE32+ optional header (x64). */
typedef struct {
    uint16_t magic;
    uint8_t  major_linker_version, minor_linker_version;
    uint32_t size_of_code;
    uint32_t size_of_initialized_data;
    uint32_t size_of_uninitialized_data;
    uint32_t address_of_entry_point;
    uint32_t base_of_code;
    uint64_t image_base;
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint16_t major_os_version, minor_os_version;
    uint16_t major_image_version, minor_image_version;
    uint16_t major_subsystem_version, minor_subsystem_version;
    uint32_t win32_version_value;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint32_t check_sum;
    uint16_t subsystem;
    uint16_t dll_characteristics;
    uint64_t size_of_stack_reserve;
    uint64_t size_of_stack_commit;
    uint64_t size_of_heap_reserve;
    uint64_t size_of_heap_commit;
    uint32_t loader_flags;
    uint32_t number_of_rva_and_sizes;
    wn_image_data_directory dirs[WN_IMAGE_NUM_DIRS];
} wn_image_optional_header64; /* 240 bytes */

/* PE32 optional header (x86) — used for validation later (32-bit support). */
typedef struct {
    uint16_t magic;
    uint8_t  major_linker_version, minor_linker_version;
    uint32_t size_of_code;
    uint32_t size_of_initialized_data;
    uint32_t size_of_uninitialized_data;
    uint32_t address_of_entry_point;
    uint32_t base_of_code;
    uint32_t base_of_data;
    uint32_t image_base;
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint16_t major_os_version, minor_os_version;
    uint16_t major_image_version, minor_image_version;
    uint16_t major_subsystem_version, minor_subsystem_version;
    uint32_t win32_version_value;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint32_t check_sum;
    uint16_t subsystem;
    uint16_t dll_characteristics;
    uint32_t size_of_stack_reserve;
    uint32_t size_of_stack_commit;
    uint32_t size_of_heap_reserve;
    uint32_t size_of_heap_commit;
    uint32_t loader_flags;
    uint32_t number_of_rva_and_sizes;
    wn_image_data_directory dirs[WN_IMAGE_NUM_DIRS];
} wn_image_optional_header32;

typedef struct {
    uint16_t signature; /* PE\0\0 */
    wn_image_file_header file;
    wn_image_optional_header64 opt64;
} wn_image_nt_headers64;

/* --- Sections ------------------------------------------------------------ */
#define WN_IMAGE_SCN_MEM_EXECUTE    0x20000000
#define WN_IMAGE_SCN_MEM_READ       0x40000000
#define WN_IMAGE_SCN_MEM_WRITE      0x80000000
#define WN_IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080
#define WN_IMAGE_SCN_MEM_DISCARDABLE 0x02000000

typedef struct {
    char     name[8];
    uint32_t virtual_size;
    uint32_t virtual_address;
    uint32_t size_of_raw_data;
    uint32_t pointer_to_raw_data;
    uint32_t pointer_to_relocations;
    uint32_t pointer_to_linenumbers;
    uint16_t number_of_relocations;
    uint16_t number_of_linenumbers;
    uint32_t characteristics;
} wn_image_section_header; /* 40 bytes */

/* --- Imports -------------------------------------------------------------- */
typedef struct {
    uint32_t original_first_thunk;
    uint32_t time_date_stamp;
    uint32_t forwarder_chain;
    uint32_t name;
    uint32_t first_thunk;
} wn_image_import_descriptor;

#define WN_IMAGE_ORDINAL_FLAG64 0x8000000000000000ULL
#define WN_IMAGE_ORDINAL_FLAG32 0x80000000u

typedef struct {
    uint16_t hint;
    char     name[1];
} wn_image_import_by_name;

/* --- Delay imports --------------------------------------------------------- */
typedef struct {
    uint32_t gr_attrs;
    uint32_t sz_name;
    uint32_t phmod;
    uint32_t p_iat;
    uint32_t p_int;
    uint32_t p_bound_iat;
    uint32_t p_unload_iat;
    uint32_t dw_time_stamp;
} wn_image_delayload_descriptor;

/* --- Exports ---------------------------------------------------------------- */
typedef struct {
    uint32_t characteristics;
    uint32_t time_date_stamp;
    uint16_t major_version, minor_version;
    uint32_t name;
    uint32_t ordinal_base;
    uint32_t number_of_functions;
    uint32_t number_of_names;
    uint32_t address_of_functions;
    uint32_t address_of_names;
    uint32_t address_of_name_ordinals;
} wn_image_export_directory;

/* --- TLS --------------------------------------------------------------------- */
typedef struct {
    uint64_t start_address_of_raw_data;
    uint64_t end_address_of_raw_data;
    uint64_t address_of_index;
    uint64_t address_of_callbacks;
    uint32_t size_of_zero_fill;
    uint32_t characteristics;
} wn_image_tls_directory64;

/* PE32 (i386) TLS directory: 6 dwords + 2 dwords = 24 bytes. */
typedef struct {
    uint32_t start_address_of_raw_data;
    uint32_t end_address_of_raw_data;
    uint32_t address_of_index;
    uint32_t address_of_callbacks;
    uint32_t size_of_zero_fill;
    uint32_t characteristics;
} wn_image_tls_directory32;

/* --- Relocations --------------------------------------------------------------- */
#define WN_IMAGE_REL_BASED_ABSOLUTE 0
#define WN_IMAGE_REL_BASED_HIGHLOW  3
#define WN_IMAGE_REL_BASED_DIR64    10

/* --- Loader API ---------------------------------------------------------------- */

/* A loaded PE image in memory. */
typedef struct wn_pe_image {
    uint8_t *base;                  /* mapping address (guest-visible) */
    size_t   mapped_size;           /* page-rounded size mapped */
    uint64_t preferred_base;        /* ImageBase from header */
    uint16_t machine;
    int      is_64;                 /* 1 = PE32+, 0 = PE32 (i386) */
    int      is_dll;
    uint32_t entry_rva;
    uint32_t size_of_image;
    uint32_t headers_size;          /* SizeOfHeaders (bytes copied from file) */
    uint32_t opt_off;               /* offset of optional header, cached from
                                     * the VALIDATED file header — section
                                     * copies can clobber the mapped DOS
                                     * header, so it must never be re-read */
    uint32_t stack_reserve, stack_commit;
    wn_image_section_header *sections; /* points into image headers */
    uint16_t num_sections;
    char     path[1024];            /* host path it was loaded from */
    /* File bytes are released after mapping; only the mapping remains. */
} wn_pe_image;

/* The image's data directories (works for PE32 and PE32+). */
const wn_image_data_directory *wn_pe_dirs(const wn_pe_image *img);

/* Parse+map a PE image from a file's bytes. Returns 0 on success.
 * On failure returns a Win32-ish error code and logs loudly.
 * image->sections points into the mapping itself. */
uint32_t wn_pe_map(const uint8_t *file_data, size_t file_size,
                   const char *path_for_logs, wn_pe_image *image);

/* Apply base relocations (delta = base - preferred_base). Returns 0 or
 * error; logs every rejected entry. */
uint32_t wn_pe_apply_relocations(wn_pe_image *image);

/* Apply final per-section page protections after all loader writes
 * (relocations/imports) are done. */
uint32_t wn_pe_apply_protections(wn_pe_image *image);

/* Unmap and zero the structure. */
void     wn_pe_unmap(wn_pe_image *image);

/* Rva -> mapped pointer with bounds check (NULL if outside image). */
void    *wn_pe_rva(const wn_pe_image *img, uint32_t rva, size_t min_size);

/* Resolve an export by name (case-insensitive) or ordinal.
 * Returns function/data address, or NULL if not found (logs at debug).
 * Handles forwarder strings recursively via `depth` guard. */
void    *wn_pe_resolve_export(wn_pe_image *img, const char *name,
                              uint16_t ordinal, int by_ordinal, int depth);

/* Fill the per-thread static TLS block for this image; assign its TLS index.
 * Called once per image at load. Returns 0 on success. */
uint32_t wn_pe_tls_setup(wn_pe_image *img, uint32_t *out_index);

#endif /* WN_PE_H */
