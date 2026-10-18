/* wn_module.h — module registry: builtin DLLs + mapped PE images, import
 * resolution, PEB LDR lists. The rest of the code never resolves symbols any
 * other way.
 */
#ifndef WN_MODULE_H
#define WN_MODULE_H

#include "wn_types.h"
#include "wn_pe.h"

/* One entry in a builtin DLL's export table. fn is either an ms_abi function
 * (all builtin APIs are ms_abi so guest code calls them directly) or a data
 * object exported by address. */
typedef struct {
    const char *name;
    void       *fn;
} wn_export_entry;

typedef struct wn_builtin_dll {
    const char           *name;      /* "kernel32.dll" */
    const wn_export_entry *exports;  /* NULL-terminated */
    void                 (*init)(void); /* optional, once per process */
} wn_builtin_dll;

typedef enum {
    WN_MOD_BUILTIN = 0,
    WN_MOD_PE      = 1,
} wn_module_kind;

typedef struct wn_module {
    char              name[64];      /* lowercased basename */
    char              path[1024];    /* host path; "" for builtins */
    uint8_t          *base;          /* guest-visible image base */
    size_t            size;
    wn_module_kind    kind;
    wn_pe_image       pe;            /* valid when kind == WN_MOD_PE */
    const wn_builtin_dll *builtin;   /* valid when kind == WN_MOD_BUILTIN */
    uint32_t          refcount;
    int               loading;       /* import cycle guard */
    uint32_t          tls_index;     /* static TLS index, 0 = none */
    uint64_t          tls_index_va;  /* guest VA of the index slot (TLS dir AddrOfIndex) */
    struct wn_module *next;          /* global module list */
    void             *ldr_entry;     /* guest-visible LDR_DATA_TABLE_ENTRY */
    struct wn_module *next_ldr_load, *prev_ldr_load;
    struct wn_module *next_ldr_mem, *prev_ldr_mem;
    struct wn_module *next_ldr_init, *prev_ldr_init;
} wn_module;

/* Register builtin DLLs; call once at process start. */
void         wn_module_init(void);

/* Load the main executable (PE). Fails hard (logs + returns NULL). */
wn_module   *wn_module_load_exe(const char *host_path);

/* Load a DLL by Windows name ("kernel32.dll", "user32.dll", "foo.dll").
 * Search order: already loaded -> builtin -> <dir> (usually exe dir) ->
 * prefix system32 -> prefix windows -> cwd -> PATH entries. Returns the
 * module or NULL with last error set and a loud log. */
wn_module   *wn_module_load_dll(const char *name, const char *dir);

/* Find an already-loaded module by case-insensitive basename; NULL if absent. */
wn_module   *wn_module_find(const char *name);

/* Find loaded module containing an address (module ranges only).
 * Sets *rva_out when non-NULL. Returns NULL if address is host memory. */
wn_module   *wn_module_from_addr(const void *addr, uint32_t *rva_out);

/* "module!addr (0x...)" description for logs. Always writes something. */
const char  *wn_module_describe_addr(const void *addr, char *buf, size_t cap);

/* Resolve an export: builtin table first, then PE export directory.
 * NULL + loud debug log when missing. */
void        *wn_module_get_proc(wn_module *mod, const char *name,
                                uint16_t ordinal, int by_ordinal);

/* GetProcAddress with a number: treat low word as ordinal when HIWORD==0. */
void        *wn_module_get_proc_ordinal(wn_module *mod, uint32_t ordinal);

/* Walk loaded module list (for LDR, FreeLibrary bookkeeping). */
wn_module   *wn_module_list_head(void);

/* Build the PEB LDR lists from the module list. Call after exe is loaded. */
void         wn_module_build_ldr(void);

/* Increase/decrease refcount. Unmap on zero is deferred (documented decision:
 * guest code may still hold raw pointers; freeing is unsafe). */
wn_module   *wn_module_ref(wn_module *m);
void         wn_module_unref(wn_module *m);

/* Module's Windows path (reverse-mapped host path, e.g. C:\...). */
void         wn_module_win_path(const wn_module *m, char *out, size_t cap);

#endif /* WN_MODULE_H */
