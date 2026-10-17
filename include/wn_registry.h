/* wn_registry.h — simple file-backed registry (prefix/system.reg).
 * Text format, one line per value:
 *   key<TAB>name<TAB>type<TAB>data(hex bytes)
 */
#ifndef WN_REGISTRY_H
#define WN_REGISTRY_H

#include <stddef.h>
#include <stdint.h>

#define WN_HKEY_CLASSES_ROOT   0x80000000u
#define WN_HKEY_CURRENT_USER   0x80000001u
#define WN_HKEY_LOCAL_MACHINE  0x80000002u
#define WN_HKEY_USERS          0x80000003u

#define WN_REG_NONE       0
#define WN_REG_SZ         1
#define WN_REG_EXPAND_SZ  2
#define WN_REG_BINARY     3
#define WN_REG_DWORD      4

typedef struct wn_reg_key wn_reg_key;

/* Load from prefix/system.reg (creating defaults if missing). */
void wn_registry_init(void);

/* Save current tree to prefix/system.reg. Called at process exit. */
void wn_registry_save(void);

/* Open/create keys. Path like "Software\\Vendor\\App" under root.
 * Returns 0 and sets *key, or a Win32 error code. */
uint32_t wn_reg_open_key(uint32_t root, const char *path, wn_reg_key **key,
                         int create);

uint32_t wn_reg_query_value(wn_reg_key *key, const char *name, uint32_t *type,
                            void *data, uint32_t *size_inout);

uint32_t wn_reg_set_value(wn_reg_key *key, const char *name, uint32_t type,
                          const void *data, uint32_t size);

/* Get a string value quickly (NULL when missing). Caller frees. */
char *wn_reg_get_string(uint32_t root, const char *path, const char *name);

/* Enumerate subkeys / values. Returns 0 or WN_ERR_NO_MORE_FILES. */
uint32_t wn_reg_enum_key(wn_reg_key *k, uint32_t idx, char *name, size_t cap);
uint32_t wn_reg_enum_value(wn_reg_key *k, uint32_t idx, char *name, size_t cap,
                           uint32_t *type);

#endif /* WN_REGISTRY_H */
