/* advapi32.c — builtin advapi32.dll: registry APIs over wn_registry. */
#include "wn_dll.h"
#include "wn_registry.h"
#include "wn_handle.h"
#include "wn_log.h"
#include "wn_process.h"
#include "wn_util.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* HKEY values are our wn_reg_key* wrapped in the handle table. */
static wn_handle regkey_handle(wn_reg_key *k)
{
    return wn_handle_alloc(WN_HTYPE_REGKEY, k);
}

static WN_API int32_t adv_RegOpenKeyExA(uint32_t root, const char *path,
                                        uint32_t reserved, uint32_t access,
                                        wn_handle *out)
{
    (void)reserved;
    (void)access;
    wn_reg_key *k;
    uint32_t r = wn_reg_open_key(root, path ? path : "", &k, 0);
    if (r != WN_ERR_SUCCESS) {
        wn_last_error_set(r);
        return 2;   /* ERROR_FILE_NOT_FOUND */
    }
    *out = regkey_handle(k);
    return 0;
}

static WN_API int32_t adv_RegOpenKeyExW(uint32_t root, const uint16_t *path,
                                        uint32_t reserved, uint32_t access,
                                        wn_handle *out)
{
    char *a = path ? wn_utf16_to_utf8(path, 4096) : wn_xstrdup("");
    int32_t r = adv_RegOpenKeyExA(root, a, reserved, access, out);
    free(a);
    return r;
}

static WN_API int32_t adv_RegCreateKeyExA(uint32_t root, const char *sub,
                                          uint32_t reserved, char *cls,
                                          uint32_t options, uint32_t access,
                                          void *sa, wn_handle *out,
                                          uint32_t *disposition)
{
    (void)reserved; (void)options; (void)access; (void)sa;
    (void)cls;
    wn_reg_key *k;
    uint32_t r = wn_reg_open_key(root, sub ? sub : "", &k, 1);
    if (r != WN_ERR_SUCCESS) {
        wn_last_error_set(r);
        return r;
    }
    *out = regkey_handle(k);
    if (disposition)
        *disposition = 1; /* REG_CREATED_NEW_KEY (approximation) */
    return 0;
}

static WN_API int32_t adv_RegCreateKeyExW(uint32_t root, const uint16_t *sub,
                                          uint32_t reserved, uint16_t *cls,
                                          uint32_t options, uint32_t access,
                                          void *sa, wn_handle *out,
                                          uint32_t *disposition)
{
    (void)cls;
    char *a = sub ? wn_utf16_to_utf8(sub, 4096) : wn_xstrdup("");
    int32_t r = adv_RegCreateKeyExA(root, a, reserved, NULL, options, access,
                                    sa, out, disposition);
    free(a);
    return r;
}

static WN_API int32_t adv_RegQueryValueExA(wn_handle h, const char *name,
                                           uint32_t *reserved, uint32_t *type,
                                           void *data, uint32_t *size)
{
    (void)reserved;
    wn_object *o = wn_handle_get(h, WN_HTYPE_REGKEY);
    if (!o)
        return 2;
    uint32_t r = wn_reg_query_value(o->ptr, name, type, data, size);
    if (r != WN_ERR_SUCCESS)
        return r == WN_ERR_MORE_DATA ? 234 /* ERROR_MORE_DATA */ : 2;
    return 0;
}

static WN_API int32_t adv_RegQueryValueExW(wn_handle h, const uint16_t *name,
                                           uint32_t *reserved, uint32_t *type,
                                           void *data, uint32_t *size)
{
    char *a = name ? wn_utf16_to_utf8(name, 4096) : wn_xstrdup("");
    uint32_t type_a = 0;
    uint32_t sz = size ? *size : 0;
    /* query size first if data NULL */
    int32_t r = adv_RegQueryValueExA(h, a, reserved, &type_a, data, &sz);
    free(a);
    if (r != 0)
        return r;
    if (type)
        *type = type_a;
    if (size)
        *size = sz;
    return 0;
}

static WN_API int32_t adv_RegSetValueExA(wn_handle h, const char *name,
                                         uint32_t reserved, uint32_t type,
                                         const void *data, uint32_t size)
{
    (void)reserved;
    wn_object *o = wn_handle_get(h, WN_HTYPE_REGKEY);
    if (!o)
        return 2;
    uint32_t r = wn_reg_set_value(o->ptr, name, type, data, size);
    if (r != WN_ERR_SUCCESS) {
        wn_last_error_set(r);
        return 5;
    }
    return 0;
}

static WN_API int32_t adv_RegSetValueExW(wn_handle h, const uint16_t *name,
                                         uint32_t reserved, uint32_t type,
                                         const void *data, uint32_t size)
{
    char *a = name ? wn_utf16_to_utf8(name, 4096) : wn_xstrdup("");
    int32_t r;
    if ((type == WN_REG_SZ || type == WN_REG_EXPAND_SZ) && data && size) {
        /* convert wide data to UTF-8 store */
        const uint16_t *w = data;
        char *u = wn_utf16_to_utf8(w, size / 2);
        size_t l = u ? strlen(u) : 0;
        r = adv_RegSetValueExA(h, a, reserved, type, u ? u : "", (uint32_t)l + 1);
        free(u);
    } else {
        r = adv_RegSetValueExA(h, a, reserved, type, data, size);
    }
    free(a);
    return r;
}

static WN_API int32_t adv_RegCloseKey(wn_handle h)
{
    wn_object *o = wn_handle_get(h, WN_HTYPE_REGKEY);
    if (!o)
        return 2;
    wn_handle_close(h);
    return 0;
}

static WN_API int32_t adv_RegEnumKeyExA(wn_handle h, uint32_t idx, char *name,
                                        uint32_t *namecap, uint32_t *reserved,
                                        char *cls, uint32_t *clscap,
                                        uint64_t *lastwrite)
{
    (void)reserved; (void)cls; (void)clscap; (void)lastwrite;
    wn_object *o = wn_handle_get(h, WN_HTYPE_REGKEY);
    if (!o)
        return 2;
    uint32_t r = wn_reg_enum_key(o->ptr, idx, name, *namecap);
    if (r == WN_ERR_NO_MORE_FILES)
        return 259;
    if (r != WN_ERR_SUCCESS)
        return 5;
    *namecap = (uint32_t)strlen(name);
    return 0;
}

static WN_API int32_t adv_RegEnumValueA(wn_handle h, uint32_t idx, char *name,
                                        uint32_t *namecap, uint32_t *reserved,
                                        uint32_t *type, void *data, uint32_t *size)
{
    (void)reserved;
    wn_object *o = wn_handle_get(h, WN_HTYPE_REGKEY);
    if (!o)
        return 2;
    uint32_t r = wn_reg_enum_value(o->ptr, idx, name, *namecap, type);
    if (r == WN_ERR_NO_MORE_FILES)
        return 259;
    if (r != WN_ERR_SUCCESS)
        return 5;
    *namecap = (uint32_t)strlen(name);
    if (type && data)
        return adv_RegQueryValueExA(h, name, NULL, NULL, data, size);
    return 0;
}

/* GetUserName: real account name from the passwd database. */
#include <pwd.h>
#include <unistd.h>

static void account_name(char *out, size_t cap)
{
    const char *u = getenv("USER");
    if (!u || !*u) {
        struct passwd *pw = getpwuid(getuid());
        u = pw ? pw->pw_name : "user";
    }
    snprintf(out, cap, "%s", u);
}

static WN_API int32_t adv_GetUserNameA(char *buf, uint32_t *cap)
{
    if (!buf || !cap || *cap == 0) {
        wn_last_error_set(WN_ERR_INVALID_PARAMETER);
        return 0;
    }
    char name[256];
    account_name(name, sizeof name);
    size_t need = strlen(name) + 1;
    if (need > *cap) {
        *cap = (uint32_t)need;
        wn_last_error_set(WN_ERR_INSUFFICIENT_BUFFER);
        return 0;
    }
    memcpy(buf, name, need);
    *cap = (uint32_t)need;
    return 1;
}

static WN_API int32_t adv_GetUserNameW(uint16_t *buf, uint32_t *cap)
{
    if (!buf || !cap || *cap == 0) {
        wn_last_error_set(WN_ERR_INVALID_PARAMETER);
        return 0;
    }
    char name[256];
    account_name(name, sizeof name);
    uint16_t *w = wn_utf8_to_utf16_n(name, strlen(name));
    if (!w) {
        wn_last_error_set(WN_ERR_NOT_ENOUGH_MEMORY);
        return 0;
    }
    size_t n = 0;
    while (w[n])
        n++;
    size_t need = n + 1;
    if (need > *cap) {
        *cap = (uint32_t)need;
        wn_last_error_set(WN_ERR_INSUFFICIENT_BUFFER);
        free(w);
        return 0;
    }
    memcpy(buf, w, need * 2);
    *cap = (uint32_t)need;
    free(w);
    return 1;
}

const wn_export_entry wn_advapi32_exports[] = {
    { "RegCloseKey", adv_RegCloseKey },
    { "RegCreateKeyExA", adv_RegCreateKeyExA },
    { "RegCreateKeyExW", adv_RegCreateKeyExW },
    { "RegEnumKeyExA", adv_RegEnumKeyExA },
    { "RegEnumValueA", adv_RegEnumValueA },
    { "RegOpenKeyExA", adv_RegOpenKeyExA },
    { "RegOpenKeyExW", adv_RegOpenKeyExW },
    { "RegQueryValueExA", adv_RegQueryValueExA },
    { "RegQueryValueExW", adv_RegQueryValueExW },
    { "RegSetValueExA", adv_RegSetValueExA },
    { "RegSetValueExW", adv_RegSetValueExW },
    { "GetUserNameA", adv_GetUserNameA },
    { "GetUserNameW", adv_GetUserNameW },
    { NULL, NULL },
};
