/* registry.c — in-memory tree + text persistence. */
#include "wn_registry.h"
#include "wn_log.h"
#include "wn_util.h"
#include "wn_path.h"
#include "wn_process.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct wn_reg_value {
    char     *name;
    uint32_t  type;
    uint8_t  *data;
    uint32_t  size;
    struct wn_reg_value *next;
} wn_reg_value;

struct wn_reg_key {
    char     *path;              /* full path e.g. "HKLM\Software\..." */
    struct wn_reg_key *parent;
    struct wn_reg_key *first_child, *next_sibling;
    wn_reg_value *first_value;
};

/* Documented global: the registry roots. */
static wn_reg_key *g_roots[4];
static const char *g_root_names[4] = { "HKCR", "HKCU", "HKLM", "HKU" };

static wn_reg_key *key_new(const char *path)
{
    wn_reg_key *k = wn_xcalloc(1, sizeof *k);
    k->path = wn_xstrdup(path);
    return k;
}

static wn_reg_key *root_of(uint32_t root)
{
    switch (root) {
    case WN_HKEY_CLASSES_ROOT:  return g_roots[0];
    case WN_HKEY_CURRENT_USER:  return g_roots[1];
    case WN_HKEY_LOCAL_MACHINE: return g_roots[2];
    case WN_HKEY_USERS:         return g_roots[3];
    default:                    return NULL;
    }
}

static wn_reg_key *child_find(wn_reg_key *parent, const char *name)
{
    for (wn_reg_key *c = parent->first_child; c; c = c->next_sibling)
        if (wn_strcaseeq(c->path ? strrchr(c->path, '\\') ? strrchr(c->path, '\\') + 1 : c->path : "", name)
            || wn_strcaseeq(c->path, name))
            return c;
    return NULL;
}

static wn_reg_key *child_get(wn_reg_key *parent, const char *name, int create)
{
    wn_reg_key *c = child_find(parent, name);
    if (c || !create)
        return c;
    char path[1024];
    snprintf(path, sizeof path, "%s\\%s", parent->path, name);
    c = key_new(path);
    c->parent = parent;
    c->next_sibling = parent->first_child;
    parent->first_child = c;
    return c;
}

uint32_t wn_reg_open_key(uint32_t root, const char *path, wn_reg_key **key,
                         int create)
{
    wn_reg_key *k = root_of(root);
    if (!k || !path || !*path) {
        if (key) *key = NULL;
        return WN_ERR_INVALID_PARAMETER;
    }
    char copy[1024];
    snprintf(copy, sizeof copy, "%s", path);
    char *save = NULL;
    for (char *part = strtok_r(copy, "\\", &save); part;
         part = strtok_r(NULL, "\\", &save)) {
        wn_reg_key *n = child_get(k, part, create);
        if (!n) {
            if (key) *key = NULL;
            return WN_ERR_PATH_NOT_FOUND;
        }
        k = n;
    }
    if (key)
        *key = k;
    return WN_ERR_SUCCESS;
}

uint32_t wn_reg_query_value(wn_reg_key *key, const char *name, uint32_t *type,
                            void *data, uint32_t *size_inout)
{
    if (!key)
        return WN_ERR_INVALID_HANDLE;
    for (wn_reg_value *v = key->first_value; v; v = v->next) {
        if (wn_strcaseeq(v->name, name)) {
            if (type)
                *type = v->type;
            if (size_inout) {
                if (!data) {
                    *size_inout = v->size;
                    return WN_ERR_SUCCESS;
                }
                if (*size_inout < v->size) {
                    memcpy(data, v->data, *size_inout);
                    *size_inout = v->size;
                    return WN_ERR_MORE_DATA;
                }
                memcpy(data, v->data, v->size);
                *size_inout = v->size;
            }
            return WN_ERR_SUCCESS;
        }
    }
    return WN_ERR_FILE_NOT_FOUND;
}

uint32_t wn_reg_set_value(wn_reg_key *key, const char *name, uint32_t type,
                          const void *data, uint32_t size)
{
    if (!key)
        return WN_ERR_INVALID_HANDLE;
    for (wn_reg_value *v = key->first_value; v; v = v->next) {
        if (wn_strcaseeq(v->name, name)) {
            free(v->data);
            v->data = wn_xmalloc(size ? size : 1);
            memcpy(v->data, data, size);
            v->size = size;
            v->type = type;
            return WN_ERR_SUCCESS;
        }
    }
    wn_reg_value *v = wn_xcalloc(1, sizeof *v);
    v->name = wn_xstrdup(name ? name : "");
    v->type = type;
    v->data = wn_xmalloc(size ? size : 1);
    memcpy(v->data, data, size);
    v->size = size;
    v->next = key->first_value;
    key->first_value = v;
    return WN_ERR_SUCCESS;
}

char *wn_reg_get_string(uint32_t root, const char *path, const char *name)
{
    wn_reg_key *k;
    if (wn_reg_open_key(root, path, &k, 0) != WN_ERR_SUCCESS)
        return NULL;
    char buf[2048];
    uint32_t sz = sizeof buf, type = 0;
    if (wn_reg_query_value(k, name, &type, buf, &sz) != WN_ERR_SUCCESS)
        return NULL;
    if (type == WN_REG_SZ || type == WN_REG_EXPAND_SZ) {
        buf[sz < sizeof buf ? sz : sizeof buf - 1] = '\0';
        return wn_xstrdup(buf);
    }
    return NULL;
}

uint32_t wn_reg_enum_key(wn_reg_key *k, uint32_t idx, char *name, size_t cap)
{
    if (!k)
        return WN_ERR_INVALID_HANDLE;
    uint32_t i = 0;
    for (wn_reg_key *c = k->first_child; c; c = c->next_sibling, i++) {
        if (i == idx) {
            const char *bs = strrchr(c->path, '\\');
            snprintf(name, cap, "%s", bs ? bs + 1 : c->path);
            return WN_ERR_SUCCESS;
        }
    }
    return WN_ERR_NO_MORE_FILES;
}

uint32_t wn_reg_enum_value(wn_reg_key *k, uint32_t idx, char *name, size_t cap,
                           uint32_t *type)
{
    if (!k)
        return WN_ERR_INVALID_HANDLE;
    uint32_t i = 0;
    for (wn_reg_value *v = k->first_value; v; v = v->next, i++) {
        if (i == idx) {
            snprintf(name, cap, "%s", v->name);
            if (type)
                *type = v->type;
            return WN_ERR_SUCCESS;
        }
    }
    return WN_ERR_NO_MORE_FILES;
}

/* --- persistence ---------------------------------------------------------------- */

static void set_str(uint32_t root, const char *path, const char *name,
                    const char *val)
{
    wn_reg_key *k;
    if (wn_reg_open_key(root, path, &k, 1) == WN_ERR_SUCCESS)
        wn_reg_set_value(k, name, WN_REG_SZ, val, (uint32_t)strlen(val) + 1);
}

static void save_tree(FILE *f, wn_reg_key *k)
{
    for (wn_reg_value *v = k->first_value; v; v = v->next) {
        fprintf(f, "%s\t%s\t%u\t", k->path, v->name, v->type);
        for (uint32_t i = 0; i < v->size; i++)
            fprintf(f, "%02x", v->data[i]);
        fputc('\n', f);
    }
    for (wn_reg_key *c = k->first_child; c; c = c->next_sibling)
        save_tree(f, c);
}

void wn_registry_save(void)
{
    char path[1100];
    snprintf(path, sizeof path, "%s/system.reg", g_proc.prefix);
    FILE *f = fopen(path, "we");
    if (!f) {
        wn_log(WN_LOG_WARN, "registry: cannot save %s", path);
        return;
    }
    fprintf(f, "# WinNux registry v1\n");
    for (int i = 0; i < 4; i++)
        if (g_roots[i])
            save_tree(f, g_roots[i]);
    fclose(f);
}

static void insert_line(const char *line)
{
    /* format: keypath \t name \t type \t hexdata */
    char kpath[512], name[256];
    uint32_t type;
    char hex[4096];
    if (sscanf(line, "%511[^\t]\t%255[^\t]\t%u\t%4095s", kpath, name, &type, hex) != 4)
        return;
    uint32_t root = 0;
    const char *sub = NULL;
    if (!strncmp(kpath, "HKLM", 4)) { root = WN_HKEY_LOCAL_MACHINE; sub = kpath + 4; }
    else if (!strncmp(kpath, "HKCU", 4)) { root = WN_HKEY_CURRENT_USER; sub = kpath + 4; }
    else if (!strncmp(kpath, "HKCR", 4)) { root = WN_HKEY_CLASSES_ROOT; sub = kpath + 4; }
    else if (!strncmp(kpath, "HKU", 3))  { root = WN_HKEY_USERS; sub = kpath + 3; }
    else return;
    wn_reg_key *k;
    if (wn_reg_open_key(root, sub && *sub == '\\' ? sub + 1 : sub, &k, 1) != WN_ERR_SUCCESS)
        return;
    size_t hl = strlen(hex);
    if (hl % 2)
        return;
    uint8_t *data = wn_xmalloc(hl / 2 + 1);
    for (size_t i = 0; i < hl / 2; i++) {
        unsigned b;
        if (sscanf(hex + i * 2, "%2x", &b) != 1)
            b = 0;
        data[i] = (uint8_t)b;
    }
    wn_reg_set_value(k, name, type, data, (uint32_t)(hl / 2));
    free(data);
}

void wn_registry_init(void)
{
    for (int i = 0; i < 4; i++)
        g_roots[i] = key_new(g_root_names[i]);

    char path[1100];
    snprintf(path, sizeof path, "%s/system.reg", g_proc.prefix);
    FILE *f = fopen(path, "re");
    if (f) {
        char line[5000];
        while (fgets(line, sizeof line, f)) {
            if (line[0] == '#' || line[0] == '\n')
                continue;
            line[strcspn(line, "\n")] = '\0';
            insert_line(line);
        }
        fclose(f);
    }

    /* Sensible defaults (only where missing). */
    set_str(WN_HKEY_LOCAL_MACHINE,
            "Software\\Microsoft\\Windows\\CurrentVersion",
            "ProgramFilesDir", "C:\\Program Files");
    set_str(WN_HKEY_LOCAL_MACHINE,
            "Software\\Microsoft\\Windows\\CurrentVersion",
            "ProgramFilesDir (x86)", "C:\\Program Files");
    set_str(WN_HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows NT\\CurrentVersion",
            "SystemRoot", "C:\\windows");
    set_str(WN_HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows NT\\CurrentVersion",
            "CurrentVersion", "10.0");
    set_str(WN_HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows NT\\CurrentVersion",
            "CurrentBuild", "19045");
    set_str(WN_HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows NT\\CurrentVersion",
            "ProductName", "WinNux Windows Compat");
    set_str(WN_HKEY_CURRENT_USER, "Environment", "TEMP", "C:\\windows\\temp");
    set_str(WN_HKEY_CURRENT_USER, "Environment", "TMP", "C:\\windows\\temp");
}
