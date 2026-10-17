/* handle.c — handle table with generations (reuse detection).
 *
 * Layout: handle = (index << 6) | generation. Index 0 reserved so handles
 * are never 0. Table grows geometrically; a spinlock guards structural
 * changes only — hot lookups are lock-free reads over stable slots.
 */
#include "wn_handle.h"
#include "wn_log.h"
#include "wn_util.h"
#include "wn_process.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

typedef struct slot {
    wn_object obj;   /* obj.type == 0 means free */
    uint32_t gen;
} slot;

static slot *g_slots;
static size_t g_cap;             /* power of two */
static size_t g_used;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static void (*g_dtors[16])(void *);

#define HTABLE_INIT_CAP 64

static void table_grow(void)
{
    size_t ncap = g_cap ? g_cap * 2 : HTABLE_INIT_CAP;
    slot *ns = wn_xcalloc(ncap, sizeof *ns);
    if (g_slots)
        memcpy(ns, g_slots, g_cap * sizeof *ns);
    g_slots = ns;
    g_cap = ncap;
}

wn_handle wn_handle_alloc(int type, void *ptr)
{
    pthread_mutex_lock(&g_lock);
    if (g_used >= g_cap / 2)
        table_grow();
    size_t idx = 0;
    for (size_t i = 0; i < g_cap; i++) {
        if (g_slots[i].obj.type == 0) {
            idx = i;
            break;
        }
    }
    g_slots[idx].obj.type = (uint8_t)type;
    g_slots[idx].obj.refcount = 1;
    g_slots[idx].obj.ptr = ptr;
    uint32_t gen = g_slots[idx].gen & 0x3F;
    g_used++;
    pthread_mutex_unlock(&g_lock);
    return (wn_handle)(uintptr_t)(((idx + 1) << 6) | gen);
}

static slot *slot_of(wn_handle h, int expected_type, int *ok)
{
    *ok = 0;
    uint64_t v = (uint64_t)(uintptr_t)h;
    if (v == 0 || (v & 0x3F) == 0x3F)
        return NULL;
    size_t idx = (size_t)(v >> 6) - 1;
    if (idx >= g_cap)
        return NULL;
    slot *s = &g_slots[idx];
    if (s->obj.type == 0)
        return NULL;
    if ((uint32_t)(v & 0x3F) != (s->gen & 0x3F))
        return NULL;
    if (expected_type && s->obj.type != (uint8_t)expected_type)
        return NULL;
    *ok = 1;
    return s;
}

wn_object *wn_handle_get(wn_handle h, int expected_type)
{
    int ok;
    slot *s = slot_of(h, expected_type, &ok);
    if (!ok) {
        wn_last_error_set(WN_ERR_INVALID_HANDLE);
        return NULL;
    }
    return &s->obj;
}

wn_object *wn_handle_acquire(wn_handle h, int expected_type)
{
    int ok;
    slot *s = slot_of(h, expected_type, &ok);
    if (!ok) {
        wn_last_error_set(WN_ERR_INVALID_HANDLE);
        return NULL;
    }
    __atomic_fetch_add(&s->obj.refcount, 1, __ATOMIC_ACQ_REL);
    return &s->obj;
}

void wn_handle_release(wn_object *o)
{
    slot *s = (slot *)((char *)o - offsetof(slot, obj));
    if (__atomic_sub_fetch(&s->obj.refcount, 1, __ATOMIC_ACQ_REL) == 0) {
        pthread_mutex_lock(&g_lock);
        uint8_t t = s->obj.type;
        void *p = s->obj.ptr;
        s->obj.type = 0;
        s->gen++;
        if (g_used)
            g_used--;
        pthread_mutex_unlock(&g_lock);
        if (t < 16 && g_dtors[t])
            g_dtors[t](p);
        free(p);
    }
}

int wn_handle_close(wn_handle h)
{
    int ok;
    slot *s = slot_of(h, 0, &ok);
    if (!ok) {
        wn_last_error_set(WN_ERR_INVALID_HANDLE);
        return 0;
    }
    wn_handle_release(&s->obj);
    return 1;
}

void wn_handle_set_dtor(int type, void (*dtor)(void *))
{
    if (type >= 0 && type < 16)
        g_dtors[type] = dtor;
}
