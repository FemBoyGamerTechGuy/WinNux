/* wn_handle.h — generic object handle table (files, threads, sync objects).
 * Handles are nonzero, unique per object, stable for the object's lifetime.
 */
#ifndef WN_HANDLE_H
#define WN_HANDLE_H

#include "wn_types.h"

enum wn_htype {
    WN_HTYPE_FILE      = 1,
    WN_HTYPE_THREAD    = 2,
    WN_HTYPE_EVENT     = 3,
    WN_HTYPE_MUTEX     = 4,
    WN_HTYPE_SEMAPHORE = 5,
    WN_HTYPE_PROCESS   = 6,
    WN_HTYPE_REGKEY    = 7,
    WN_HTYPE_CONSOLE   = 8,
    WN_HTYPE_FIND      = 9,   /* FindFirstFile search */
    WN_HTYPE_GFX       = 10,  /* GDI/user32 later */
    WN_HTYPE_RES       = 11   /* FindResource: opaque HRSRC */
};

typedef struct wn_object {
    uint8_t  type;
    uint32_t refcount;
    void    *ptr;
} wn_object;

/* Allocate a handle for obj. Never returns 0. */
wn_handle  wn_handle_alloc(int type, void *ptr);

/* Look up: returns the object or NULL (sets last error 6). */
wn_object *wn_handle_get(wn_handle h, int expected_type);

/* Like wn_handle_get but pins (refcount++) — pair with wn_handle_release. */
wn_object *wn_handle_acquire(wn_handle h, int expected_type);

/* Drop a reference taken by wn_handle_acquire. Frees at zero. */
void       wn_handle_release(wn_object *o);

/* Close: refcount-- ; when zero, calls the type's destructor if any and
 * frees. Returns 1 on success, 0 invalid handle. */
int        wn_handle_close(wn_handle h);

/* Install a destructor for a type (called with o->ptr at final release). */
void       wn_handle_set_dtor(int type, void (*dtor)(void *));

/* Mark a type's payloads as BORROWED: the handle table refs/deres them but
 * never frees the payload at refcount-0 (the payload's owner outlives the
 * handles — e.g. registry keys are owned by the tree and must outlive every
 * HKEY; RegCloseKey freeing them left freed nodes linked in the tree). */
void       wn_handle_set_nofree(int type);

#endif /* WN_HANDLE_H */
