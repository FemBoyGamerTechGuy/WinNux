/* wn_sync.h — Windows synchronization objects over Linux futexes.
 *
 * Event (auto/manual), Mutex (recursive), Semaphore. Single-object waits use
 * the object's own futex word. WaitForMultipleObjects uses a global wake
 * channel (correct, some thundering herd; documented in ARCHITECTURE.md).
 */
#ifndef WN_SYNC_H
#define WN_SYNC_H

#include "wn_types.h"
#include "wn_process.h"

typedef struct wn_event {
    uint32_t state;       /* 0 unsignaled / 1 signaled */
    int      manual;
    char     name[64];
} wn_event;

typedef struct wn_mutex {
    uint64_t state;       /* low32: contended flag, high32: owner tid */
    int32_t  recursion;
    char     name[64];
} wn_mutex;

typedef struct wn_semaphore {
    uint32_t count;
    uint32_t max;
    char     name[64];
} wn_semaphore;

/* Creators: return 0 on success; set last error otherwise. Objects are
 * wrapped in the handle table by the callers (kernel32.c). */
int wn_event_init(wn_event *e, int manual, int initial);
int wn_mutex_init(wn_mutex *m);
int wn_sem_init(wn_semaphore *s, uint32_t initial, uint32_t max);

/* Operations (used by kernel32 + WFMO). */
void wn_event_set(wn_event *e);
void wn_event_reset(wn_event *e);
int  wn_event_try_wait(wn_event *e);            /* consumes auto-reset */

int  wn_mutex_try(wn_mutex *m);                 /* 1 acquired, 0 not */
int  wn_mutex_release(wn_mutex *m);
uint32_t wn_mutex_owner(wn_mutex *m);

int  wn_sem_try(wn_semaphore *s);               /* 1 acquired */
int  wn_sem_release(wn_semaphore *s, uint32_t n, uint32_t *prev);

/* Wait: returns WN_WAIT object or error. timeout_ms: 0 poll, -1 infinite. */
#define WN_WAIT_OBJECT_0    0
#define WN_WAIT_IO         0x80
#define WN_WAIT_TIMEOUT    0x102
#define WN_WAIT_FAILED     0xFFFFFFFF
#define WN_WAIT_ABANDONED  0x80

/* Generic dispatch used by kernel32 waits (knows object types via handles). */
uint32_t wn_wait_single(wn_handle h, uint32_t timeout_ms);
uint32_t wn_wait_multiple(uint32_t count, const wn_handle *handles,
                          int wait_all, uint32_t timeout_ms);

/* Critical sections (guest-visible in-place objects). x86 (32-bit) layout
 * variants for the wow64 layer: RTL_CRITICAL_SECTION is 24 bytes on i386. */
void wn_critsect32_init(void *cs, uint32_t spin);
void wn_critsect32_enter(void *cs);
int  wn_critsect32_try(void *cs);
void wn_critsect32_leave(void *cs);
void wn_critsect32_delete(void *cs);

/* Critical sections operate on guest in-place structures. */
void wn_critsect_init(wn_critsect *cs, uint32_t spin);
void wn_critsect_enter(wn_critsect *cs);
void wn_critsect_leave(wn_critsect *cs);
int  wn_critsect_try(wn_critsect *cs);
void wn_critsect_delete(wn_critsect *cs);

#endif /* WN_SYNC_H */
