/* sync.c — futex-backed Windows sync objects.
 *
 * Encoding decisions:
 *   event.state    0/1. Auto-reset consumers do an atomic xchg(0); if they
 *                  got 1, they consumed the signal.
 *   mutex.state    64-bit: low 32 bits = contended flag, high 32 = owner
 *                  thread id (0 = unowned). Recursive via `recursion`.
 *   sem.count      plain counter with cmpxchg.
 * WFMO(any) loop: poll all objects, then sleep on the global wake channel;
 * every signal operation wakes the global channel too.
 */
#include "wn_sync.h"
#include "wn_process.h"
#include "wn_handle.h"
#include "wn_log.h"

#include <errno.h>
#include <string.h>
#include <time.h>

static void wake_global(void)
{
    wn_futex_wake(&g_proc.global_wake, 1 << 30);
}

/* --- events ------------------------------------------------------------------ */

int wn_event_init(wn_event *e, int manual, int initial)
{
    e->state = initial ? 1 : 0;
    e->manual = manual;
    e->name[0] = '\0';
    return 0;
}

void wn_event_set(wn_event *e)
{
    if (__atomic_exchange_n(&e->state, 1, __ATOMIC_ACQ_REL) == 0) {
        wn_futex_wake(&e->state, e->manual ? 1 << 30 : 1);
        wake_global();
    }
}

void wn_event_reset(wn_event *e)
{
    __atomic_store_n(&e->state, 0, __ATOMIC_RELEASE);
}

int wn_event_try_wait(wn_event *e)
{
    if (e->manual)
        return __atomic_load_n(&e->state, __ATOMIC_ACQUIRE) != 0;
    return __atomic_exchange_n(&e->state, 0, __ATOMIC_ACQ_REL) != 0;
}

/* --- mutexes ------------------------------------------------------------------- */

int wn_mutex_init(wn_mutex *m)
{
    m->state = 0;
    m->recursion = 0;
    m->name[0] = '\0';
    return 0;
}

int wn_mutex_try(wn_mutex *m)
{
    uint32_t me = wn_teb_current()->client_id_thread;
    uint64_t cur = __atomic_load_n(&m->state, __ATOMIC_ACQUIRE);
    if ((cur >> 32) == me) {
        m->recursion++;
        return 1;
    }
    if (cur == 0 &&
        __atomic_compare_exchange_n(&m->state, &cur,
                                    ((uint64_t)me << 32) | 0ULL,
                                    0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        m->recursion = 1;
        return 1;
    }
    return 0;
}

int wn_mutex_release(wn_mutex *m)
{
    uint32_t me = wn_teb_current()->client_id_thread;
    uint64_t cur = __atomic_load_n(&m->state, __ATOMIC_ACQUIRE);
    if ((cur >> 32) != me)
        return 0;              /* not owner: Windows fails ReleaseMutex */
    if (--m->recursion > 0)
        return 1;
    __atomic_store_n(&m->state, 0, __ATOMIC_RELEASE);
    wn_futex_wake((uint32_t *)&m->state, 1);
    wake_global();
    return 1;
}

uint32_t wn_mutex_owner(wn_mutex *m)
{
    return (uint32_t)(__atomic_load_n(&m->state, __ATOMIC_ACQUIRE) >> 32);
}

/* --- semaphores ------------------------------------------------------------------ */

int wn_sem_init(wn_semaphore *s, uint32_t initial, uint32_t max)
{
    s->count = initial;
    s->max = max;
    s->name[0] = '\0';
    return 0;
}

int wn_sem_try(wn_semaphore *s)
{
    for (;;) {
        uint32_t c = __atomic_load_n(&s->count, __ATOMIC_ACQUIRE);
        if (c == 0)
            return 0;
        if (__atomic_compare_exchange_n(&s->count, &c, c - 1,
                                        0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            return 1;
    }
}

int wn_sem_release(wn_semaphore *s, uint32_t n, uint32_t *prev)
{
    for (;;) {
        uint32_t c = __atomic_load_n(&s->count, __ATOMIC_ACQUIRE);
        if ((uint64_t)c + n > s->max)
            return 0;
        if (__atomic_compare_exchange_n(&s->count, &c, c + n,
                                        0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
            if (prev)
                *prev = c;
            wn_futex_wake(&s->count, 1 << 30);
            wake_global();
            return 1;
        }
    }
}

/* --- waiting on handles ---------------------------------------------------------- */

/* Try-wait a single object without blocking. 1 = satisfied. */
static int try_object(wn_object *o)
{
    switch (o->type) {
    case WN_HTYPE_EVENT:     return wn_event_try_wait((wn_event *)o->ptr);
    case WN_HTYPE_MUTEX:     return wn_mutex_try((wn_mutex *)o->ptr);
    case WN_HTYPE_SEMAPHORE: return wn_sem_try((wn_semaphore *)o->ptr);
    case WN_HTYPE_THREAD: {
        wn_thread *t = o->ptr;
        return __atomic_load_n(&t->exited, __ATOMIC_ACQUIRE) != 0;
    }
    default:
        wn_last_error_set(WN_ERR_INVALID_HANDLE);
        return -1;
    }
}

static struct timespec deadline_from_ms(uint32_t timeout_ms)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    struct timespec dl = {
        .tv_sec = now.tv_sec + timeout_ms / 1000,
        .tv_nsec = now.tv_nsec + (long)(timeout_ms % 1000) * 1000000L,
    };
    if (dl.tv_nsec >= 1000000000L) {
        dl.tv_sec += 1;
        dl.tv_nsec -= 1000000000L;
    }
    return dl;
}

static int ts_left_ms(const struct timespec *dl, int infinite)
{
    if (infinite)
        return -1;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    int64_t ns = (int64_t)(dl->tv_sec - now.tv_sec) * 1000000000
               + (dl->tv_nsec - now.tv_nsec);
    if (ns <= 0)
        return 0;
    return (int)(ns / 1000000);
}

uint32_t wn_wait_single(wn_handle h, uint32_t timeout_ms)
{
    wn_object *o = wn_handle_acquire(h, 0);
    if (!o)
        return WN_WAIT_FAILED;

    int infinite = (timeout_ms == 0xFFFFFFFF);
    struct timespec dl = deadline_from_ms(timeout_ms);

    for (;;) {
        int r = try_object(o);
        if (r == -1) {
            wn_handle_release(o);
            return WN_WAIT_FAILED;
        }
        if (r == 1) {
            wn_handle_release(o);
            return WN_WAIT_OBJECT_0;
        }
        if (!infinite && ts_left_ms(&dl, 0) <= 0) {
            wn_handle_release(o);
            wn_last_error_set(WN_WAIT_TIMEOUT);
            return WN_WAIT_TIMEOUT;
        }
        /* Block on the object's own word when possible. */
        if (o->type == WN_HTYPE_EVENT) {
            wn_futex_wait(&((wn_event *)o->ptr)->state, 0,
                          infinite ? NULL : &dl);
        } else if (o->type == WN_HTYPE_SEMAPHORE) {
            wn_futex_wait(&((wn_semaphore *)o->ptr)->count, 0,
                          infinite ? NULL : &dl);
        } else if (o->type == WN_HTYPE_MUTEX) {
            wn_futex_wait((uint32_t *)&((wn_mutex *)o->ptr)->state, 0,
                          infinite ? NULL : &dl);
        } else {  /* thread or other: poll */
            struct timespec nap = { .tv_sec = 0, .tv_nsec = 20000000 };
            nanosleep(&nap, NULL);
        }
    }
}

uint32_t wn_wait_multiple(uint32_t count, const wn_handle *handles,
                          int wait_all, uint32_t timeout_ms)
{
    if (count == 0 || count > 64) {
        wn_last_error_set(WN_ERR_INVALID_PARAMETER);
        return WN_WAIT_FAILED;
    }
    if (count == 1 && !wait_all)
        return wn_wait_single(handles[0], timeout_ms);

    int infinite = (timeout_ms == 0xFFFFFFFF);
    struct timespec dl = deadline_from_ms(timeout_ms);

    wn_object *objs[64];
    for (uint32_t i = 0; i < count; i++) {
        objs[i] = wn_handle_acquire(handles[i], 0);
        if (!objs[i]) {
            for (uint32_t j = 0; j < i; j++)
                wn_handle_release(objs[j]);
            return WN_WAIT_FAILED;
        }
    }

    for (;;) {
        if (wait_all) {
            int all = 1;
            for (uint32_t i = 0; i < count && all; i++)
                if (!try_object(objs[i]))
                    all = 0;
            if (all) {
                for (uint32_t i = 0; i < count; i++)
                    wn_handle_release(objs[i]);
                return WN_WAIT_OBJECT_0;
            }
        } else {
            for (uint32_t i = 0; i < count; i++) {
                int r = try_object(objs[i]);
                if (r == -1) {
                    for (uint32_t j = 0; j < count; j++)
                        wn_handle_release(objs[j]);
                    return WN_WAIT_FAILED;
                }
                if (r == 1) {
                    for (uint32_t j = 0; j < count; j++)
                        wn_handle_release(objs[j]);
                    return WN_WAIT_OBJECT_0 + i;
                }
            }
        }
        if (!infinite && ts_left_ms(&dl, 0) <= 0) {
            for (uint32_t i = 0; i < count; i++)
                wn_handle_release(objs[i]);
            wn_last_error_set(WN_WAIT_TIMEOUT);
            return WN_WAIT_TIMEOUT;
        }
        int left = ts_left_ms(&dl, infinite);
        if (left < 0 || left > 20) {
            struct timespec nap = { .tv_sec = 0, .tv_nsec = 10000000 };
            nanosleep(&nap, NULL);
        } else {
            struct timespec nap = { .tv_sec = 0, .tv_nsec = 2000000 };
            nanosleep(&nap, NULL);
        }
    }
}

/* --- critical sections (guest in-place structs) ----------------------------------- */

void wn_critsect_init(wn_critsect *cs, uint32_t spin)
{
    memset(cs, 0, sizeof *cs);
    cs->lock_count = -1;
    cs->spin_count = spin;
}

void wn_critsect_enter(wn_critsect *cs)
{
    uint32_t me = wn_teb_current()->client_id_thread;
    for (;;) {
        int32_t cur = -1;
        if (__atomic_compare_exchange_n(&cs->lock_count, &cur, 0,
                                        0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
            cs->owning_thread = me;
            cs->recursion_count = 1;
            return;
        }
        if (cs->owning_thread == me) {
            cs->recursion_count++;
            return;
        }
        wn_futex_wait((uint32_t *)&cs->lock_count, cur, NULL);
    }
}

int wn_critsect_try(wn_critsect *cs)
{
    int32_t cur = -1;
    if (__atomic_compare_exchange_n(&cs->lock_count, &cur, 0,
                                    0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        cs->owning_thread = wn_teb_current()->client_id_thread;
        cs->recursion_count = 1;
        return 1;
    }
    return 0;
}

void wn_critsect_leave(wn_critsect *cs)
{
    if (--cs->recursion_count > 0)
        return;
    cs->owning_thread = 0;
    __atomic_store_n(&cs->lock_count, -1, __ATOMIC_RELEASE);
    wn_futex_wake((uint32_t *)&cs->lock_count, 1);
}

void wn_critsect_delete(wn_critsect *cs)
{
    (void)cs;
}
