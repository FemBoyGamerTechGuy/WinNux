/* virtual.c — VirtualAlloc/VirtualProtect/VirtualQuery over mmap.
 *
 * Allocations are tracked in a list for fast VirtualQuery; arbitrary
 * addresses (guest-foreign regions) are answered from /proc/self/maps.
 */
#include "wn_process.h"
#include "wn_wow64.h"
#include "wn_log.h"
#include "wn_util.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

typedef struct vregion {
    uint64_t start, end;
    uint32_t prot;       /* Win32 page protection value */
    uint32_t state;      /* 0x1000 MEM_COMMIT or 0x2000 MEM_RESERVE */
    struct vregion *next;
} vregion;

/* Documented global: list of VirtualAlloc regions. */
static vregion *g_regions;
static pthread_mutex_t g_reg_lock = PTHREAD_MUTEX_INITIALIZER;

/* Win32 protection constants (subset). */
#define PAGE_NOACCESS          0x01
#define PAGE_READONLY          0x02
#define PAGE_READWRITE         0x04
#define PAGE_WRITECOPY         0x08
#define PAGE_EXECUTE           0x10
#define PAGE_EXECUTE_READ      0x20
#define PAGE_EXECUTE_READWRITE 0x40
#define PAGE_EXECUTE_WRITECOPY 0x80
#define WN_MEM_COMMIT  0x1000
#define WN_MEM_RESERVE 0x2000

static int win_to_prot(uint32_t wp)
{
    switch (wp & 0xFF) {   /* modifiers (GUARD/NOCACHE/WRITECOMBINE) masked */
    case PAGE_NOACCESS:      return PROT_NONE;
    case PAGE_READONLY:      return PROT_READ;
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:     return PROT_READ | PROT_WRITE;
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:  return PROT_READ | PROT_EXEC;
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY: return PROT_READ | PROT_WRITE | PROT_EXEC;
    }
    wn_log(WN_LOG_WARN, "virtual: unknown page protection 0x%x "
           "(read-write assumed)", wp);
    return PROT_READ | PROT_WRITE;
}

static void region_add(uint64_t s, uint64_t e, uint32_t prot, uint32_t state)
{
    pthread_mutex_lock(&g_reg_lock);
    vregion *r = wn_xmalloc(sizeof *r);
    r->start = s; r->end = e; r->prot = prot; r->state = state;
    r->next = g_regions;
    g_regions = r;
    pthread_mutex_unlock(&g_reg_lock);
}

static void region_remove(uint64_t s, uint64_t e)
{
    pthread_mutex_lock(&g_reg_lock);
    vregion **pp = &g_regions;
    while (*pp) {
        if ((*pp)->start == s && (*pp)->end == e) {
            vregion *dead = *pp;
            *pp = dead->next;
            free(dead);
        } else {
            pp = &(*pp)->next;
        }
    }
    pthread_mutex_unlock(&g_reg_lock);
}

/* --- public API used by kernel32 ------------------------------------------- */

static void *wn_virtual_alloc_inner(void *hint, uint64_t size, uint32_t type,
                                    uint32_t prot);

void *wn_virtual_alloc(void *hint, uint64_t size, uint32_t type, uint32_t prot)
{
    void *res = wn_virtual_alloc_inner(hint, size, type, prot);
    wn_log(WN_LOG_DEBUG, " valloc addr=%p size=0x%llx type=0x%x prot=0x%x "
           "-> %p", hint, (unsigned long long)size, type, prot, res);
    return res;
}

static void *wn_virtual_alloc_inner(void *hint, uint64_t size, uint32_t type,
                                    uint32_t prot)
{
    if (size == 0 || size > 0x100000000ULL) {
        wn_log(WN_LOG_WARN, "virtual: VirtualAlloc size 0x%llx rejected",
               (unsigned long long)size);
        return NULL;
    }
    int commit  = (type & WN_MEM_COMMIT) != 0;
    int reserve = (type & WN_MEM_RESERVE) != 0;
    if (!commit && !reserve) {
        wn_log(WN_LOG_WARN, "virtual: VirtualAlloc type 0x%x lacks "
               "MEM_COMMIT/MEM_RESERVE", type);
        return NULL;
    }
    int p = win_to_prot(prot);
    uint64_t a = (uint64_t)(uintptr_t)hint;

    if (commit && !reserve && a != 0) {
        /* Windows: committing a range the process already reserved commits
         * IN PLACE — the address is not negotiable and the reservation
         * survives. The old code always made a fresh mmap, which the kernel
         * displaced whenever the reservation covered the address; callers
         * that keep using their original base (the Delphi/Inno allocator)
         * then faulted on the still-PROT_NONE reserve. */
        uint64_t page_a = a & ~0xFFFULL;
        uint64_t usize = (size + 0xFFF) & ~0xFFFULL;
        /* Extend to the 64KB allocation-granularity boundary (Windows 9x
         * committed whole granules; the old Delphi/Inno heap manager READS
         * its pool-end sentinel 4 bytes past the requested commit —
         * LuaForWindows: SEGV reading [commit_end] during block coalescing
         * without this). Never past the reservation end. */
        pthread_mutex_lock(&g_reg_lock);
        vregion *r = g_regions;
        while (r && !(r->start <= page_a && r->end > page_a))
            r = r->next;
        if (r) {
            uint64_t end = page_a + usize;
            uint64_t g64 = (end + 0xFFFF) & ~0xFFFFULL;
            if (g64 > r->end)
                g64 = r->end;
            if (g64 > end)
                usize = g64 - page_a;
        }
        if (r && r->end - page_a >= usize &&
            mprotect((void *)(uintptr_t)page_a, usize, p) == 0) {
            r->state = WN_MEM_COMMIT;
            if (r->prot == 0 || r->prot == PAGE_NOACCESS)
                r->prot = prot;
            pthread_mutex_unlock(&g_reg_lock);
            return (void *)(uintptr_t)page_a;
        }
        pthread_mutex_unlock(&g_reg_lock);
        /* Not one of our reservations (or overruns it): Windows fails for
         * an unreserved/unaligned address. Ask for exactly that range,
         * refusing to clobber anything that already lives there. */
        if ((a & 0xFFF) == 0) {
            void *base = mmap(hint, usize, p,
                              MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE
                                  | MAP_FIXED_NOREPLACE
                                  | (g_wow64_active ? MAP_32BIT : 0),
                              -1, 0);
            if (base == MAP_FAILED) {
                wn_log(WN_LOG_WARN, "virtual: MEM_COMMIT at %p (size 0x%llx) "
                       "failed", hint, (unsigned long long)size);
                return NULL;
            }
            if ((uint64_t)(uintptr_t)base != a) {
                /* Pre-4.17 kernel ignored MAP_FIXED_NOREPLACE. */
                munmap(base, usize);
                return NULL;
            }
            region_add(a, a + usize, prot, WN_MEM_COMMIT);
            return (void *)(uintptr_t)a;
        }
        wn_log(WN_LOG_WARN, "virtual: MEM_COMMIT of unaligned %p", hint);
        return NULL;
    }

    /* Reserve (+ same-call commit): 64K granularity like Windows. NOTE:
     * MEM_COMMIT without MEM_RESERVE and lpAddress==NULL is legal on
     * Windows - the system implicitly reserves AND commits. The old
     * `commit && reserve` test mapped such requests PROT_NONE while
     * tagging them COMMIT (LZMA state in the NSIS installer: SEGV_ACCERR
     * write fault at the returned buffer). */
    uint64_t usize = (size + 0xFFFF) & ~0xFFFFULL;
    if (usize == 0)
        usize = 0x10000;
    int want = commit ? p : PROT_NONE;
    void *base = mmap(hint, usize, want,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE
                          | ((a != 0) ? MAP_FIXED_NOREPLACE : 0)
                          | (g_wow64_active ? MAP_32BIT : 0),
                      -1, 0);
    if (base == MAP_FAILED && g_wow64_active && a == 0) {
        /* low space fragmented: retry without the hint constraint */
        base = mmap(NULL, usize, want,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_32BIT,
                    -1, 0);
    }
    if (base == MAP_FAILED) {
        wn_log(WN_LOG_WARN, "virtual: reserve of 0x%llx bytes at %p failed",
               (unsigned long long)usize, hint);
        return NULL;
    }
    if (a != 0 && (uint64_t)(uintptr_t)base != a) {
        /* Windows never relocates an explicitly requested address. */
        munmap(base, usize);
        return NULL;
    }
    region_add((uint64_t)(uintptr_t)base,
               (uint64_t)(uintptr_t)base + usize, prot,
               commit ? WN_MEM_COMMIT : WN_MEM_RESERVE);
    return base;
}

int wn_virtual_free(void *addr, uint64_t size, uint32_t type)
{
    wn_log(WN_LOG_DEBUG, " vfree addr=%p size=0x%llx type=0x%x",
           addr, (unsigned long long)size, type);
    if (type & 0x8000 /* MEM_RELEASE */) {
        if (size == 0) {
            /* Windows: release the entire allocation. Find its region. */
            pthread_mutex_lock(&g_reg_lock);
            uint64_t s = 0, e = 0;
            for (vregion *r = g_regions; r; r = r->next) {
                if (r->start == (uint64_t)(uintptr_t)addr) {
                    s = r->start;
                    e = r->end;
                    break;
                }
            }
            pthread_mutex_unlock(&g_reg_lock);
            if (!e || munmap(addr, (size_t)(e - s)) != 0)
                return 0;
            region_remove(s, e);
            return 1;
        }
        size = (size + 0xFFFF) & ~0xFFFFULL;
        if (munmap(addr, size) != 0)
            return 0;
        region_remove((uint64_t)(uintptr_t)addr,
                      (uint64_t)(uintptr_t)addr + size);
        return 1;
    }
    if (type & 0x4000 /* MEM_DECOMMIT */) {
        /* Re-map anonymous over the range (zeroes, PROT_NONE). */
        if (mmap(addr, (size + 0xFFF) & ~0xFFFULL, PROT_NONE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == MAP_FAILED)
            return 0;
        return 1;
    }
    return 0;
}

int wn_virtual_protect(void *addr, uint64_t size, uint32_t newprot,
                       uint32_t *oldprot_out)
{
    size = (size + 0xFFF) & ~0xFFFULL;
    /* Query old protection from /proc for arbitrary regions. */
    uint32_t old = 0;
    int found = 0;
    pthread_mutex_lock(&g_reg_lock);
    for (vregion *r = g_regions; r; r = r->next) {
        if (r->start <= (uint64_t)(uintptr_t)addr && r->end > (uint64_t)(uintptr_t)addr) {
            old = r->prot;
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock(&g_reg_lock);
    if (!found) {
        FILE *f = fopen("/proc/self/maps", "re");
        if (f) {
            char line[512];
            uint64_t a = (uint64_t)(uintptr_t)addr;
            while (fgets(line, sizeof line, f)) {
                unsigned long ls, le;   /* %lx width: 4 bytes on i386! */
                char perms[8];
                if (sscanf(line, "%lx-%lx %4s", &ls, &le, perms) == 3) {
                    uint64_t s = ls, e = le;
                    if (s <= a && e > a) {
                        old = 0;
                        if (perms[0] == 'r') old |= 0x02;
                        if (perms[1] == 'w') old |= 0x04;
                        if (perms[2] == 'x') old |= 0x10;
                        if (!old) old = 0x01;
                        found = 1;
                        break;
                    }
                }
            }
            fclose(f);
        }
    }
    if (mprotect(addr, size, win_to_prot(newprot)) != 0) {
        wn_last_error_set(WN_ERR_INVALID_PARAMETER);
        return 0;
    }
    if (oldprot_out)
        *oldprot_out = old ? old : 0x02;
    if (found)
        region_add((uint64_t)(uintptr_t)addr,
                   (uint64_t)(uintptr_t)addr + size, newprot, WN_MEM_COMMIT);
    return 1;
}

/* Fill MEMORY_BASIC_INFORMATION. Layouts differ by arch — i386 MBI is 28
 * bytes of 4-byte fields, x64 is 48 bytes with 8-byte pointers:
 * Base@0, AllocationBase@+1, AllocationProtect@+2, RegionSize@+3,
 * State@+4, Protect@+4b, Type@+5. */
#define WN_MBI_FIELD(m, idx, val) do { \
    wn_abiword *_q = (wn_abiword *)(m); _q[(idx)] = (wn_abiword)(val); \
} while (0)

static void mbi_fill(void *mbi, uint64_t base, uint64_t alloc_base,
                     uint32_t alloc_prot, uint64_t region_size,
                     uint32_t state, uint32_t protect)
{
    uint8_t *m = mbi;
#if defined(__x86_64__)
    memset(m, 0, 48);
    WN_MBI_FIELD(m, 0, base);
    WN_MBI_FIELD(m, 1, alloc_base);
    *(uint32_t *)(m + 16) = alloc_prot;
    WN_MBI_FIELD(m, 3, region_size);
    *(uint32_t *)(m + 32) = state;
    *(uint32_t *)(m + 36) = protect;
    *(uint32_t *)(m + 40) = 0x20000 /* MEM_PRIVATE */;
#else
    memset(m, 0, 28);
    *(uint32_t *)(m + 0)  = (uint32_t)base;
    *(uint32_t *)(m + 4)  = (uint32_t)alloc_base;
    *(uint32_t *)(m + 8)  = alloc_prot;
    *(uint32_t *)(m + 12) = (uint32_t)region_size;
    *(uint32_t *)(m + 16) = state;
    *(uint32_t *)(m + 20) = protect;
    *(uint32_t *)(m + 24) = 0x20000 /* MEM_PRIVATE */;
#endif
}

static int wn_virtual_query_inner(void *addr, void *mbi);

int wn_virtual_query(void *addr, void *mbi)
{
    int rc = wn_virtual_query_inner(addr, mbi);
    if (!rc)
        wn_log(WN_LOG_DEBUG, "virtual: VirtualQuery(%p) FAILED", addr);
    return rc;
}

static int wn_virtual_query_inner(void *addr, void *mbi)
{
    uint64_t a = (uint64_t)(uintptr_t)addr;
    pthread_mutex_lock(&g_reg_lock);
    for (vregion *r = g_regions; r; r = r->next) {
        if (r->start <= a && r->end > a) {
            mbi_fill(mbi, r->start, r->start, r->prot, r->end - r->start,
                     r->state ? r->state : 0x1000, r->prot);
            pthread_mutex_unlock(&g_reg_lock);
            return 1;
        }
    }
    pthread_mutex_unlock(&g_reg_lock);

    /* Not ours: consult /proc/self/maps. */
    FILE *f = fopen("/proc/self/maps", "re");
    if (!f)
        return 0;
    char line[512];
    int ok = 0;
    while (fgets(line, sizeof line, f)) {
        unsigned long ls, le;   /* %lx width: 4 bytes on i386! */
        char perms[8];
        if (sscanf(line, "%lx-%lx %4s", &ls, &le, perms) != 3)
            continue;
        uint64_t s = ls, e = le;
        if (s <= a && e > a) {
            uint32_t p = 0;
            if (perms[0] == 'r') p |= 0x02;
            if (perms[1] == 'w') p |= 0x04;
            if (perms[2] == 'x') p |= 0x10;
            if (!p) p = 0x01;
            uint32_t state = (perms[0] == '-' && perms[1] == '-')
                                 ? 0x10000 /* MEM_FREE */ : 0x1000;
            mbi_fill(mbi, s, s, p, e - s, state, p);
            ok = 1;
            break;
        }
    }
    fclose(f);
    return ok;
}
