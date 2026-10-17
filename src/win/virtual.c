/* virtual.c — VirtualAlloc/VirtualProtect/VirtualQuery over mmap.
 *
 * Allocations are tracked in a list for fast VirtualQuery; arbitrary
 * addresses (guest-foreign regions) are answered from /proc/self/maps.
 */
#include "wn_process.h"
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
    struct vregion *next;
} vregion;

/* Documented global: list of VirtualAlloc regions. */
static vregion *g_regions;
static pthread_mutex_t g_reg_lock = PTHREAD_MUTEX_INITIALIZER;

/* Win32 protection constants (subset). */
#define PAGE_NOACCESS          0x01
#define PAGE_READONLY          0x02
#define PAGE_READWRITE         0x04
#define PAGE_EXECUTE           0x10
#define PAGE_EXECUTE_READ      0x20
#define PAGE_EXECUTE_READWRITE 0x40

static int win_to_prot(uint32_t wp)
{
    int p = 0;
    if (wp & 0x02) p |= PROT_READ;
    if (wp & 0x04) p |= PROT_WRITE;
    if (wp & 0x10) p |= PROT_EXEC;
    return p;
}

static void region_add(uint64_t s, uint64_t e, uint32_t prot)
{
    pthread_mutex_lock(&g_reg_lock);
    vregion *r = wn_xmalloc(sizeof *r);
    r->start = s; r->end = e; r->prot = prot;
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

void *wn_virtual_alloc(void *hint, uint64_t size, uint32_t type, uint32_t prot)
{
    size = (size + 0xFFFF) & ~0xFFFFULL;   /* 64K granularity like Windows */
    int p = win_to_prot(prot);
    if (type & 0x1000 /* MEM_RESERVE */) {
        if (!(type & 0x1000 /* MEM_COMMIT */))
            p = PROT_NONE;
    }
    void *base = mmap(hint, size, p, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
                      -1, 0);
    if (base == MAP_FAILED)
        return NULL;
    region_add((uint64_t)(uintptr_t)base, (uint64_t)(uintptr_t)base + size, prot);
    return base;
}

int wn_virtual_free(void *addr, uint64_t size, uint32_t type)
{
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
                uint64_t s, e;
                char perms[8];
                if (sscanf(line, "%lx-%lx %4s", &s, &e, perms) == 3 && s <= a && e > a) {
                    old = 0;
                    if (perms[0] == 'r') old |= 0x02;
                    if (perms[1] == 'w') old |= 0x04;
                    if (perms[2] == 'x') old |= 0x10;
                    if (!old) old = 0x01;
                    found = 1;
                    break;
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
                   (uint64_t)(uintptr_t)addr + size, newprot);
    return 1;
}

/* Fill MEMORY_BASIC_INFORMATION (x64 layout, 48 bytes):
 * Base@0, AllocationBase@8, AllocationProtect@16, RegionSize@24,
 * State@32, Protect@36, Type@40. */
int wn_virtual_query(void *addr, void *mbi)
{
    uint64_t *q = mbi;
    memset(q, 0, 48);
    uint64_t a = (uint64_t)(uintptr_t)addr;
    pthread_mutex_lock(&g_reg_lock);
    for (vregion *r = g_regions; r; r = r->next) {
        if (r->start <= a && r->end > a) {
            q[0] = r->start;                    /* BaseAddress */
            q[1] = r->start;                    /* AllocationBase */
            *(uint32_t *)&q[2] = r->prot;       /* AllocationProtect @16 */
            q[3] = r->end - r->start;           /* RegionSize @24 */
            *(uint32_t *)&q[4] = 0x1000;        /* State: MEM_COMMIT @32 */
            *(uint32_t *)((uint8_t *)&q[4] + 4) = r->prot;  /* Protect @36 */
            *(uint32_t *)&q[5] = 0x20000;       /* Type: MEM_PRIVATE @40 */
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
        uint64_t s, e;
        char perms[8];
        if (sscanf(line, "%lx-%lx %4s", &s, &e, perms) != 3)
            continue;
        if (s <= a && e > a) {
            uint32_t p = 0;
            if (perms[0] == 'r') p |= 0x02;
            if (perms[1] == 'w') p |= 0x04;
            if (perms[2] == 'x') p |= 0x10;
            if (!p) p = 0x01;
            q[0] = s;
            q[1] = s;
            *(uint32_t *)&q[2] = p;
            q[3] = e - s;
            *(uint32_t *)&q[4] = (perms[0] == '-' && perms[1] == '-') ? 0x10000 /* MEM_FREE */ : 0x1000;
            *(uint32_t *)((uint8_t *)&q[4] + 4) = p;
            *(uint32_t *)&q[5] = 0x20000;
            ok = 1;
            break;
        }
    }
    fclose(f);
    return ok;
}
