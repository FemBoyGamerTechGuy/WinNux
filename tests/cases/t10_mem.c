/* t10: VirtualAlloc/commit/protect/query + HeapAlloc loops. */
#include <windows.h>
#include <stdio.h>
#include <string.h>
int main(void)
{
    /* Reserve 16MB, commit 64KB. */
    void *p = VirtualAlloc(NULL, 16 * 1024 * 1024,
                           MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!p) { puts("T10 FAIL valloc"); return 1; }
    memset(p, 0xAB, 65536);
    if (((unsigned char *)p)[100] != 0xAB || ((unsigned char *)p)[65535] != 0xAB) {
        puts("T10 FAIL write"); return 2;
    }
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T q = VirtualQuery(p, &mbi, sizeof mbi);
    printf("T10 query state=%lx prot=%lx size=%llu\n",
           (unsigned long)mbi.State, (unsigned long)mbi.Protect,
           (unsigned long long)mbi.RegionSize);
    if (q == 0 || mbi.State != MEM_COMMIT) { puts("T10 FAIL state"); return 3; }

    DWORD old = 0;
    if (!VirtualProtect(p, 4096, PAGE_READONLY, &old)) { puts("T10 FAIL protect"); return 4; }
    printf("T10 old-prot=%lx (want 4)\n", (unsigned long)old);
    if (!VirtualProtect(p, 4096, PAGE_READWRITE, &old)) { puts("T10 FAIL restore"); return 5; }

    if (!VirtualFree(p, 0, MEM_RELEASE)) { puts("T10 FAIL vfree"); return 6; }

    /* Heap: 10k small allocations. */
    HANDLE heap = GetProcessHeap();
    int sum = 0;
    for (int i = 0; i < 10000; i++) {
        int *v = (int *)HeapAlloc(heap, 0, sizeof(int) * 4);
        if (!v) { puts("T10 FAIL heap"); return 7; }
        v[0] = i; v[3] = i;
        sum += v[0] + v[3];
        HeapFree(heap, 0, v);
    }
    printf("T10 heap sum=%d (want 99990000)\n", sum);
    if (sum != 99990000) { puts("T10 FAIL heap sum"); return 8; }
    puts("T10 MEM OK");
    return 0;
}
