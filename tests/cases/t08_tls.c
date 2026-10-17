/* t08: compiler-native __thread TLS + TlsAlloc API across threads. */
#include <windows.h>
#include <stdio.h>
static __thread int per_thread = 41;
static DWORD slot;
static DWORD WINAPI worker(void *p)
{
    per_thread++;                       /* 42 in each thread */
    TlsSetValue(slot, (void *)(uintptr_t)(0x1000 + (int)(uintptr_t)p));
    Sleep(50);
    if (TlsGetValue(slot) != (void *)(uintptr_t)(0x1000 + (int)(uintptr_t)p)) {
        puts("T08 FAIL tls slot in thread"); return 1;
    }
    return (DWORD)per_thread;
}
int main(void)
{
    slot = TlsAlloc();
    if (slot == TLS_OUT_OF_INDEXES) { puts("T08 FAIL alloc"); return 1; }
    per_thread++;                       /* 42 in main */
    HANDLE th[2];
    for (int i = 0; i < 2; i++)
        th[i] = CreateThread(NULL, 0, worker, (void *)(uintptr_t)i, 0, NULL);
    DWORD c0, c1;
    WaitForSingleObject(th[0], 2000); GetExitCodeThread(th[0], &c0); CloseHandle(th[0]);
    WaitForSingleObject(th[1], 2000); GetExitCodeThread(th[1], &c1); CloseHandle(th[1]);
    printf("T08 main=%d t0=%lu t1=%lu (want 42,42,42)\n",
           per_thread, (unsigned long)c0, (unsigned long)c1);
    if (per_thread != 42 || c0 != 42 || c1 != 42) { puts("T08 FAIL values"); return 2; }
    if (!TlsFree(slot)) { puts("T08 FAIL free"); return 3; }
    puts("T08 TLS OK");
    return 0;
}
