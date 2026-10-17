/* t06: CreateThread + WaitForSingleObject + exit codes + critical sections. */
#include <windows.h>
#include <stdio.h>
static CRITICAL_SECTION cs;
static volatile LONG counter = 0;
static DWORD WINAPI worker(void *p)
{
    for (int i = 0; i < 1000; i++) {
        EnterCriticalSection(&cs);
        counter++;
        LeaveCriticalSection(&cs);
    }
    return (DWORD)(uintptr_t)p * 2;
}
int main(void)
{
    InitializeCriticalSection(&cs);
    HANDLE th[4];
    for (int i = 0; i < 4; i++)
        th[i] = CreateThread(NULL, 0, worker, (void *)(uintptr_t)(i + 10), 0, NULL);
    DWORD codes[4];
    for (int i = 0; i < 4; i++) {
        if (WaitForSingleObject(th[i], 5000) != WAIT_OBJECT_0) {
            puts("T06 FAIL wait"); return 1;
        }
        if (!GetExitCodeThread(th[i], &codes[i])) { puts("T06 FAIL code"); return 2; }
        CloseHandle(th[i]);
    }
    printf("T06 counter=%ld (want 4000)\n", (long)counter);
    printf("T06 codes=%lu,%lu,%lu,%lu\n", codes[0], codes[1], codes[2], codes[3]);
    DeleteCriticalSection(&cs);
    if (counter != 4000) { puts("T06 FAIL count"); return 3; }
    if (codes[0] != 20 || codes[3] != 26) { puts("T06 FAIL codes"); return 4; }
    puts("T06 THREADS OK");
    return 0;
}
