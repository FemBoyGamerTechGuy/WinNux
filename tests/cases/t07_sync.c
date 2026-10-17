/* t07: events (auto/manual), semaphores, WaitForMultipleObjects, mutex. */
#include <windows.h>
#include <stdio.h>
static HANDLE go;
static HANDLE done_ev;
static volatile LONG hits = 0;
static DWORD WINAPI worker(void *p)
{
    WaitForSingleObject(go, 1000);
    InterlockedIncrement(&hits);
    SetEvent(done_ev);
    return 0;
}
int main(void)
{
    go = CreateEventA(NULL, FALSE, FALSE, NULL);      /* auto reset */
    done_ev = CreateEventA(NULL, TRUE, FALSE, NULL);  /* manual reset */
    HANDLE th[3];
    for (int i = 0; i < 3; i++)
        th[i] = CreateThread(NULL, 0, worker, NULL, 0, NULL);

    SetEvent(go);
    Sleep(50);
    HANDLE hs[3] = { done_ev, th[0], th[1] };
    DWORD r = WaitForMultipleObjects(3, hs, FALSE, 1000);
    printf("T07 wfmo=%lu (any)\n", (unsigned long)r);
    if (r != WAIT_OBJECT_0) { puts("T07 FAIL wfmo"); return 1; }

    /* semaphore: 2 slots, 3 acquires => one timeout */
    HANDLE sem = CreateSemaphoreA(NULL, 2, 2, NULL);
    DWORD a = WaitForSingleObject(sem, 0);
    DWORD b = WaitForSingleObject(sem, 0);
    DWORD c = WaitForSingleObject(sem, 100);
    printf("T07 sem=%lu,%lu,%lu (want 0,0,258)\n",
           (unsigned long)a, (unsigned long)b, (unsigned long)c);
    LONG prev = 0;
    ReleaseSemaphore(sem, 1, &prev);
    DWORD d = WaitForSingleObject(sem, 0);
    printf("T07 sem-after=%lu (want 0)\n", (unsigned long)d);
    (void)prev;

    /* recursive mutex */
    HANDLE m = CreateMutexA(NULL, TRUE, NULL);
    int ok1 = (WaitForSingleObject(m, 0) == WAIT_OBJECT_0);
    ReleaseMutex(m); ReleaseMutex(m);
    int ok2 = (ReleaseMutex(m) == 0);   /* over-release must fail */
    printf("T07 mutex recursive=%d overrelease-fails=%d\n", ok1, ok2);

    for (int i = 0; i < 3; i++) { WaitForSingleObject(th[i], 1000); CloseHandle(th[i]); }
    printf("T07 hits=%ld\n", (long)hits);
    if (hits != 3) { puts("T07 FAIL hits"); return 2; }
    if (a != 0 || b != 0 || c != WAIT_TIMEOUT || d != 0) { puts("T07 FAIL sem"); return 3; }
    if (!ok1 || !ok2) { puts("T07 FAIL mutex"); return 4; }
    puts("T07 SYNC OK");
    return 0;
}
