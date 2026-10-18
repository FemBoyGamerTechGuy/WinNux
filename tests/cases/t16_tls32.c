/* t16_tls32.c — static TLS (PE TLS directory) end-to-end, both arches.
 *
 * __thread variables make mingw emit a .tls section + a TLS directory whose
 * AddressOfIndex the loader must fill; every thread must receive its own
 * template-initialized block. Delphi RTLs (LuaForWindows/Inno Setup) read
 * fs:[0x2C][*(DWORD*)index_va] directly with NO fallback — a missing link
 * means a NULL block and a guest AV on the first threadvar access
 * (field case: write to [block+4] at exe+0x4325).
 *
 * Also exercises the per-thread template COPY semantics: the worker's
 * counter starts from the template value (7), not from main's mutations.
 */
#include <windows.h>
#include <stdio.h>

__thread int    tv_counter = 7;
__thread char   tv_buf[16] = "thread";
__thread DWORD  tv_tid = 0;

static void show(const char *who)
{
    tv_tid = GetCurrentThreadId();
    printf("%s: counter=%d buf=%s tid=%lu\n", who, tv_counter, tv_buf,
           (unsigned long)tv_tid);
    fflush(stdout);
}

static DWORD WINAPI worker(void *arg)
{
    (void)arg;
    show("worker");
    tv_counter += 100;
    return (DWORD)tv_counter;
}

int main(void)
{
    show("main");
    tv_counter += 1;                       /* main's copy only */
    HANDLE h = CreateThread(NULL, 0, worker, NULL, 0, NULL);
    if (!h) {
        printf("CreateThread failed\n");
        return 2;
    }
    WaitForSingleObject(h, INFINITE);
    DWORD code = 0;
    GetExitCodeThread(h, &code);
    printf("worker exit=%lu main counter=%d\n", (unsigned long)code,
           tv_counter);
    fflush(stdout);
    /* main=8 (7+1), worker=107 (fresh template 7 + 100) */
    return (tv_counter == 8 && code == 107) ? 0 : 1;
}
