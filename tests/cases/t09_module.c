/* t09: module APIs: GetModuleHandle, LoadLibrary, GetProcAddress, filename. */
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
int main(void)
{
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    if (!k32) { puts("T09 FAIL handle"); return 1; }
    FARPROC gtc = GetProcAddress(k32, "GetTickCount");
    if (!gtc) { puts("T09 FAIL proc"); return 2; }
    DWORD (WINAPI *pGetTickCount)(void) = (void *)gtc;
    DWORD t = pGetTickCount();
    printf("T09 tick=%lu (>0)\n", (unsigned long)t);

    HMODULE msvcrt = LoadLibraryA("msvcrt.dll");
    if (!msvcrt) { puts("T09 FAIL loadlibrary"); return 3; }
    FARPROC slen = GetProcAddress(msvcrt, "strlen");
    int64_t (WINAPI *pstrlen)(const char *) = (void *)slen;
    printf("T09 strlen=lld:%lld\n", (long long)pstrlen("hello"));

    HMODULE exe = GetModuleHandleA(NULL);
    char path[300];
    DWORD n = GetModuleFileNameA(exe, path, sizeof path);
    printf("T09 self=%s (%lu chars)\n", path, (unsigned long)n);
    if (n == 0 || n >= sizeof path) { puts("T09 FAIL filename"); return 4; }
    puts("T09 MODULE OK");
    return 0;
}
