#include <windows.h>
/* t03: argc/argv/envp from __getmainargs path + env APIs. */
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv, char **envp)
{
    printf("T03 argc=%d\n", argc);
    for (int i = 0; i < argc; i++)
        printf("T03 argv[%d]=%s\n", i, argv[i]);
    char v[256];
    DWORD n = GetEnvironmentVariableA("SystemRoot", v, sizeof v);
    printf("T03 SystemRoot=%s n=%lu\n", v, (unsigned long)n);
    char cwd[256];
    GetCurrentDirectoryA(sizeof cwd, cwd);
    printf("T03 cwd=%s\n", cwd);
    printf("T03 cmdline=%s\n", GetCommandLineA());
    (void)envp;
    return argc;
}
