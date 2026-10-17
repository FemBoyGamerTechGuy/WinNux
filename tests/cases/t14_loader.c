/* t14_loader — DLL resolution semantics: no-extension LoadLibrary,
 * case-insensitive full-path loads, system32 placeholder presence,
 * optional-DLL failure = ERROR_MOD_NOT_FOUND, missing proc =
 * ERROR_PROC_NOT_FOUND, and GetWindowsDirectory shapes. */
#include <windows.h>
#include <stdio.h>
#include <string.h>

static int fails = 0;

static void check(int cond, const char *what)
{
    printf("%s: %s\n", cond ? "ok" : "FAIL", what);
    if (!cond) fails++;
}

int main(void)
{
    /* 1. No extension: Windows appends .dll. */
    HMODULE k = LoadLibraryA("kernel32");
    check(k != NULL, "LoadLibraryA(\"kernel32\")");
    FARPROC beep = GetProcAddress(k, "Beep");
    check(beep != NULL, "kernel32!Beep by bare-module handle");

    /* 2. Case-insensitive full system32 path (PuTTY's pattern). */
    char sysdir[MAX_PATH];
    UINT n = GetSystemDirectoryA(sysdir, sizeof sysdir);
    check(n > 0 && n < sizeof sysdir, "GetSystemDirectoryA");
    char path[MAX_PATH];
    _snprintf(path, sizeof path, "%s\\IMM32.DLL", sysdir);
    HMODULE imm = LoadLibraryA(path);
    check(imm != NULL, "LoadLibraryA(system32\\IMM32.DLL) case-insensitive");

    /* 3. The placeholder file really exists on disk. */
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(path, &fd);
    check(h != INVALID_HANDLE_VALUE, "FindFirstFileA(system32\\IMM32.DLL)");
    if (h != INVALID_HANDLE_VALUE)
        FindClose(h);

    /* 4. Optional DLL missing -> clean failure + ERROR_MOD_NOT_FOUND(126). */
    SetLastError(0);
    HMODULE nope = LoadLibraryA("winnux-missing-test.dll");
    check(nope == NULL, "LoadLibraryA(\"winnux-missing-test.dll\") fails");
    check(GetLastError() == ERROR_MOD_NOT_FOUND,
          "GetLastError() == ERROR_MOD_NOT_FOUND");

    /* 5. Missing proc -> ERROR_PROC_NOT_FOUND(127). */
    SetLastError(0);
    FARPROC np = GetProcAddress(k, "DefinitelyNotARealExport");
    check(np == NULL, "GetProcAddress missing fails");
    check(GetLastError() == ERROR_PROC_NOT_FOUND,
          "GetLastError() == ERROR_PROC_NOT_FOUND");

    /* 6. GetModuleHandle with no extension. */
    HMODULE k2 = GetModuleHandleA("KERNEL32");
    check(k2 != NULL, "GetModuleHandleA(\"KERNEL32\")");
    check(k2 == k, "module identity across case");

    /* 7. GetWindowsDirectory + tree shape. */
    char windir[MAX_PATH];
    n = GetWindowsDirectoryA(windir, sizeof windir);
    check(n > 0, "GetWindowsDirectoryA");
    _snprintf(path, sizeof path, "%s\\system32\\kernel32.dll", windir);
    DWORD attr = GetFileAttributesA(path);
    check(attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY),
          "kernel32.dll file exists via windows dir path");

    printf("t14 loader: %s (%d failures)\n", fails ? "FAIL" : "PASS", fails);
    return fails ? 1 : 0;
}
