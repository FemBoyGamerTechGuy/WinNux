/* t04: file create/write/read/delete + attributes + size + seek. */
#include <windows.h>
#include <string.h>
#include <stdio.h>
int main(void)
{
    HANDLE h = CreateFileA("t04_data.txt", GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) { puts("T04 FAIL create"); return 1; }
    const char *msg = "T04 file roundtrip payload\n";
    DWORD w = 0;
    if (!WriteFile(h, msg, (DWORD)strlen(msg), &w, NULL) || w != strlen(msg)) {
        puts("T04 FAIL write"); return 2;
    }
    CloseHandle(h);

    h = CreateFileA("T04_DATA.TXT", GENERIC_READ, FILE_SHARE_READ, NULL,
                    OPEN_EXISTING, 0, NULL);   /* case-insensitive open */
    if (h == INVALID_HANDLE_VALUE) { puts("T04 FAIL reopen"); return 3; }
    LARGE_INTEGER sz;
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart != (LONGLONG)strlen(msg)) {
        puts("T04 FAIL size"); return 4;
    }
    char buf[128] = { 0 };
    DWORD r = 0;
    if (!ReadFile(h, buf, sizeof buf - 1, &r, NULL) || strcmp(buf, msg) != 0) {
        puts("T04 FAIL read"); return 5;
    }
    CloseHandle(h);

    if (!DeleteFileA("t04_data.txt")) { puts("T04 FAIL delete"); return 6; }
    if (GetFileAttributesA("t04_data.txt") != INVALID_FILE_ATTRIBUTES) {
        puts("T04 FAIL gone"); return 7;
    }
    puts("T04 FILES OK");
    return 0;
}
