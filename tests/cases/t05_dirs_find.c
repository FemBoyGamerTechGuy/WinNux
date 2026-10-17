/* t05: directories + FindFirstFile/FindNextFile. */
#include <windows.h>
#include <stdio.h>
#include <string.h>
int main(void)
{
    if (!CreateDirectoryA("t05_dir", NULL) &&
        GetLastError() != ERROR_ALREADY_EXISTS) { puts("T05 FAIL mkdir"); return 1; }
    HANDLE h = CreateFileA("t05_dir\\alpha.txt", GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, 0, NULL);
    DWORD w; WriteFile(h, "x", 1, &w, NULL); CloseHandle(h);
    h = CreateFileA("t05_dir\\BETA.txt", GENERIC_WRITE, 0, NULL,
                    CREATE_ALWAYS, 0, NULL);
    WriteFile(h, "y", 1, &w, NULL); CloseHandle(h);

    WIN32_FIND_DATAA fd;
    HANDLE f = FindFirstFileA("t05_dir\\*.txt", &fd);
    if (f == INVALID_HANDLE_VALUE) { puts("T05 FAIL findfirst"); return 2; }
    int n = 0, alpha = 0, beta = 0;
    do {
        n++;
        if (!strcmp(fd.cFileName, "alpha.txt")) alpha = 1;
        if (!strcmp(fd.cFileName, "BETA.txt")) beta = 1;
    } while (FindNextFileA(f, &fd));
    FindClose(f);
    printf("T05 found=%d alpha=%d beta=%d (dots counted, Windows-style)\n", n, alpha, beta);
    if (n != 4 || !alpha || !beta) { puts("T05 FAIL contents"); return 3; }

    DeleteFileA("t05_dir\\alpha.txt");
    DeleteFileA("t05_dir\\BETA.txt");
    if (!RemoveDirectoryA("t05_dir")) { puts("T05 FAIL rmdir"); return 4; }
    puts("T05 DIRS OK");
    return 0;
}
