/* t01: console output via raw WriteFile — no CRT stdio involved. */
#include <windows.h>
int main(void)
{
    DWORD w = 0;
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    WriteFile(h, "T01 WriteFile OK\n", 17, &w, NULL);
    WriteConsoleA(h, "T01 WriteConsoleA OK\n", 21, &w, NULL);
    return (w >= 21 && w <= 22) ? 0 : 1;
}
