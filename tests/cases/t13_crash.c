/* t13: guest crash handling — a NULL dereference must produce a
 * Windows-style unhandled-exception crash report on stderr (module+rva,
 * registers, access type) and exit with the exception code. NOTE: POSIX
 * truncates exit codes to 8 bits, so 0xC0000005 surfaces as 5 — the same
 * limitation Wine has on Linux; the full code appears in the report. */
#include <stdio.h>
int main(void)
{
    volatile int *p = (volatile int *)0;
    puts("T13 before crash");
    *p = 42;                        /* access violation */
    puts("T13 UNREACHABLE");
    return 0;
}
