/* raise32.c — native-i386 RaiseException register-capture probe.
 *
 * Session-17's naked gate in k32_RaiseException snapshots the GUEST's
 * registers with pusha before any C prologue runs; this probe proves the
 * snapshot reaches the crash report. Every general-purpose register is
 * loaded with a distinctive constant right before RaiseException (i386
 * stdcall passes args on the stack, so EAX..EDI are untouched between the
 * inline asm and the call), and the report must print them back.
 *
 * Build (needs the i686 mingw from toolchain/root — scripts/setup_root32
 * era; run32.sh documents the apt-get download line):
 *   i686-w64-mingw32-gcc-posix -O1 -fno-omit-frame-pointer \
 *       -o raise32.exe scripts/dev/raise32.c
 * Run:
 *   sh scripts/dev/run32.sh raise32.exe   →  expect
 *   ===== unhandled exception DELPHI_EXCEPTION (0x0EEDFACE) ...
 *     RAX=00000000dead0001 ... RBX=00000000feed0002 ...
 *     RSI=00000000aaaa0005 RDI=00000000bbbb0006   and an EBP backtrace.
 */
#include <windows.h>
#include <stdio.h>

__attribute__((noinline)) static void do_raise(void)
{
    RaiseException(0x0EEDFACE, 0, 0, NULL);
}

int main(void)
{
    puts("raise32: loading registers, then raising 0xEEDFACE");
    fflush(stdout);
    __asm__ volatile(
        "mov $0xdead0001, %%eax\n\t"
        "mov $0xfeed0002, %%ebx\n\t"
        "mov $0x12340003, %%ecx\n\t"
        "mov $0x56780004, %%edx\n\t"
        "mov $0xaaaa0005, %%esi\n\t"
        "mov $0xbbbb0006, %%edi\n\t"
        :
        :
        : "eax", "ebx", "ecx", "edx", "esi", "edi", "memory");
    do_raise();
    puts("raise32: NOT REACHED (raise must not return)");
    return 0;
}
