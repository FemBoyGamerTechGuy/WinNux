/* canary32.c — dev tool: interpose __stack_chk_fail in winnux32 runs.
 *
 * When a stack canary trips inside the WinNux host code, glibc just prints
 * "*** stack smashing detected ***" and aborts — no backtrace. Build this
 * as a 32-bit shared object and LD_PRELOAD it under qemu-i386:
 *
 *   cc -m32 ... -shared -fPIC -static-libgcc -o canary32.so
 *   LD_PRELOAD=$PWD/canary32.so qemu-i386 -L <root32> bin/winnux32 run app.exe
 *
 * Level-0 return address needs no frame pointers: on entry the return
 * address sits at [ESP], pointing INSIDE the function whose canary failed.
 * Resolve it with: addr2line -e bin/winnux32 <exe_base_offset>.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/syscall.h>

static void dputc(int c, int fd);

void __stack_chk_fail(void)
{
    /* -O0 frame-pointer build: [ebp+4] = return address into the smashed
     * caller; the caller's own frame sits directly above. Dump it raw so
     * the overflowing bytes identify the writer. */
    void **ebp = (void **)__builtin_frame_address(0);
    void *ra = ebp[1];
    Dl_info di;
    unsigned int expect = 0;
    __asm__ volatile ("movw %%gs:0x14, %%ax\n\t" : "=a"(expect) ::);
    if (dladdr(ra, &di) && di.dli_fbase) {
        dprintf(2, "\n=== CANARY: smash in %s + 0x%llx (retaddr %p) ===\n",
                di.dli_fname ? di.dli_fname : "?",
                (unsigned long long)((char *)ra - (char *)di.dli_fbase),
                ra);
        if (di.dli_sname)
            dprintf(2, "=== CANARY: near symbol %s + 0x%lx ===\n",
                    di.dli_sname,
                    (unsigned long)((char *)ra - (char *)di.dli_saddr));
    } else {
        dprintf(2, "\n=== CANARY: retaddr %p (dladdr failed) ===\n", ra);
    }
    dprintf(2, "=== expected canary low32: 0x%08x, tid %ld ===\n",
            expect, (long)syscall(SYS_gettid));
    unsigned char *r = (unsigned char *)&ebp[1];
    for (int row = 0; row < 8; row++) {
        unsigned char *q = r + row * 16;
        dprintf(2, "+0x%02x: %02x %02x %02x %02x %02x %02x %02x %02x "
                  "%02x %02x %02x %02x %02x %02x %02x %02x  ",
                row * 16, q[0], q[1], q[2], q[3], q[4], q[5], q[6], q[7],
                q[8], q[9], q[10], q[11], q[12], q[13], q[14], q[15]);
        for (int i = 0; i < 16; i++)
            dputc(q[i] >= 32 && q[i] < 127 ? q[i] : '.', 2);
        dprintf(2, "\n");
    }
    _exit(70);
}

static void dputc(int c, int fd)
{
    char b = (char)c;
    if (write(fd, &b, 1) < 0) { /* ignore */ }
}

void __stack_chk_fail_local(void)
{
    __stack_chk_fail();
}
