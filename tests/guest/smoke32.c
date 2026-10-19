/* t-smoke32: minimal PE32 exe (no CRT) exercising the wow64 basics:
 * ExitProcess, GetLastError, GetModuleHandleA, GetVersion, GetTickCount,
 * plus raw fs:[0x18]/[0x20]/[0x34] TEB access (fault-emulated).
 * Exit code 0 = all checks passed. */
__attribute__((dllimport)) void __stdcall ExitProcess(unsigned);
__attribute__((dllimport)) unsigned __stdcall GetLastError(void);
__attribute__((dllimport)) void * __stdcall GetModuleHandleA(const char *);
__attribute__((dllimport)) unsigned __stdcall GetVersion(void);
__attribute__((dllimport)) unsigned __stdcall GetTickCount(void);
__attribute__((dllimport)) void __stdcall Sleep(unsigned);
__attribute__((dllimport)) void * __stdcall GetCommandLineA(void);
__attribute__((dllimport)) void * __stdcall HeapCreate(unsigned, unsigned, unsigned);
__attribute__((dllimport)) void * __stdcall HeapAlloc(void *, unsigned, unsigned);
__attribute__((dllimport)) void __stdcall HeapFree(void *, unsigned, void *);
__attribute__((dllimport)) unsigned __stdcall HeapDestroy(void *);

static unsigned teb_self(void)
{
    unsigned r;
    __asm__ volatile("mov %%fs:0x18, %0" : "=r"(r));
    return r;
}
static unsigned teb_pid(void)
{
    unsigned r;
    __asm__ volatile("mov %%fs:0x20, %0" : "=r"(r));
    return r;
}
static void teb_lasterr(unsigned v)
{
    __asm__ volatile("mov %0, %%fs:0x34" :: "r"(v));
}

void __stdcall smoke_entry(void)
{
    unsigned score = 0;

    if (GetModuleHandleA("kernel32.dll"))
        score |= 1;

    if ((GetVersion() & 0x80000000u) == 0)
        score |= 2;

    unsigned t0 = GetTickCount();
    Sleep(20);
    if (GetTickCount() >= t0)
        score |= 4;

    if (GetLastError() == 0)
        score |= 8;
    teb_lasterr(1234);
    if (GetLastError() == 1234)
        score |= 16;

    unsigned self = teb_self();
    if (self > 0x10000 && self < 0xF0000000u)
        score |= 32;

    if (teb_pid() != 0)
        score |= 64;

    const char *cl = (const char *)GetCommandLineA();
    if (cl && cl[0])
        score |= 128;

    {
        void *h = HeapCreate(0, 0, 0);
        void *p = h ? HeapAlloc(h, 0, 100) : 0;
        if (p) {
            *(unsigned *)p = 0x55667788;
            score |= 256;
        }
        if (p) HeapFree(h, 0, p);
        if (h) HeapDestroy(h);
    }

    ExitProcess(score == 511 ? 0 : 100 + (score & 0xFF));
}
