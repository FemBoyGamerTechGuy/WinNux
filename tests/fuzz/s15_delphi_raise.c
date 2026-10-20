/* Synthetic Delphi-2-era raise (throwaway verification, not a suite case):
 * crafts the Exception-object shape the Inno engine raises and calls
 * RaiseException(0x0EEDFACE, 0, 3, [site, obj, 0]) with NO guest handler.
 * The new crash-report line must decode class + message from the object:
 *   [obj+0]=VMT (class shortstring at vmt-$0C)  [obj+4]=FMessage
 *   FMessage = longstring (length DWORD at ptr-4, chars at ptr). */
#include <windows.h>
#include <string.h>

static const char msg[] = "list item and state item count mismatch";

int main(void)
{
    /* All decoy structures must sit BELOW 4GB: a real 0xEEDFACE raise
     * comes from a 32-bit Delphi engine, and the decoder's DWORD reads
     * model exactly that memory space. */
    BYTE *lo = (BYTE *)VirtualAlloc((LPVOID)0x20000000, 4096,
                                    MEM_COMMIT | MEM_RESERVE,
                                    PAGE_READWRITE);
    if (!lo)
        return 2;

    BYTE *vmt = lo + 0x100 + 0x40;    /* [vmt-0x40, vmt) all readable */
    BYTE *cls = vmt - 0x0C;           /* canonical vmtClassName slot */
    cls[0] = 10;                      /* shortstring length */
    memcpy(cls + 1, "ETestError", 10);

    BYTE *msgstr = lo + 0x200 + 8;
    *(DWORD *)(msgstr - 4) = (DWORD)sizeof msg - 1;    /* len at msg-4 */
    memcpy(msgstr, msg, sizeof msg - 1);

    BYTE *obj = lo + 0x300;
    *(DWORD *)(obj + 0) = (DWORD)(uintptr_t)vmt;
    *(DWORD *)(obj + 4) = (DWORD)(uintptr_t)msgstr;

    ULONG_PTR info[3];
    info[0] = (ULONG_PTR)0x41414141;  /* raise site (never probed: obj wins) */
    info[1] = (ULONG_PTR)obj;
    info[2] = 0;
    RaiseException(0x0EEDFACE, 0, 3, info);
    return 0;   /* not reached if unhandled */
}
