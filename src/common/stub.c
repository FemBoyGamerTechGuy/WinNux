/* stub.c — executable trampolines for unimplemented imports.
 *
 * Stub code (guest calls it like any ms_abi function):
 *   41 BA <imm32>     mov r10d, info       ; r10/r11 volatile in MS ABI
 *   48 B8 <imm64>     mov rax, trampoline
 *   FF E0             jmp rax
 *
 * The trampoline preserves the guest argument registers (rcx,rdx,r8,r9),
 * captures the guest return address for logging, calls the C implementation,
 * and returns 0 (failure by contract; last error 120 is set by the logger).
 */
#include "wn_stub.h"
#include "wn_log.h"
#include "wn_util.h"
#include "wn_types.h"
#include "wn_module.h"
#include "wn_process.h"

#include <sys/mman.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <stdlib.h>

#define WN_STUB_AREA  (256u * 1024u)   /* 256 KiB => ~10k stubs */
#define WN_STUB_SLOT  32u

typedef struct wn_stub_info {
    uint32_t    hits;      /* offset 0                            */
    uint16_t    pop;       /* offset 4: i386 trampoline reads it  */
    uint8_t     pop_known; /* i386: pop from the curated table    */
    const char *dll;
    const char *name;
} wn_stub_info;

/* The i386 trampoline hardcodes the pop offset; keep it honest. */
_Static_assert(__builtin_offsetof(wn_stub_info, pop) == 4,
               "wn_stub_info.pop must sit at offset 4 for the asm bridge");

static uint8_t *g_stub_region;
extern void wn_stub_entry_trampoline(void);

/* Stable per-entry storage: trampolines embed &info in their code, so the
 * info objects must never move (no realloc of the objects themselves). */
static wn_stub_info **g_infos;     /* index i <-> stub i */
static uint32_t g_info_count;

/* The impl is called by the raw-asm trampoline: ms_abi on x64 (the asm
 * builds the MS register+shadow layout), plain cdecl on i386 — where the
 * trampoline pushes 4-byte slots, so the impl MUST take 4-byte params
 * (the old uint64_t params read adjacent slot pairs as garbage). wn_abiword
 * is exactly the right width on both arches. */
#if defined(__x86_64__)
#define WN_STUBIMPL_DECL WN_API
#else
#define WN_STUBIMPL_DECL
#endif
WN_STUBIMPL_DECL void wn_stub_entry_impl(wn_abiword info_p, wn_abiword a1,
                                         wn_abiword a2, wn_abiword a3,
                                         wn_abiword a4, wn_abiword guest_ret);

/* MS-ABI assembly bridge (see file comment). */
#if defined(__x86_64__)
__asm__(
    ".text\n"
    ".globl wn_stub_entry_trampoline\n"
    ".type wn_stub_entry_trampoline, @function\n"
    "wn_stub_entry_trampoline:\n"
    "    subq  $0x38, %rsp\n"          /* align to 16 + shadow + 2 stack args */
    "    movq  %r9, 0x20(%rsp)\n"      /* C arg5  <- original guest r9   */
    "    movq  0x38(%rsp), %rax\n"     /* guest return address           */
    "    movq  %rax, 0x28(%rsp)\n"     /* C arg6  <- guest retaddr       */
    "    movq  %r8, %r9\n"             /* C arg4  <- original guest r8   */
    "    movq  %rdx, %r8\n"            /* C arg3  <- original guest rdx  */
    "    movq  %rcx, %rdx\n"           /* C arg2  <- original guest rcx  */
    "    movq  %r10, %rcx\n"           /* C arg1  <- info                */
    "    call  wn_stub_entry_impl\n"
    "    xorq  %rax, %rax\n"           /* return 0                      */
    "    addq  $0x38, %rsp\n"
    "    ret\n"
    ".size wn_stub_entry_trampoline, .-wn_stub_entry_trampoline\n"
);
#else
/* i386 bridge. At entry: [esp]=info (pushed by the stub code), [esp+4]=
 * guest return address, [esp+8..+20]=a1..a4. The impl decides and caches
 * the callee-pop byte count (Win32 i386 APIs are stdcall: the callee pops
 * its own argument frame; CRT functions are cdecl and the caller cleans).
 * The return sequence pops info->pop bytes after the return address, so
 * stdcall guests keep a balanced stack instead of the old leak that
 * shifted every subsequent pop/locals access. */
__asm__(
    ".text\n"
    ".globl wn_stub_entry_trampoline\n"
    ".type wn_stub_entry_trampoline, @function\n"
    "wn_stub_entry_trampoline:\n"
    "    pushl %ebx\n"                /* save guest ebx               */
    "    movl  4(%esp), %ebx\n"       /* ebx = info                   */
    "    pushl 8(%esp)\n"             /* arg6: guest ret addr         */
    "    pushl 28(%esp)\n"            /* arg5: a4                     */
    "    pushl 28(%esp)\n"            /* arg4: a3                     */
    "    pushl 28(%esp)\n"            /* arg3: a2                     */
    "    pushl 28(%esp)\n"            /* arg2: a1                     */
    "    pushl %ebx\n"                /* arg1: info                   */
    "    call  wn_stub_entry_impl\n"
    "    addl  $24, %esp\n"           /* drop the 6 arg pushes        */
    "    movzwl 4(%ebx), %ecx\n"      /* ecx = info->pop (offset 4)   */
    "    popl  %ebx\n"                /* restore guest ebx            */
    "    addl  $4, %esp\n"            /* drop info slot               */
    "    popl  %eax\n"                /* eax = return address         */
    "    addl  %ecx, %esp\n"          /* stdcall: drop the arg frame  */
    "    pushl %eax\n"
    "    xorl  %eax, %eax\n"          /* return 0                     */
    "    ret\n"
    ".size wn_stub_entry_trampoline, .-wn_stub_entry_trampoline\n"
);
#endif


/* --- i386 stdcall argument counts ----------------------------------------- */
/* Known stdcall parameter counts for frequently-missed exports. Shared by
 * the i386 trampoline (native winnux32) AND the in-process wow64 stub32
 * path: a missing stdcall import MUST still pop its arg frame, otherwise
 * every call skews the 32-bit guest stack (LuaForWindows installer:
 * InterlockedExchange stub returned cdecl -> +8 skew -> ret to garbage). */
static const struct { const char *dll, *name; uint8_t nargs; } g_stub_pop_table[] = {
    { "kernel32.dll", "SetDefaultDllDirectories", 1 },
    { "kernel32.dll", "SetDllDirectoryA", 1 },
    { "kernel32.dll", "SetDllDirectoryW", 1 },
    { "kernel32.dll", "GetUserDefaultLangID", 0 },
    { "kernel32.dll", "GetSystemDefaultLangID", 0 },
    { "kernel32.dll", "GetUserDefaultLCID", 0 },
    { "kernel32.dll", "GetSystemDefaultLCID", 0 },
    { "kernel32.dll", "GetLocaleInfoA", 4 },
    { "kernel32.dll", "GetLocaleInfoW", 4 },
    { "kernel32.dll", "GetFullPathNameA", 4 },
    { "kernel32.dll", "GetFullPathNameW", 4 },
    { "kernel32.dll", "InterlockedExchange", 2 },
    { "kernel32.dll", "InterlockedIncrement", 1 },
    { "kernel32.dll", "InterlockedDecrement", 1 },
    { "kernel32.dll", "InterlockedCompareExchange", 3 },
    { "kernel32.dll", "FormatMessageA", 7 },
    { "kernel32.dll", "FormatMessageW", 7 },
    { "kernel32.dll", "CreateProcessA", 10 },
    { "kernel32.dll", "CreateProcessW", 10 },
    { "kernel32.dll", "IsWow64Process", 2 },
    { "kernel32.dll", "QueryPerformanceCounter", 1 },
    { "kernel32.dll", "QueryPerformanceFrequency", 1 },
    { "kernel32.dll", "GetProcessAffinityMask", 3 },
    { "kernel32.dll", "GetExitCodeProcess", 2 },
    { "kernel32.dll", "SetThreadExecutionState", 1 },
    { "user32.dll", "LoadStringA", 4 },
    { "user32.dll", "LoadStringW", 4 },
    { "user32.dll", "CharPrevA", 2 },
    { "user32.dll", "CharNextA", 1 },
    { "user32.dll", "CallWindowProcA", 5 },
    { "user32.dll", "CallWindowProcW", 5 },
    { "user32.dll", "ExitWindowsEx", 2 },
    { "user32.dll", "MessageBeep", 1 },
    { "user32.dll", "SetProcessDPIAware", 0 },
    { "user32.dll", "IsProcessDPIAware", 0 },
    { "user32.dll", "GetSystemMetricsForDpi", 2 },
    { "oleaut32.dll", "VariantChangeTypeEx", 6 },
    { "oleaut32.dll", "VariantCopyInd", 2 },
    { "oleaut32.dll", "VariantInit", 1 },
    { "oleaut32.dll", "VariantClear", 1 },
    { "oleaut32.dll", "VariantCopy", 2 },
    { "oleaut32.dll", "SysAllocStringLen", 2 },
    { "oleaut32.dll", "SysStringLen", 1 },
    { "oleaut32.dll", "SysFreeString", 1 },
    { "advapi32.dll", "OpenProcessToken", 3 },
    { "advapi32.dll", "LookupPrivilegeValueA", 4 },
    { "advapi32.dll", "LookupPrivilegeValueW", 4 },
    { "advapi32.dll", "AdjustTokenPrivileges", 6 },
    { "advapi32.dll", "GetTokenInformation", 5 },
    /* Inno Setup (LuaForWindows installer) second-stage imports. */
    { "oleaut32.dll", "SafeArrayPutElement", 3 },
    { "oleaut32.dll", "SafeArrayCreate", 3 },
    { "advapi32.dll", "SetSecurityDescriptorDacl", 4 },
    { "advapi32.dll", "RegQueryInfoKeyA", 12 },
    { "advapi32.dll", "RegQueryInfoKeyW", 12 },
    { "advapi32.dll", "RegDeleteValueA", 2 },
    { "advapi32.dll", "RegDeleteValueW", 2 },
    { "advapi32.dll", "RegDeleteKeyA", 2 },
    { "advapi32.dll", "RegDeleteKeyW", 2 },
    { "advapi32.dll", "OpenThreadToken", 4 },
    { "advapi32.dll", "InitializeSecurityDescriptor", 2 },
    { "advapi32.dll", "FreeSid", 1 },
    { "advapi32.dll", "EqualSid", 2 },
    { "advapi32.dll", "AllocateAndInitializeSid", 11 },
    { "kernel32.dll", "WriteProfileStringA", 3 },
    { "kernel32.dll", "WriteProfileStringW", 3 },
    { "kernel32.dll", "WritePrivateProfileStringA", 3 },
    { "kernel32.dll", "WritePrivateProfileStringW", 3 },
    { "kernel32.dll", "TransactNamedPipe", 5 },
    { "kernel32.dll", "TerminateThread", 2 },
    { "kernel32.dll", "SetNamedPipeHandleState", 4 },
    { "kernel32.dll", "SetFileTime", 4 },
    { "kernel32.dll", "OpenProcess", 3 },
    { "kernel32.dll", "OpenMutexA", 3 },
    { "kernel32.dll", "OpenMutexW", 3 },
    { "kernel32.dll", "MoveFileExA", 3 },
    { "kernel32.dll", "MoveFileExW", 3 },
    { "kernel32.dll", "LocalFileTimeToFileTime", 2 },
    { "kernel32.dll", "FileTimeToLocalFileTime", 2 },
    { "kernel32.dll", "DeviceIoControl", 8 },
    { "kernel32.dll", "CreateNamedPipeA", 7 },
    { "kernel32.dll", "CreateNamedPipeW", 7 },
    { "kernel32.dll", "CompareStringA", 6 },
    { "kernel32.dll", "CompareStringW", 6 },
    { "kernel32.dll", "CompareFileTime", 2 },
    { "kernel32.dll", "SetVolumeLabelA", 2 },
    { "mpr.dll", "WNetGetConnectionA", 3 },
    { "mpr.dll", "WNetGetConnectionW", 3 },
    { "mpr.dll", "WNetAddConnection2A", 4 },
    { "mpr.dll", "WNetAddConnection2W", 4 },
    { "mpr.dll", "WNetCancelConnection2A", 3 },
    { "mpr.dll", "WNetCancelConnection2W", 3 },
    { "mpr.dll", "WNetOpenEnumA", 5 },
    { "mpr.dll", "WNetOpenEnumW", 5 },
    { "mpr.dll", "WNetCloseEnum", 1 },
    { "mpr.dll", "WNetEnumResourceA", 4 },
    /* Inno Setup 2nd-stage import batch (arities from mingw-w64
     * headers via scripts/dev/gen_stub_pops.py + MSDN). */
    { "gdi32.dll", "AddFontResourceA", 1 },
    { "user32.dll", "AdjustWindowRectEx", 4 },
    { "user32.dll", "AppendMenuA", 4 },
    { "gdi32.dll", "Arc", 9 },
    { "user32.dll", "BringWindowToTop", 1 },
    { "user32.dll", "CallNextHookEx", 4 },
    { "user32.dll", "CharLowerA", 1 },
    { "user32.dll", "CharLowerBuffA", 2 },
    { "user32.dll", "CharToOemBuffA", 3 },
    { "user32.dll", "CharUpperBuffA", 2 },
    { "user32.dll", "CheckMenuItem", 3 },
    { "gdi32.dll", "Chord", 9 },
    { "gdi32.dll", "CreateBitmap", 5 },
    { "gdi32.dll", "CreateBrushIndirect", 1 },
    { "gdi32.dll", "CreateCompatibleBitmap", 3 },
    { "gdi32.dll", "CreateDIBitmap", 6 },
    { "user32.dll", "CreateIcon", 7 },
    { "user32.dll", "CreateMenu", 0 },
    { "gdi32.dll", "CreatePalette", 1 },
    { "gdi32.dll", "CreatePenIndirect", 1 },
    { "user32.dll", "CreatePopupMenu", 0 },
    { "gdi32.dll", "CreateRectRgn", 4 },
    { "user32.dll", "DefFrameProcA", 5 },
    { "user32.dll", "DefMDIChildProcA", 4 },
    { "user32.dll", "DeleteMenu", 3 },
    { "user32.dll", "DestroyCursor", 1 },
    { "user32.dll", "DestroyMenu", 1 },
    { "user32.dll", "DrawFocusRect", 2 },
    { "user32.dll", "DrawFrameControl", 4 },
    { "user32.dll", "DrawIcon", 4 },
    { "user32.dll", "DrawIconEx", 9 },
    { "user32.dll", "DrawMenuBar", 1 },
    { "gdi32.dll", "Ellipse", 5 },
    { "user32.dll", "EnableMenuItem", 3 },
    { "gdi32.dll", "EnumFontsA", 4 },
    { "user32.dll", "EnumThreadWindows", 3 },
    { "user32.dll", "EnumWindows", 2 },
    { "user32.dll", "EqualRect", 2 },
    { "gdi32.dll", "ExcludeClipRect", 5 },
    { "gdi32.dll", "ExtFloodFill", 5 },
    { "user32.dll", "FrameRect", 3 },
    { "kernel32.dll", "FreeResource", 1 },
    { "gdi32.dll", "GetBitmapBits", 3 },
    { "user32.dll", "GetClassInfoA", 3 },
    { "user32.dll", "GetClassInfoW", 3 },
    { "gdi32.dll", "GetClipBox", 2 },
    { "kernel32.dll", "GetComputerNameA", 2 },
    { "gdi32.dll", "GetCurrentPositionEx", 2 },
    { "user32.dll", "GetCursor", 0 },
    { "user32.dll", "GetDCEx", 3 },
    { "gdi32.dll", "GetDIBits", 7 },
    { "kernel32.dll", "GetDiskFreeSpaceA", 5 },
    { "user32.dll", "GetIconInfo", 2 },
    { "user32.dll", "GetKeyNameTextA", 3 },
    { "user32.dll", "GetKeyState", 1 },
    { "user32.dll", "GetLastActivePopup", 1 },
    { "kernel32.dll", "GetLogicalDrives", 0 },
    { "user32.dll", "GetMenu", 1 },
    { "user32.dll", "GetMenuItemCount", 1 },
    { "user32.dll", "GetMenuState", 3 },
    { "user32.dll", "GetMenuStringA", 5 },
    { "user32.dll", "GetMessagePos", 0 },
    { "gdi32.dll", "GetObjectA", 3 },
    { "gdi32.dll", "GetPaletteEntries", 4 },
    { "gdi32.dll", "GetPixel", 3 },
    { "kernel32.dll", "GetPrivateProfileStringA", 6 },
    { "kernel32.dll", "GetProfileStringA", 5 },
    { "user32.dll", "GetPropA", 2 },
    { "user32.dll", "GetScrollPos", 2 },
    { "kernel32.dll", "GetShortPathNameA", 3 },
    { "user32.dll", "GetSubMenu", 2 },
    { "user32.dll", "GetSystemMenu", 2 },
    { "gdi32.dll", "GetSystemPaletteEntries", 4 },
    { "gdi32.dll", "GetTextExtentPointA", 4 },
    { "user32.dll", "GetWindow", 2 },
    { "gdi32.dll", "GetWindowOrgEx", 2 },
    { "user32.dll", "GetWindowRgn", 2 },
    { "user32.dll", "GetWindowThreadProcessId", 2 },
    { "kernel32.dll", "GlobalAddAtomA", 1 },
    { "kernel32.dll", "GlobalDeleteAtom", 1 },
    { "kernel32.dll", "GlobalHandle", 1 },
    { "kernel32.dll", "GlobalReAlloc", 3 },
    { "user32.dll", "InflateRect", 3 },
    { "user32.dll", "InsertMenuA", 5 },
    { "user32.dll", "InsertMenuItemA", 4 },
    { "gdi32.dll", "IntersectClipRect", 5 },
    { "user32.dll", "IntersectRect", 3 },
    { "kernel32.dll", "IsBadWritePtr", 2 },
    { "user32.dll", "IsRectEmpty", 1 },
    { "user32.dll", "IsWindowVisible", 1 },
    { "gdi32.dll", "LineDDA", 6 },
    { "user32.dll", "LoadBitmapA", 2 },
    { "user32.dll", "MapVirtualKeyA", 2 },
    { "user32.dll", "MapWindowPoints", 4 },
    { "user32.dll", "OemToCharA", 2 },
    { "user32.dll", "OemToCharBuffA", 3 },
    { "gdi32.dll", "PatBlt", 6 },
    { "gdi32.dll", "Pie", 9 },
    { "gdi32.dll", "Polyline", 3 },
    { "user32.dll", "PtInRect", 2 },
    { "gdi32.dll", "RealizePalette", 1 },
    { "gdi32.dll", "RectVisible", 2 },
    { "gdi32.dll", "RemoveFontResourceA", 1 },
    { "user32.dll", "RemoveMenu", 3 },
    { "user32.dll", "RemovePropA", 2 },
    { "user32.dll", "ReplyMessage", 1 },
    { "gdi32.dll", "RestoreDC", 2 },
    { "gdi32.dll", "RoundRect", 7 },
    { "gdi32.dll", "SaveDC", 1 },
    { "user32.dll", "ScrollWindow", 5 },
    { "user32.dll", "ScrollWindowEx", 8 },
    { "gdi32.dll", "SelectPalette", 3 },
    { "user32.dll", "SendMessageTimeoutA", 7 },
    { "user32.dll", "SendNotifyMessageA", 4 },
    { "user32.dll", "SetMenu", 2 },
    { "user32.dll", "SetPropA", 3 },
    { "gdi32.dll", "SetROP2", 2 },
    { "user32.dll", "SetRect", 5 },
    { "user32.dll", "SetRectEmpty", 1 },
    { "user32.dll", "SetScrollInfo", 4 },
    { "user32.dll", "SetScrollPos", 4 },
    { "gdi32.dll", "SetStretchBltMode", 2 },
    { "gdi32.dll", "SetViewportOrgEx", 4 },
    { "gdi32.dll", "SetWindowOrgEx", 4 },
    { "user32.dll", "SetWindowRgn", 3 },
    { "user32.dll", "SetWindowsHookExA", 4 },
    { "user32.dll", "ShowOwnedPopups", 2 },
    { "gdi32.dll", "StretchBlt", 11 },
    { "gdi32.dll", "StretchDIBits", 13 },
    { "user32.dll", "TrackPopupMenu", 7 },
    { "user32.dll", "TranslateMDISysAccel", 2 },
    { "user32.dll", "UnhookWindowsHookEx", 1 },
    { "gdi32.dll", "UnrealizeObject", 1 },
    { "user32.dll", "UnregisterClassA", 2 },
    { "user32.dll", "WaitForInputIdle", 2 },
    { "user32.dll", "WaitMessage", 0 },
    { "user32.dll", "WinHelpA", 4 },
    { "user32.dll", "WindowFromPoint", 1 },
    { "ole32.dll", "CLSIDFromProgID", 2 },
    { "ole32.dll", "CoDisconnectObject", 2 },
    { "ole32.dll", "CoFreeUnusedLibraries", 0 },
    { "shell32.dll", "ExtractIconA", 3 },
    { "kernel32.dll", "FileTimeToSystemTime", 2 },
    { "oleaut32.dll", "GetActiveObject", 3 },
    { "kernel32.dll", "GetLocalTime", 1 },
    { "kernel32.dll", "GetOverlappedResult", 5 },
    { "oleaut32.dll", "LoadTypeLib", 2 },
    { "oleaut32.dll", "RegisterTypeLib", 3 },
    { "shell32.dll", "SHBrowseForFolder", 1 },
    { "shell32.dll", "SHChangeNotify", 4 },
    { "shell32.dll", "SHGetFileInfoA", 5 },
    { "shell32.dll", "SHGetMalloc", 1 },
    { "shell32.dll", "SHGetPathFromIDList", 2 },
    { "mpr.dll", "WNetGetUniversalNameA", 5 },
    { "comctl32.dll", "ImageList_BeginDrag", 3 },
    { "comctl32.dll", "ImageList_Destroy", 1 },
    { "comctl32.dll", "ImageList_DragEnter", 2 },
    { "comctl32.dll", "ImageList_DragLeave", 1 },
    { "comctl32.dll", "ImageList_DragMove", 2 },
    { "comctl32.dll", "ImageList_DragShowNolock", 1 },
    { "comctl32.dll", "ImageList_EndDrag", 0 },
    { "comctl32.dll", "ImageList_GetDragImage", 4 },
    { "comctl32.dll", "ImageList_ReplaceIcon", 3 },
    { "comctl32.dll", "ImageList_SetBkColor", 2 },
    { "comctl32.dll", "ImageList_SetDragCursorImage", 4 },
};

/* Case-insensitive dll compare ignoring an optional .dll suffix on either
 * side (stubs are created with names like "user32.dll" but imports may
 * arrive bare, like "user32"). */
static int stub_dll_eq(const char *a, const char *b)
{
    size_t la = strlen(a), lb = strlen(b);
    if (la >= 4 && !strcasecmp(a + la - 4, ".dll")) la -= 4;
    if (lb >= 4 && !strcasecmp(b + lb - 4, ".dll")) lb -= 4;
    if (la != lb || la >= 64)
        return 0;
    char ea[64], eb[64];
    memcpy(ea, a, la); ea[la] = 0;
    memcpy(eb, b, lb); eb[lb] = 0;
    return strcasecmp(ea, eb) == 0;
}

/* Public: stack WORDS a missing import pops (stdcall), or -1 when unknown.
 * Used by the i386 trampoline AND the in-process wow64 stub32 registry to
 * keep 32-bit stacks balanced. */
int wn_stub_pop_words_for(const char *dll, const char *name)
{
    for (size_t i = 0; i < sizeof g_stub_pop_table / sizeof g_stub_pop_table[0]; i++)
        if (stub_dll_eq(g_stub_pop_table[i].dll, dll) &&
            !strcasecmp(g_stub_pop_table[i].name, name))
            return g_stub_pop_table[i].nargs;
    return -1;
}

WN_STUBIMPL_DECL void wn_stub_entry_impl(wn_abiword info_p, wn_abiword a1,
                                         wn_abiword a2, wn_abiword a3,
                                         wn_abiword a4, wn_abiword guest_ret)
{
    wn_stub_info *info = (wn_stub_info *)(uintptr_t)info_p;
    if (!info)
        return;
    info->hits++;
#if !defined(__x86_64__)
    /* Refine the pop decision on the first call: the curated table already
     * set it at creation; for the rest, a cdecl caller (CRT) betrays itself
     * by `add esp,imm` right after the call site. Unknown stdcall stays 0
     * (frame leaks) with a loud warning — never over-pops. Only decode
     * return addresses that live inside a mapped PE module (fault-safe). */
    if (info->pop_known == 0 && info->hits == 1 && guest_ret) {
        wn_module *m = wn_module_from_addr((const void *)(uintptr_t)guest_ret, NULL);
        if (m) {
            uint8_t code[6];
            memcpy(code, (const void *)(uintptr_t)guest_ret, sizeof code);
            int cdecl_caller = (code[0] == 0x83 && code[1] == 0xC4) ||
                               (code[0] == 0x81 && code[1] == 0xC4);
            if (!cdecl_caller)
                wn_log(WN_LOG_WARN, "stub: unknown stdcall arg count for "
                       "%s!%s (arg frame leaks on return)", info->dll, info->name);
        }
    }
#endif
    /* Crash-proof first line: raw write, no stdio, no formatting. */
    if (info->hits == 1) {
        const char msg[] = "[stub-call] ";
        (void)!write(2, msg, sizeof msg - 1);
        (void)!write(2, info->dll, strlen(info->dll));
        (void)!write(2, "!", 1);
        (void)!write(2, info->name, strlen(info->name));
        (void)!write(2, "\n", 1);
    }
    if (wn_log_level() >= WN_LOG_TRACE || info->hits == 1 || info->hits % 1000 == 0) {
        wn_log(WN_LOG_ERR, "STUB %s!%s(args: 0x%llx 0x%llx 0x%llx 0x%llx)",
               info->dll, info->name,
               (unsigned long long)a1, (unsigned long long)a2,
               (unsigned long long)a3, (unsigned long long)a4);
        char where[96] = "?";
        wn_module_describe_addr((const void *)(uintptr_t)guest_ret, where, sizeof where);
        wn_log(WN_LOG_ERR, "STUB %s!%s called from %s -> returning 0, "
               "GetLastError=120", info->dll, info->name, where);
        wn_last_error_set(120 /* ERROR_CALL_NOT_IMPLEMENTED */);
    }
}

static void ensure_region(void)
{
    if (g_stub_region)
        return;
    g_stub_region = mmap(NULL, WN_STUB_AREA, PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
    if (g_stub_region == MAP_FAILED)
        g_stub_region = mmap(NULL, WN_STUB_AREA, PROT_READ | PROT_WRITE | PROT_EXEC,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (g_stub_region == MAP_FAILED) {
        wn_log(WN_LOG_ERR, "stub: cannot allocate trampoline area");
        abort();
    }
}

void *wn_stub_for(const char *dll, const char *name)
{
    ensure_region();
    for (uint32_t i = 0; i < g_info_count; i++)
        if (!strcmp(g_infos[i]->dll, dll) && !strcmp(g_infos[i]->name, name))
            return g_stub_region + (size_t)i * WN_STUB_SLOT;

    if ((uint64_t)(g_info_count + 1) * WN_STUB_SLOT > WN_STUB_AREA) {
        wn_log(WN_LOG_ERR, "stub: trampoline area exhausted");
        abort();
    }
    uint32_t idx = g_info_count;
    g_infos = wn_xrealloc(g_infos, (idx + 1) * sizeof *g_infos);
    wn_stub_info *info = wn_xmalloc(sizeof *info);
    info->dll = wn_xstrdup(dll);
    info->name = wn_xstrdup(name);
    info->hits = 0;
#if !defined(__x86_64__)
    {
        int words = wn_stub_pop_words_for(dll, name);
        info->pop = words >= 0 ? (uint16_t)(words * 4) : 0;
        info->pop_known = words >= 0;
    }
#else
    info->pop = 0;
    info->pop_known = 0;
#endif
    g_infos[idx] = info;
    g_info_count++;

    uint8_t *p = g_stub_region + (size_t)idx * WN_STUB_SLOT;
#if defined(__x86_64__)
    uint64_t info_addr = (uint64_t)(uintptr_t)g_infos[idx];
    uint64_t entry_addr = (uint64_t)(uintptr_t)&wn_stub_entry_trampoline;
    if (info_addr < 0x100000000ULL) {
        *p++ = 0x41; *p++ = 0xBA; memcpy(p, &info_addr, 4); p += 4;   /* mov r10d,imm32 */
    } else {
        *p++ = 0x49; *p++ = 0xBA; memcpy(p, &info_addr, 8); p += 8;   /* mov r10,imm64  */
    }
    *p++ = 0x48; *p++ = 0xB8; memcpy(p, &entry_addr, 8); p += 8;      /* mov rax,imm64  */
    *p++ = 0xFF; *p++ = 0xE0;                                         /* jmp rax        */
#else
    uint32_t info_addr = (uint32_t)(uintptr_t)g_infos[idx];
    *p++ = 0x68; memcpy(p, &info_addr, 4); p += 4;                    /* push imm32     */
    int32_t rel = (int32_t)((uintptr_t)&wn_stub_entry_trampoline
                            - (uintptr_t)(p + 5));
    *p++ = 0xE9; memcpy(p, &rel, 4); p += 4;                          /* jmp rel32      */
#endif
    return g_stub_region + (size_t)idx * WN_STUB_SLOT;
}

unsigned wn_stub_count(void) { return g_info_count; }
