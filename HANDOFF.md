# HANDOFF.md — what was happening, and the next 3 steps

Read this before continuing. Pair with STATUS.md (what works + proof) and
TODO.md (prioritized backlog).

# HANDOFF.md — what was happening, and the next 3 steps

Read this before continuing. Pair with STATUS.md (what works + proof) and
TODO.md (prioritized backlog).

## Last session (session 8) — what happened

The user reported LuaForWindows (i386, Inno/Delphi, /FIXED) failing at
"needs relocation but has no .reloc". That cascaded into the deepest
32-bit chain-fix yet — every layer was a real i386-only bug that the
64-bit build masked. In order: preferred-ImageBase mapping
(MAP_FIXED_NOREPLACE), PE32 static-TLS registration + main-thread block
backfill, VirtualAlloc reserve→commit-in-place (the Delphi MM pattern),
i386 MEMORY_BASIC_INFORMATION (28 bytes) + VirtualQuery return, arch-split
GetSystemInfo, sscanf %lx width in /proc parsing, -fno-pic/-no-pie for the
whole build (PIC EBX=GOT leaked into guest calls!), stdcall-correct stub
trampolines, entry-point hInstance = image base. Plus the API batch real
32-bit apps need (FindFirstFileW, GetFullPathName, LoadString, locale
family, FormatMessage, wchar CRT, GetProcessAffinityMask...) and the
readdir64 fix (32-bit readdir EOVERFLOWs on 64-bit-inode filesystems).

Proof points: LuaForWindows runs past every crash (alive, payload work),
7zr 26.04 i386 scans and starts archiving (blocked on MSVC C++ EH — see
TODO 0), hello32/torture32/FindFile A+W tests PASS, 64-bit 15/15.

The debugging was done with scripts/gdbstub_watch.py (+measure/step/vtrace)
— a Python GDB-remote client for qemu-i386's gdbstub. USE IT for the next
32-bit crash: breakpoints at wn_* symbols via `nm`, arg dumps from the
guest stack, single-step traces from any breakpoint.

## Next 3 steps

1. MSVC C++ EH (i386 first: fs:0 scope frames + __CxxFrameHandler, then
   x64 .pdata): unlocks 7zr completion and every modern MSVC 32-bit app's
   error paths. 7zr create+extract roundtrip is the test.
2. LuaForWindows GUI on native hardware: window creation + Inno dialog
   fidelity (the `&` mnemonic stripping and ListBox text bugs from putty
   are still open — same rendering path).
3. The putty follow-ups (message-queue overflow, EnableWindow+SEH scope
   dispatch, resize crash, fd leak in registry) — all still queued.
