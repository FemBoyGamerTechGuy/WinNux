# HANDOFF.md — what was happening, and the next 3 steps

Read this before continuing. Pair with STATUS.md (what works + proof) and
TODO.md (prioritized backlog).

## Last session (session 9) — what happened

The user reported LuaForWindows dying with glibc `*** stack smashing
detected ***` right after six DLL-not-found warnings. Three-part fix:

1. The smash: user32.c's extern decls used uint64_t for parameters the
   definitions type wn_abiword — on i386 that is 8 pushed vs 12 popped
   bytes (stdcall ret 12) per call, and the skewed ESP pushed straight
   through load_string_lookup's rid[16] and its canary. All 6 decls now
   use wn_abiword. Why we never saw it: Debian gcc has no default stack
   protector, Arch gcc does; the Makefile now passes
   -fstack-protector-strong everywhere (use scripts/dev/canary32.c as
   LD_PRELOAD under qemu to see any future canary trip with a frame dump).
2. The DLLs: apphelp/propsys/oleacc/profapi/comres/clbcatq are Inno
   presence probes — added as builtins in src/dlls/sysdlls.c (loads
   succeed, functions fail honestly, placeholder files appear in
   drive_c/windows/system32). Startup log is clean.
3. Fuzzer-found (re-run exposed them): wild ImageBase above 2^47 now
   rejected before MAP_FIXED_NOREPLACE (LA57 kernels would map it);
   wn_pe_dirs() no longer re-reads e_lfanew from the mapped image (a
   VA-0 section clobbers the mapped DOS header) — the validated offset
   is cached in wn_pe_image.opt_off; the header blob must fit in
   SizeOfHeaders and the file.

Verified: 15/15 tests, fuzz 45k mutations clean, lua 7/WIN, sqlite,
putty alive, 7zr usage, LuaForWindows alive with zero warnings and
zero canary trips under qemu.

## Next 3 steps

1. User's native re-test of LuaForWindows (the whole point of session
   9): past DLL probing, the Inno engine should decompress and raise
   its wizard GUI — expect the next crash to be in that path; use
   scripts/dev/canary32.so + WINNUX_LOG=trace first, gdbstub second.
2. MSVC C++ EH (i386 fs:0 scope frames + __CxxFrameHandler, then x64
   .pdata): unlocks 7zr completion and modern MSVC 32-bit error paths.
3. The putty follow-ups (message-queue overflow, EnableWindow+SEH scope
   dispatch, resize crash, fd leak in registry) — still queued from
   session 6-8.
