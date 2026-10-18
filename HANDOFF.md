# HANDOFF.md — what was happening, and the next 3 steps

Read this before continuing. Pair with STATUS.md (what works + proof) and
TODO.md (prioritized backlog).

## Last session (session 10) — what happened

The user's next native report (LuaForWindows, one log line):
`EXCEPTION_ACCESS_VIOLATION at luaforwindows+0x4325, access READ at 0x4`,
registers mostly zero, RSP sign-extended garbage. Root-caused:

- `exe+0x4325` is `mov [eax+4],edx` — Delphi System-unit init writing
  threadvar[1] through the block returned by Inno's fast-path accessor
  (`fs:[0x2C][*(DWORD*)0x40d3d0]`, the PE TLS dir's index slot). The
  returned block was NULL on the user's box.
- The old crash report MIS-CLASSIFIED the write as a read (Linux
  SEGV_MAPERR carries no direction) and printed sign-extended i386 gregs.
  Both fixed: fault_is_write() opcode decode in seh.c, gregs zero-extended,
  "putty-ish rip" label replaced by real module+RVA.
- The whole static-TLS chain is provably healthy under qemu-i386 (new
  scripts/tls_probe.py — a GDB-remote client for qemu's -g stub; also the
  tool that injected the fault). The native failure is index-slot-loss or
  block-loss by elimination; gdbstub-injecting it reproduces the user's
  crash byte-for-byte.
- FIX: guest_entry_shim now enforces the Windows loader contract at the
  last moment — index slot rewritten if wrong (WARN), entry thread's block
  allocated if missing (WARN), full chain logged at DEBUG, refusal +
  ERR if fs:0x18 does not resolve to a registered TEB. Injected fault is
  healed and the app survives; the WARN/ERR text names the broken link
  for the next native run.
- New t16_tls32 test locks static TLS on both arches (16/16 suite);
  i386 t01/t06/t09/t16 + 7zr verified under qemu; fuzz 3000 clean.
- Sandbox reset had wiped toolchain/root32 + qemu + i686 mingw AGAIN —
  rebuilt from debs (see run32.sh header + STATUS session 10; lib32gcc-s1
  is now required: glibc dlopens libgcc_s.so.1 on pthread_exit).

## Next 3 steps

1. User's native re-test of LuaForWindows: `make winnux32 && ./bin/winnux
   run .../LuaForWindows_v5.1.5-52.exe`. If the pre-entry repair fires,
   the WARN/ERR line in the log names the exact broken link (slot value,
   missing block, or unregistered TEB) — that pinpoints the native-only
   root cause for a REAL fix rather than the guarantee. If no repair line
   and it still crashes: grab the (now honest) crash report + WINNUX_LOG=debug
   (adds "pre-entry TLS: index/teb/array/block").
2. MSVC C++ EH (i386 fs:0 scope frames + __CxxFrameHandler, then x64
   .pdata): unlocks 7zr completion and modern MSVC 32-bit error paths.
3. The putty follow-ups (message-queue overflow, EnableWindow+SEH scope
   dispatch, resize crash, fd leak in registry) — still queued from
   session 6-8.
