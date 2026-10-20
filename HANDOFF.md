# HANDOFF.md — what was happening, and the next 3 steps

Read this before continuing. Pair with STATUS.md (what works + proof) and
TODO.md (prioritized backlog).

## Last session (session 11) — what happened

USER REPORT (the session trigger): `WINNUX_WOW64=1 WINNUX_LOG=debug
timeout 120 ./bin/winnux run ~/test/LuaForWindows_v5.1.5-52.exe /S` spammed
the terminal with `PeekMessageA / TranslateMessage / DispatchMessageA` pairs
returning `hwnd=101 msg=1` forever and hit the timeout.

- REPRODUCED exactly (21.5M lines / 40s with Xvfb up). TWO root causes:
  (a) u32_PeekMessageA had PM_NOREMOVE/PM_REMOVE INVERTED (PM_REMOVE=1 took
  the "leave it queued" branch — Inno re-peeked the same message forever);
  (b) WM_CREATE was POSTED into the queue instead of being sent inside
  CreateWindowEx with a real CREATESTRUCT. Both fixed.
- The fix exposed a chain of systemic wow64 bugs, all the same class
  (compile-time `#if __x86_64__` struct layouts applied to a 32-bit guest
  running IN-PROCESS on the x86-64 host; the runtime fix is
  wn_wow64_guest32()): guest MSG layout (stack smash per peek),
  RegisterClassA/WNDCLASS (the child registered 'TApplication' with a
  GARBAGE name -> Delphi "class not found" exception), the sigs32 table
  (regenerate with scripts/dev/gen_sigs32.py after adding exports — a
  stale table caused a 4-byte stack skew: CreateWnd's `pop ebx` read a
  RETURN ADDRESS and `ret` jumped to 0), RaiseException info arrays,
  WFMO/MsgWait handle arrays (the parent polled garbage handles and never
  reaped its zombie child), GWL_WNDPROC on builtin classes (host pointer
  handed to the guest -> jumped to its low 32 bits).
- NEW INFRASTRUCTURE: the 64->32 callback bridge
  (wn_wow64_call_wndproc32: wndprocs/dlgprocs/timers/subclassing/
  CallWindowProc — 32-bit guest code addresses are NEVER callable as host
  functions) and the 32-bit frame-based SEH engine in seh.c (fs:[0] walk,
  guest-layout record/context in low memory, unwind-to-finally + outward
  search model decoded from the installer's own Borland System-unit
  handlers, RtlUnwind continuation landing with [esp]=ReturnValue
  [esp+4]=Record, longjmp chain for clean handler-abort).
- RESULT: the process tree works end-to-end for the first time (extract ->
  spawn engine -> engine reads its payload byte-perfect -> parent notices
  failure, deletes the temp dir, ExitProcess). The engine itself still
  crashes in Inno's setup-data processing (corrupted list node
  edx=0x40a998; reads proven clean, so the engine corrupts its own data —
  details + evidence in TODO "installer bring-up").

## The next 3 steps

0. DONE in session 12 (context): the reported `make winnux32` failure
   (unused params in wn_wow64_unwind32_take under -m32) plus the link
   breakage it was masking (wn_seh_rtl_unwind_32 was x64-only): seh.c now
   has the NATIVE i386 frame-SEH engine (#else branch — real fs:0x18 TEB
   walk, cdecl handler calls, wn_seh32_land stack-switch landing), the
   nested-fault cap + pending-unwind reuse went into BOTH engines, and
   the obj32 Makefile rules gained per-file -fno-stack-protector + dep
   tracking. toolchain/root32 + qemu were rebuilt (setup script:
   /home/z/my-project/scripts/setup_root32.sh); `make winnux32` links,
   smoke32 9/9 under qemu, 64-bit suite 16/16. The qemu process tree works
   (WINNUX_CHILD_CMD routes guest CreateProcess through the emulator).
1. Engine corruption hunt — now fully armed: the crash is DECODED (the
   engine's own small-block heap freelist push at 0x401bb7 with a VMT
   address in the bucket head; one runaway write also tramples host brk
   key structs, caught by the child_find "HK" tripwire). The engine
   binary is captured + analysis in /home/z/my-project/engine-forensics/.
   Next: qemu -g + gdb on winnux32, breakpoint 0x401bb7, watchpoint the
   bucket table (ds:0x49d478), walk back to the FIRST corrupting write.
   All Windows-contract fixes that were provably wrong (Global heap
   moveable model, resource HGLOBALs, registry zombies) are landed;
   16/16 + smoke32 green with them.
2. Then the same installer goal continues: engine past the data-corruption
   crash -> files land in drive_c/Program Files -> registry uninstall keys
   -> lua.exe smoke test `print(1+2*3, ("win"):upper())`.
