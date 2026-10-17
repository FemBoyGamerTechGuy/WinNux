# HANDOFF.md — what was happening, and the next 3 steps

Read this before continuing. Pair with STATUS.md (what works + proof) and
TODO.md (prioritized backlog).

## Last session (session 4) — what happened

Goal (from the task brief): keep the loop going on putty until its config
dialog is real; the session started with in-flight SEH-unwinding work
(Rtl* exports) uncommitted.

Putty used to die ~50ms after startup with no crash report — only three
optional-DLL notes then silence, exit 9. The hunt (disassembly of
putty.exe + stack archaeology from our TerminateProcess handler) found a
chain of four real WinNux bugs, all fixed this session:

1. **gdi32 GetTextMetricsA overflow (THE killer)**: memset(tm, 0, 0x58) +
   a write at tm+0x54 into a 56-byte TEXTMETRICA → 32-byte stack smash →
   putty's /GS canary corrupted → __report_gsfailure →
   TerminateProcess(0xC0000409). Exact x64 layout now (0x38 bytes).
2. **LoadCursor/LoadIcon(A/W) dereferenced MAKEINTRESOURCE** values
   (IDC_ARROW = 0x7f00 as a char*) → SIGSEGV in res_name_to_id.
3. **IsDialogMessage was one-arg**; real signature (hDlg, lpMsg) — RCX is
   the dialog HWND, RDX the MSG*.
4. **loader cands[2] OOB read** in the explicit-path probe loop (only when
   the name lacked ".dll", e.g. hhctrl.ocx) → garbage 3rd probe → the
   "unreadable win-path pointer" WARN spam. cands[3] + NULL terminator +
   Windows extension semantics (.dll only appended to extension-less names).

Also landed: MoveWindow + SetWindowPos (child coords + parent recompose;
top-level via new backend op win_move_resize — X11 XMoveResizeWindow
dlsym'd), and the previously in-flight kernel32 Rtl* unwinding exports
(RtlCaptureContext raw-asm, RtlLookupFunctionEntry, RtlVirtualUnwind with
full unwind-code interpretation, RtlPcToFileHeader, RtlUnwind v1) +
RaiseException + UnhandledExceptionFilter routing to the app's filter.

**RESULT: putty now STAYS ALIVE in its message loop** (killed only by our
timeout), "PuTTY Configuration" dialog + timing window mapped under Xvfb,
quiet log, 40s ASan/UBSan soak clean. 15/15 tests; lua/sqlite re-verified.

Debug-tooling that helped (kept): scripts/dev/xtree.c — host tool compiled
with -lX11 OUTSIDE the product build; dumps the X window tree and saves
PPM screenshots. `cc -O2 -o /tmp/xtree scripts/dev/xtree.c -lX11`.

## Next 3 steps (exactly this order)

1. **Dialog interaction proof**: route X clicks to child controls →
   WM_COMMAND (BN_CLICKED, control id) to the dialog proc; verify putty's
   OK/Cancel/Apply buttons fire (log lines from putty's dlgproc handlers).
   Extend the existing mouse-hit path in the message pump.
2. **Control visual fidelity**: real Button (border + text + check),
   Edit (sunken border + caret), Static, ListBox painting in the compose
   path + GetSysColor palette; screenshot with xtree should show text in
   the dialog, not flat boxes.
3. **SEH dispatch loop** (P1): use RtlVirtualUnwind in wn_seh_raise/crash
   paths to walk guest frames and call scope-table handlers; t16 test with
   mingw __try/__except catching a deliberate AV.

## Dead ends / gotchas (do not repeat)

- The Edit/Write tools convert TABs to spaces — NEVER edit the Makefile with
  them; use `sed` (a session was lost to "missing separator" once already).
- `wn_utf16_to_utf8(w, len16)`: second arg is the INPUT length in UTF-16
  units, not bytes, not a capacity. Two people got this wrong already.
- SQLite CLI: `sqlite3.exe FILE` opens FILE as a DATABASE and reads SQL from
  stdin — a foreground run then blocks on the terminal forever. Use
  `sqlite3.exe :memory: "SQL..."` or `< script.sql`.
- Block comments must not contain `*/` from things like "wave*/midi*" — it
  terminates the comment.
- PuTTY is MSVC-built with FPO OFF: RBP chains are walkable; keep the crash
  report's frame walk.
- Stale .o files under obj-dbg (sources since deleted) break the fuzz link:
  `rm -rf obj-dbg && make debug` before fuzzing after structural changes.
- Builtin output-struct writers MUST match the exact Win64 layout size —
  putty's /GS canary sat right after a 56-byte TEXTMETRICA and our 88-byte
  write killed the process with 0xC0000409 (no crash report — MSVC
  fast-fails). When adding any struct-writing API, write the offsets in a
  comment and count the bytes.
- MSVC __report_gsfailure sequence to recognize: SetUnhandledExceptionFilter
  (NULL) then TerminateProcess(-1, 0xC0000409). If you see it, a callee
  smashed a guest stack buffer — hunt OUR struct writers first.
- backtrace() cannot unwind guest (ms_abi) frames; symbolize the first
  non-winnux frame with wn_module_from_addr and objdump the exe around
  that RVA (host objdump works on PE with -M intel; image base 0x140000000).
- `winnux run` output through `grep | head` pipes eats the REAL exit code —
  redirect to a file and check $? separately or you will misread exits.

## Environment notes

- Box: Debian 13, GCC 14.2 (user runs GCC 15 — keep both compatible; the
  strchr/strrchr/strstr const-propagation class of diagnostics is the known
  difference so far).
- Xvfb auto-started on :95 by the test runner; `scripts/dev/xtree.c` (host
  tool, cc -lX11, not shipped) lists the X window tree and captures PPM
  screenshots — use it to prove guest windows.
- Real apps live OUTSIDE the repo in /home/z/my-project/apps: putty.exe
  (x64 GUI), 7zr.exe (32-bit! WoW64 driver case), lua-5.4.7 (built with the
  in-tree mingw toolchain), sqlite-amalgamation-3500400 (built likewise).
  Never commit binaries; the token stays in /home/z/my-project/.github_token.
- GitHub: push with the per-command credential helper (see git log messages
  / worklog for the pattern); token must never enter the repo.
