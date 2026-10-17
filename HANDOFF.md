# HANDOFF.md — what was happening, and the next 3 steps

Read this before continuing. Pair with STATUS.md (what works + proof) and
TODO.md (prioritized backlog).

## Last session (session 3) — what happened

Goal: stop fixing missing DLLs one at a time; make real apps load.

Done, in order:
1. `winnux imports <exe> [-v]` static import analyzer (PE32+ AND PE32, incl.
   delay-load imports and builtin ordinal `#N` exports). Exit 1 = missing DLL
   or 32-bit image.
2. 25+ new builtin DLLs (imm32, comctl32, comdlg32, shell32, shlwapi, ole32,
   oleaut32 with ordinals, rpcrt4/uuid, version, psapi, dbghelp, setupapi,
   winspool.drv, wininet, winhttp, mswsock, iphlpapi, dnsapi, crypt32,
   bcrypt(+cryptbase), secur32/sspicli, userenv, uxtheme, dwmapi, winmm,
   msvcp140 family) + api-set routing (crt→ucrtbase, rest→kernelbase).
3. Real bugs found BY REAL APPS and fixed:
   - **loader: LoadLibrary with full paths** ("C:\windows\system32\kernel32.dll")
     now resolves: basename matches builtins, paths map into the prefix.
     This is what unblocked putty's winsock load.
   - wn_utf16_to_utf8(length) misused in 3 places (LoadLibraryW,
     GetModuleHandleW) — out-of-bounds reads, fixed.
   - FLS implemented on the Tls index space (mingw CRT init needs it).
   - msvcrt: ctype batch, real x64 `_setjmp`/`_longjmp` (raw asm, MS
     jmp_buf layout), fgets, _wfopen, _fileno, _isatty, _access, _setmode,
     _time64.
   - IsProcessorFeaturePresent: PF_FASTFAIL_AVAILABLE=23 returns 0 now
     (returning 1 made MSVC abort() execute int 0x29 instantly).
   - user32 MessageBoxA/W prints text to the log + returns IDOK (diagnostic
     aid: this is how "Unable to load any WinSock library" was found).
   - Crash report now walks the RBP frame chain ("#N from module+rva").
   - wsock32.dll alias onto ws2_32 exports.
4. Real-app results (recorded in STATUS.md): putty.exe creates a window;
   lua.exe and sqlite3.exe run REAL workloads; 13/13 tests; ASan+UBSan clean;
   fuzz clean.

## Next 3 steps (exactly this order)

1. **user32 dialog engine**: DLGTEMPLATE(EX) parser + CreateDialogParamA/W +
   DialogBoxParam + IsDialogMessageA + EndDialog + GetDlgItem +
   WM_INITDIALOG. PuTTY's config dialog is the test case (putty.exe +
   `xprobe :95` to verify the window tree; add t14_gui_dialog mingw test).
2. **Basic control classes**: register built-in classes "Button", "Edit",
   "Static", "ListBox", "ComboBox" (own wndprocs over the existing GDI
   software backend). t15 control test.
3. **SEH table unwinding** (P1 in TODO.md): RtlLookupFunctionEntry +
   RtlVirtualUnwind + RtlUnwind(Ex) over .pdata/.xdata — putty's abort path
   calls them and guest __try needs them. Test: mingw exe with __try/__except
   catching a deliberate access violation.

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

## Environment notes

- Box: Debian 13, GCC 14.2 (user runs GCC 15 — keep both compatible; the
  strchr/strrchr/strstr const-propagation class of diagnostics is the known
  difference so far).
- Xvfb auto-started on :95 by the test runner; `scripts/xprobe.c` (host
  tool, not shipped) lists the X window tree — use it to prove guest windows.
- Real apps live OUTSIDE the repo in /home/z/my-project/apps: putty.exe
  (x64 GUI), 7zr.exe (32-bit! WoW64 driver case), lua-5.4.7 (built with the
  in-tree mingw toolchain), sqlite-amalgamation-3500400 (built likewise).
  Never commit binaries; the token stays in /home/z/my-project/.github_token.
- GitHub: push with the per-command credential helper (see git log messages
  / worklog for the pattern); token must never enter the repo.
