# HANDOFF.md — what was happening, and the next 3 steps

Read this before continuing. Pair with STATUS.md (what works + proof) and
TODO.md (prioritized backlog).

## Last session (session 6) — what happened

PuTTY's config dialog became the REAL dialog: the empty category pane was
a missing SysTreeView32 control class (putty creates it dynamically; our
unknown-class path returned 0 with NO log). The tree now renders exactly
like Windows (Session->Logging, Terminal->Keyboard/..., Window->...,
Connection->SSH->...) because of a Win64 interop trap: TVI_ROOT is
SIGN-EXTENDED (0xFFFFFFFFFFFF0000) and our zero-extended constant
rejected every root insert (found by disassembling the immediate in
putty.exe). BS_GROUPBOX is 0x7 (not 0x5); group boxes now paint
transparently onto the parent — the Session panel's Host Name/Port/
radios/Saved Sessions are all visible (VLM-verified). Also: the EMFILE
registry failure was ensure_gui leaking one eventfd per CreateWindowEx
(state=1 was never set on success — putty ran at 72 fds idle, now 5),
& prefixes parse in DrawText, ShellExecuteA/W/Ex really opens URLs
(xdg-open) and re-launches .exe through our own loader, and windows
without WS_THICKFRAME are locked to their size via XSetWMNormalHints
(X11 WMs resize anything; Windows dialogs are fixed) plus gdi32 DCs
re-bind pixel buffers after resize.

32-bit (i386) landed end-to-end at the source level: PE32 parse/map/
reloc/import (4-byte thunks), i386 TEB/PEB/LDR layouts (fs:0x18 self —
hosted via modify_ldt LDT entries since glibc owns %gs), WN_API=stdcall +
WN_CRTAPI=cdecl compile-time dispatch, portable msvcrt varargs, the
__p__* mingw startup family, an i386 stub trampoline, `make winnux32`
(links ELF32; stdcall ret-N + modify_ldt + fs load verified in the
binary), and the 64-bit winnux re-execs winnux32 for I386 images.
`winnux imports` fully parses PE32: 7zr.exe walks clean, and a
mingw-i686 hello32.exe shows 50/50 imports with ZERO stubs.

## Next 3 steps (exactly this order)

1. **32-bit runtime bring-up on real hardware**: the sandbox CANNOT run
   any i386 code (kernel compat syscalls blocked by seccomp — even a
   static exit(42) dies with SIGSYS). On the user's Arch box: enable
   [multilib] in /etc/pacman.conf (pacman -Ss finds nothing without it),
   `sudo pacman -S gcc-multilib lib32-gcc-libs`, `make winnux32`, then
   `./bin/winnux run 7zr.exe` (and apps/hello32.exe if built). Expect
   first-run bugs in mingw CRT startup; the i686 mingw cross-compiler is
   extracted at toolchain/root (i686-w64-mingw32-gcc-posix +
   -isystem share/mingw-w64/include) for building 32-bit test exes.
2. **PuTTY Open -> session**: the config box works; type hostname, click
   Open, trace the launch (CreateThread for the session, terminal window
   class). The terminal text path (FreeType mono) is ready.
3. **32-bit GUI struct layouts** (MSG/TVITEM/... are x64-shaped) after
   console-class 32-bit apps run.

## Dead ends / gotchas (do not repeat)

- The Edit/Write tools convert TABs to spaces — NEVER edit the Makefile
  with them; use `sed` or `python` line-rewrite (a session was lost to
  "missing separator" once already). Session 6 updated the Makefile
  exclusively via python heredocs.
- `wn_utf16_to_utf8(w, len16)`: second arg is the INPUT length in UTF-16
  units, not bytes, not a capacity. Two people got this wrong already.
- MS-ABI struct-by-value trap: 1/2/4/8-byte structs arrive IN A REGISTER
  (MonitorFromPoint's POINT -> RCX; declare it as one uint64_t).
- XGetWindowAttributes writes ~136 BYTES regardless of the overlay size.
- TVI_ROOT/FIRST/LAST/SORT on Win64 are SIGN-EXTENDED
  (0xFFFFFFFFFFFF0000+) — the tree-view class of bugs. Same for any
  (ULONG_PTR)-N sentinel (CURRENT_PROCESS pseudo-handles: compare via
  (intptr_t)(uintptr_t), not (int64_t)).
- BS_GROUPBOX = 0x7. 0x5 is BS_3STATE. Check winuser.h, not memory.
- FreeType/XImage overlays are LP64-probed: guard their asserts + make
  the runtime path x64-only (i386 falls back to the bitmap atlas).
- i386 varargs: 4-byte slots, doubles 8-aligned (4 pad skipped);
  MSVC/ELF i386 va_list are both char* — the v-family takes char* by
  value unchanged.
- Expected-file format in tests/: LINE 1 IS THE EXIT CODE.
- Makefile recipes: `exit 0` inside one recipe line does NOT stop the
  target — use make-level `ifeq` conditionals for skip logic.
- PuTTY is MSVC-built with FPO OFF (x64): RBP chains walkable. The i386
  chain is 4-byte — walk guarded to x64.
- Builtin output-struct writers MUST match the exact per-bitness layout
  (TEXTMETRICA /GS canary lesson). When adding any struct-writing API,
  write the offsets in a comment and count the bytes per arch.
- `winnux run` output through `grep | head` pipes eats the REAL exit
  code — redirect to a file and check $? separately.

## Environment notes

- Box: Debian 13, GCC 14.2 (user runs GCC 15 — keep both compatible).
  NO i386 execution (seccomp; documented above), NO root/sudo. Xvfb on
  :95 (1920x1080x24). scripts/dev/xtree.c (host tool, cc -lX11):
  tree dump, PPM screenshots, synthetic click/key, WM_DELETE close.
- Toolchains (all OUTSIDE the repo in /home/z/my-project/toolchain):
  root = x86_64-w64-mingw32 (test exes) + root/usr/bin/
  i686-w64-mingw32-gcc-posix (32-bit test exes; needs -isystem
  root/usr/share/mingw-w64/include + -B root/usr/i686-w64-mingw32/bin);
  root32 = glibc32 sysroot for -m32 (libc6-i386 + libc6-dev-i386 +
  lib32gcc-14-dev, ld scripts patched to absolute paths).
- Real apps live OUTSIDE the repo in /home/z/my-project/apps: putty.exe
  (x64 GUI), 7zr.exe (32-bit acceptance case), lua, sqlite. Putty 0.85
  SOURCE also lives in /tmp/putty-0.85 (windlg/controls/dialog.c) — the
  map for anything the config box does.
- GitHub: push with the per-command credential helper; token stays in
  /home/z/my-project/.github_token (never committed).
