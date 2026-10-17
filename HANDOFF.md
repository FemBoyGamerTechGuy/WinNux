# HANDOFF.md — what was happening, and the next 3 steps

Read this before continuing. Pair with STATUS.md (what works + proof) and
TODO.md (prioritized backlog).

## Last session (session 5) — what happened

User-reported bugs, all reproduced + fixed: the message-queue overflow spam
(WM_SIZE/WM_PAINT posted per control move + uncoalesced WM_MOUSEMOVE; now
sync-delivered / dirty-flag-synthesized / coalesced, ring grows to 8192),
the About-box segfault (dialogs were CHILDREN of their owner; now top-level
owned popups — full modal cycle proven: open, interact, WM_DELETE close,
owner re-enabled), the three missing optional DLLs (wship6 = getaddrinfo
family with AF_INET6 translated Linux 10 → Windows 23; shcore DPI; hhctrl
stubs), EnableWindow/MessageBeep real (disabled windows now refuse input),
and the registry save hardened (atomic tmp+rename, errno reported, unlink
retry).

Monitor/DPI APIs landed (GetSystemMetrics, MonitorFrom*, GetMonitorInfo,
SystemParametersInfo, real top-level GetWindowRect with cw/ch + screen-sized
desktop) — putty centers its config box exactly ((660,36) on 1080p).
Text is FreeType-rendered now (dlopen libfreetype, probed+verified struct
overlays, /proc/self/maps-guarded face scan, family matching, AA blit;
bitmap atlas remains the fallback). check32 (i386 compile probe) + arch
guards landed as WoW64 groundwork.

Session archaeology worth remembering: a 24-byte XWindowAttributes overlay
smashed the stack in x11_init (the real struct is ~136 bytes); top-level
windows never had cw/ch set (GetWindowRect → 0-size → putty clamped to
1x1); a stale /proc/self/maps snapshot made FreeType verification flaky
(FT_New_Face extends the heap — refresh per scan); MonitorFromPoint takes
POINT BY VALUE = packed into RCX.

## Next 3 steps (exactly this order)

1. **PuTTY Open → SSH session launch**: the Open button's
   WM_COMMAND(BN_CLICKED, id=1009) reaches putty's dlgproc (proven via
   ctl_notify trace) but no launch follows. Disassemble the PuTTYConfigBox
   wndproc's WM_COMMAND path around the call site, find which call fails
   silently (suspects: config serialization to the registry, CreateThread
   for the session thread, socket events on the launch thread), and drive
   it to a terminal window. Hostname typing already works (EN_CHANGE +
   GetDlgItemText verified).
2. **32-bit WoW64, the real thing** (user priority): on the user's Arch
   box (gcc-multilib), run `make check32` and fix the fallout; then build
   the i386 runtime (Wine model: separate 32-bit process, 32-bit libX11
   via dlopen), per-export stdcall/cdecl dispatch metadata, i386 TEB/PEB
   via set_thread_area. 7zr.exe (32-bit, in apps/) is the acceptance case.
3. **SEH scope-table dispatch loop**: RtlVirtualUnwind exists; wire the
   dispatch (walk guest frames, call __except handlers) with a t16 mingw
   __try/__except test catching a deliberate AV.

## Dead ends / gotchas (do not repeat)

- The Edit/Write tools convert TABs to spaces — NEVER edit the Makefile with
  them; use `sed` or `python` line-rewrite (a session was lost to "missing
  separator" once already).
- `wn_utf16_to_utf8(w, len16)`: second arg is the INPUT length in UTF-16
  units, not bytes, not a capacity. Two people got this wrong already.
- MS-ABI struct-by-value trap: 1/2/4/8-byte structs arrive IN A REGISTER
  (MonitorFromPoint's POINT → RCX; declare it as one uint64_t, not (x,y)).
  Same class as the IsDialogMessage bug.
- XGetWindowAttributes writes ~136 BYTES regardless of what your overlay
  declares — size every X struct overlay for the REAL struct or oversize
  it (XImage/wa overlay class of bugs; a 24-byte overlay smashed the
  stack this session).
- Putty's centre_dialog measures GetWindowRect(GetDesktopWindow()): the
  desktop pseudo-window must track the REAL screen size or dialogs land
  wrong / get clamped to 1x1.
- FreeType: a face's max_advance_width is NOT an average (DejaVu Bold:
  4129 units = 2× em). Use the 'x' glyph advance for tmAveCharWidth.
- /proc/self/maps snapshots go STALE when libraries allocate (dlopen,
  FT_New_Face) — refresh before pointer-validity scans.
- Expected-file format in tests/: LINE 1 IS THE EXIT CODE, then output.
  Editing a message without preserving the leading "0" line silently
  breaks the runner comparison.
- Makefile recipes: `exit 0` inside one recipe line's shell does NOT stop
  the target — use make-level `ifeq` conditionals for skip logic.
- SQLite CLI: `sqlite3.exe FILE` opens FILE as a DATABASE and reads SQL from
  stdin — a foreground run then blocks on the terminal forever. Use
  `sqlite3.exe :memory: "SQL..."` or `< script.sql`.
- Block comments must not contain `*/` from things like "wave*/midi*" — it
  terminates the comment.
- PuTTY is MSVC-built with FPO OFF: RBP chains are walkable; keep the crash
  report's frame walk.
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

- Box: Debian 13, GCC 14.2 (user runs GCC 15 — keep both compatible), NO
  32-bit libc headers (make check32 SKIPs; user's Arch box can install
  gcc-multilib). Xvfb on :95 (screen 1920x1080x24 for putty's tall config
  box). scripts/dev/xtree.c (host tool, cc -lX11, COMMITTED this time —
  it was lost once): tree dump, PPM screenshots, synthetic click/key/
  WM_DELETE-close. This time it is in git.
- Real apps live OUTSIDE the repo in /home/z/my-project/apps: putty.exe
  (x64 GUI), 7zr.exe (32-bit! WoW64 driver case), lua, sqlite. Never
  commit binaries; the token stays in /home/z/my-project/.github_token
  (untracked, and ALSO untracked from the workspace's own repo).
- GitHub: push with the per-command credential helper (pattern in git log
  messages / worklog); token must never enter any repo.
