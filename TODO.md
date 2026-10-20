# TODO.md — the prioritized backlog

Order = what real apps import/hit most. Every entry carries the evidence that
put it here. Never silently drop items; move them to STATUS.md when done.


## P0 — installer bring-up (session 18 state)

THE WIZARD PAINTS (session 18, commit b73c782): one visible window, the
license page fully rendered (text, radios, buttons, sidebar image), idles
clean. The white window / two windows / dead-close-button report is closed
root-and-branch: i386 X11 event overlays, SW_HIDE mapping, 0x0-window
inflation, the SetWindowPos SWP_SHOWWINDOW early-return, the child paint
pipeline, and the GDI clip/origin/DIB family — full decode chain in
session-18 STATUS.md. New P0 = interact with the real pixels:

0. CLICK THROUGH (now meaningful — the pixels exist): synthetic input via
   scripts/dev xtree click mode. NOTE: the click chain needs the i386 event
   overlays that landed this session (mouse was dead before). Welcome Next
   -> license radio -> components checklist -> dir page -> install. Expect
   the checklist scroll (ScrollWindowEx is real now) and the progress bar
   as the next contracts.
1. LICENSE MEMO BODY: the license page renders but the memo is empty. The
   text path is ready (full wtext + DT_WORDBREAK multiline EDIT paint +
   EM_GETLINECOUNT honest); trace where Inno's LicenseMemo.Lines.Text
   actually goes (WM_SETTEXT? EM_REPLACESEL? a gating EM_* we mis-answer?).
2. /S SILENT PATH + lua.exe smoke test (unchanged from session 17).
3. Session-11 wow64 width-bug pattern audit: STILL OPEN, and this session
   added fresh per-arch surfaces (x11_backend offsets, ScrollWindowEx
   prcUpdate RECT) — all guest-RECT layouts are arch-independent (4x LONG).
4. i686 32-bit smoke suite under run32.sh (unchanged; now also covers the
   new GDI clip/origin paths).
Older P0 notes (session 11/12 handoff):

The reported PeekMessage pump bug is FIXED+verified; the LuaForWindows /S run
now: outer instance extracts + spawns the is-*.tmp engine, the engine reads
its payload byte-perfect, and the parent reaps/cleans up/exits on failure.
Remaining, in evidence order:

1. ENGINE DATA CORRUPTION — DECODED (session 12): the crash at engine
   0x401bb7 is the Inno engine's own SMALL-BLOCK HEAP FREELIST PUSH
   (`mov [edx],eax`, fd->bk=bk) with edx=0x40a998 = a VMT code-table
   address: the engine's heap bucket heads (globals at 0x49d41c/420/46c/
   470/478) were corrupted EARLIER, and eax=0x2e ('.') is the garbage
   "header" it read. On the winnux32/qemu path the same runaway write
   also hits OUR host brk (registry key structs caught by the new child_find
   "HK" tripwire: `reg: CORRUPT child chain`). Binary CAPTURED + full decode
   in /home/z/my-project/engine-forensics/ (WINNUX_KEEP_TEMP=1 keeps temp
   artifacts). Session 12 also landed the Windows-contract fixes that were
   provably wrong before (Global heap GMEM_MOVEABLE model with opaque
   handles + lock-stable semantics, LoadResource returning a REAL HGLOBAL,
   HRSRC as opaque wn_handle values, registry key zombies, foreign-handle
   guards in GlobalFree/GlobalReAlloc) — the crash persists, so the
   remaining writer is something else. NEXT: qemu -g + gdb breakpoint at
   0x401bb7, watchpoint the bucket table ds:0x49d478, walk back to the
   first corrupting write; suspect list: an API returning a buffer the
   engine frees into its own heap, or a size-mismatched out-write.
2. DONE (session 12, moved to STATUS.md): nested-walk guard — a
   per-thread g_seh32_walk_active cap refuses re-entrant seh32_dispatch on
   BOTH engines (x64 wow64 + native i386), and capped raises during an
   unwind reuse the pending continuation (x64: thunk exit path; i386:
   wn_seh32_land trampoline) instead of crashing the walk.
3. GetSystemMenu/DeleteMenu (stub32) — implement real menu-object stubs so
   Inno's TApplication setup path is faithful; EnumFontsA (gdi32 stub)
   likely harmless (installer proceeded past it).
4. Session-11 wow64 width-bug pattern: audit the REMAINING struct
   readers/writers in user32.c/gdi32.c/shell32.c for compile-time
   `#if __x86_64__` layout picks (the same class caused: MSG stack smash,
   RegisterClass garbage name, WFMO zombie hang, GWL_WNDPROC host-ptr
   jump). grep __x86_64__ per file and check each against wn_wow64_guest32.

## P0 — 32-bit (i386): real-hardware bring-up (user priority)

Console-class PE32 now runs end-to-end (session 7: modify_ldt check,
wn_abiword width pass, FILE stride, MSG overlay, wsprintf/onexit/
localtime/qsort — all qemu-verified, 64-bit 16/16). Session 10 fixed the
guest-AV crash class (NULL static-TLS block at the first threadvar access:
pre-entry loader-contract guarantee + honest seh read/write reports).
Next:

0. MSVC C++ EH: _CxxThrowException unwinding (scope tables, catch matching,
   __CxxFrameHandler on i386 via fs:0 chain, x64 via .pdata) — 7zr.exe
   archive completion is blocked on it (currently a clean loud exit).
0a. 7zr.exe i386 finish: after C++ EH, verify the full create+extract
   roundtrip; watch the 1GB mapping it takes (LZMA dictionary sizing?).
0b. LuaForWindows on native hardware (user): session 10's pre-entry TLS
   guarantee heals (and NAMES — WARN/ERR log lines) the index-slot/block
   loss that killed exe+0x4325. If it still crashes with no repair line,
   the honest crash report + WINNUX_LOG=debug pre-entry state line is the
   evidence to send back. Past that: window creation, Inno dialog
   rendering, /SILENT CLI mode.

1. **User's Arch box validation (NEXT)**: rebuild (`make winnux32`) and
   rerun LuaForWindows. Two outcomes: (a) a "loader: pre-entry repair"
   WARN line → send it back, it names the broken link for a real root
   cause fix; (b) no repair line + still crashing → send the new report
   (it now says read/write correctly and prints module+RVA twice).

2a. **i386 WinMain-CRT exit crash (NEXT, precise repro)**: `gui32.exe`
   (mingw i686, WinMain entry — scripts/gui32.c) crashes after WinMain
   returns: SIGSEGV si_addr=0xfffffffc (a [reg-4] deref, reg=0 — smells
   like the frame-based SEH chain walk on a NULL fs:0 registration list,
   or a CRT exit handler deref). Evidence: (a) the SAME source built
   with main() instead of WinMain exits CLEANLY; (b) console torture32
   (main) exits cleanly; (c) crash reproduces with AND without X11
   display — so it is NOT in the GUI/pump path, it is in the CRT exit
   path after WinMain; (d) our SEH signal handler itself dies before
   logging ANYTHING for this fault (second SIGSEGV, si_code=SI_KERNEL)
   — handler-on-i386 hardening needed too (dispatch_veh /
   crash_report's 64-bit-shaped wn_exc_record/wn_context64 handed to
   the guest's 32-bit SetUnhandledExceptionFilter proc 0x40a9afa0 is
   the prime suspect for the handler-death). Build the repro with
   toolchain/root/usr/bin/i686-w64-mingw32-gcc-posix -mwindows, run
   under scripts/dev/run32.sh.
2b. **32-bit GUI structures beyond MSG**: TVITEM/DRAWITEMSTRUCT/
   NMTREEVIEW/WINDOWPLACEMENT + WNDCLASSEX remaining fields are still
   x64-shaped. Fill_msg/RegisterClass/Dispatch/IsDialogMessage/proc
   typedefs are done; the rest of the dialog+control read paths need
   the same dual-layout treatment (pattern: wn_abiword + arch #if).
   ALSO: 32-bit X11 for local GUI testing — extract libx11-6:i386 +
   deps into toolchain/root32 (apt-get download by pool URL), then
   qemu can run 32-bit GUI apps.
3. **Stub arg-count metadata for stdcall i386**: unimplemented imports
   leak the caller's arg frame (real exports are fine — their convention
   is compiled in). A per-export arity table for the top ~50 stubs
   covers the rest. Evidence: stub trace in torture32 pre-fix.
4. **time_t width on i386**: time(&t)/ctime with legacy MSVC i386
   time_t (4 bytes) writes 8 — mingw (64-bit time_t) is fine; add
   _time32 variants if a real app needs them.

## P1 — make PuTTY OPEN an SSH session

4. **Open-button launch path**: WM_COMMAND(BN_CLICKED, id=1009) reaches
   putty's dlgproc (proven) and the config dialog now works end-to-end
   (tree + Session panel). Drive it: type a hostname, click Open, trace
   the session-thread creation to the terminal window.
5. **Terminal window**: putty's terminal class + per-line text output;
   the FreeType mono path is ready.
6. **SysLink control class** (About box web link) — the ShellExecute side
   now works (xdg-open); the control itself still falls back.

## P2 — major features

7. **SEH scope-table dispatch** (x64): RtlVirtualUnwind exists; the
   DISPATCH loop (call __C_specific_handler filters/handlers from a
   guest SIGSEGV) is what's missing. Test: mingw __try/__except.
8. **Vulkan surface + swapchain** (Xlib WSI, dlopen'd), then D3D9-on-
   Vulkan start.
9. **OpenGL/WGL over EGL/GLX** (dlopen libGL/libEGL).
10. **Wayland surface path**: xdg_shell + shm present + seat input.
11. **Audio**: winmm waveOut + XAudio2 over PipeWire/Pulse/ALSA (dlopen).
12. **Console improvements**: real console buffer + ReadConsoleW/
    WriteConsoleW (line editing for CLIs).

## P3 — breadth

13. msvcrt gaps: _beginthreadex (7zr), signal/raise, __dllonexit,
    _XcptFilter, _except_handler3 (32-bit). (_onexit, qsort, strupr/
    strlwr, localtime/gmtime family landed in session 7.)
14. ws2_32: getaddrinfo/getnameinfo (AI), WSAAsyncSelect via window
    messages.
15. wininet/winhttp REAL over ws2_32 (curl.exe test app).
16. Chocolate Doom + SDL2 (software renderer) + Freedoom: SDL2.dll shim.
17. Registry: RegEnumKeyA/W, RegDeleteKey, RegQueryInfoKey completeness.
18. Files: FindFirstFileExW, GetFileAttributesEx, FILE_FLAG_* semantics.
19. Performance: PE map cache, futex batching, GDI present blits.
