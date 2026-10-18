# TODO.md — the prioritized backlog

Order = what real apps import/hit most. Every entry carries the evidence that
put it here. Never silently drop items; move them to STATUS.md when done.

## P0 — 32-bit (i386): real-hardware bring-up (user priority)

Console-class PE32 now runs end-to-end (session 7: modify_ldt check,
wn_abiword width pass, FILE stride, MSG overlay, wsprintf/onexit/
localtime/qsort — all qemu-verified, 64-bit 15/15). Next:

0. MSVC C++ EH: _CxxThrowException unwinding (scope tables, catch matching,
   __CxxFrameHandler on i386 via fs:0 chain, x64 via .pdata) — 7zr.exe
   archive completion is blocked on it (currently a clean loud exit).
0a. 7zr.exe i386 finish: after C++ EH, verify the full create+extract
   roundtrip; watch the 1GB mapping it takes (LZMA dictionary sizing?).
0b. LuaForWindows on native hardware (user): the payload decompression is
   CPU-heavy under emulation; on real i386 it should reach the GUI. Watch
   for: window creation, Inno dialog rendering, /SILENT CLI mode.

1. **User's Arch box validation**: `make winnux32 && ./bin/winnux run
   LuaForWindows_v5.1.5-52.exe -e 'print(1+2*3, ("win"):upper())'` —
   qemu passed hello32/heap32/torture32, but the user's box is the
   ground truth (his kernel + real apps). 7zr.exe (console) is the
   next-best candidate. NSIS installer GUI = P0.2 territory.
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
