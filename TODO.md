# TODO.md — the prioritized backlog

Order = what real apps import/hit most. Every entry carries the evidence that
put it here. Never silently drop items; move them to STATUS.md when done.

## P0 — 32-bit (i386) runtime bring-up (user priority, next session)

1. **Run 7zr.exe on the user's Arch box**: `make winn32` — no:
   `make winnux32 && ./bin/winnux run 7zr.exe`. The loader, build, and
   re-exec are all in place (session 6); runtime debugging needs a kernel
   that allows i386 syscalls (the dev container's seccomp does not).
   Likely first bugs: mingw CRT startup edge cases, printf/heap details,
   handle-table 32-bit truncation. Also test the mingw-built hello32.exe
   (50/50 imports clean) and LuaForWindows_v5.1.5-52.exe (NSIS installer
   — needs more DLL coverage: setupapi/RichEdit).
2. **32-bit GUI structures**: MSG/TVITEM/DRAWITEMSTRUCT/NMTREEVIEW/
   DLGTEMPLATE32 are still x64-shaped; guard or dual-layout them.
   (i386 GUI = after 7zr/console-class apps work.)
3. **Stub arg-count metadata for stdcall i386**: unimplemented imports
   leak the caller's arg frame (real exports are fine — their convention
   is compiled in). A per-export arity table for the top ~50 stubs
   covers the rest.

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

13. msvcrt gaps: _beginthreadex (7zr), signal/raise, _onexit/__dllonexit,
    _XcptFilter, _except_handler3 (32-bit), qsort stability nuances.
14. ws2_32: getaddrinfo/getnameinfo (AI), WSAAsyncSelect via window
    messages.
15. wininet/winhttp REAL over ws2_32 (curl.exe test app).
16. Chocolate Doom + SDL2 (software renderer) + Freedoom: SDL2.dll shim.
17. Registry: RegEnumKeyA/W, RegDeleteKey, RegQueryInfoKey completeness.
18. Files: FindFirstFileExW, GetFileAttributesEx, FILE_FLAG_* semantics.
19. Performance: PE map cache, futex batching, GDI present blits.
