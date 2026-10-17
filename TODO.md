# TODO.md — the prioritized backlog

Order = what real apps import/hit most. Every entry carries the evidence that
put it here. Never silently drop items; move them to STATUS.md when done.

## P0 — make PuTTY OPEN an SSH session (next user-visible milestone)

1. **Open-button launch path**: WM_COMMAND(BN_CLICKED, id=1009) is PROVEN
   to reach putty's PuTTYConfigBox dlgproc (ctl_notify trace) but nothing
   launches. Disassemble the dlgproc WM_COMMAND handler (image base
   0x140000000; the Open handler is the next thing to map), find the call
   that fails silently (suspects: config save to registry, CreateThread
   for the session, terminal window creation on the launch thread, socket
   events), and drive it to a live terminal window. Hostname typing
   already round-trips (EN_CHANGE + GetDlgItemText verified).
2. **Terminal window**: putty's terminal class (W-flavored APIs — the W
   message APIs now exist) + per-line text output; the FreeType mono path
   (Courier New → DejaVu Sans Mono) is ready for the cell metrics.
3. **SysLink control class** (About box web link) — render as blue
   underlined static, NM_CLICK notify (even a no-op beat failing class
   registration, which is what happens now: unknown-class WARN).

## P1 — next milestone (SEH dispatch: scope tables)

5. **x64 SEH scope-table execution** (on top of the now-real
   RtlVirtualUnwind/RtlLookupFunctionEntry): walk frames at
   RaiseException/crash time, call __C_specific_handler filters and
   handlers, guest `__try/__except` actually catching faults. The
   Rtl* exports exist; the DISPATCH loop is what's missing.
   Test: mingw exe with __try/__except catching a deliberate AV.
6. **Resource loading** — DONE session 3 (moved to STATUS.md: FindResource/
   Load/Lock/SizeofResource walk putty's .rsrc; dialog templates resolve).

## P2 — major features

7. **32-bit (WoW64-style) PE support** — user priority. GROUNDWORK DONE
   (session 5): `make check32` compiles the tree -m32 on multilib boxes,
   WN_API is arch-mapped (cdecl on i386 for now), all x64-only asm is
   guarded (stub trampoline, RtlCaptureContext, _setjmp/_longjmp, gs-TEB
   read has an fs:0x18 i386 path). Real 32-bit exes CANNOT run yet; what
   remains, in order: (a) per-export stdcall/cdecl dispatch metadata —
   Win32 i386 APIs clean the stack, varargs are cdecl (Wine's model:
   __stdcall on fixed-arity exports); (b) i386 TEB/PEB layouts +
   set_thread_area TLS (fs:0x18 self-pointer) replacing the x64 gs:0x30
   scheme; (c) i386 CONTEXT/EXCEPTION_RECORD layouts for SEH; (d) the
   separate 32-bit runtime build (Wine model: 32-bit process, 32-bit
   libX11 dlopen'd, console-first so GUI deps stay optional). Acceptance:
   7zr.exe (32-bit, apps/) runs, then a 32-bit GUI app.
8. **Vulkan surface + swapchain** (Xlib WSI, dlopen'd), then D3D9-on-Vulkan
   start: device/present/swapchain objects, DXBC sm1-sm3 bytecode → SPIR-V
   translator (headless development possible via `winnux bench`).
9. **OpenGL/WGL over EGL/GLX** (dlopen libGL/libEGL).
10. **Wayland surface path**: xdg_shell + shm present + seat input; runtime
    auto-detect Wayland vs X11 (X11 fallback proven).
11. **Audio**: winmm waveOut + XAudio2 over PipeWire/Pulse/ALSA (dlopen);
    t-winmm test with a sine generator.
12. **Console improvements**: real console buffer + ReadConsoleW/WriteConsoleW
    (putty terminal is not a console, but CLIs want line editing).

## P3 — breadth

13. msvcrt gaps observed in real apps: _beginthreadex (7zr), signal/raise,
    _onexit/__dllonexit (7zr), _XcptFilter, _except_handler3 (32-bit),
    qsort stability nuances, _itoa/_atoi family completeness.
14. ws2_32: getaddrinfo/getnameinfo (AI), WSAAsyncSelect via window
    messages once the message pump posts custom messages.
15. wininet/winhttp REAL implementation over ws2_32 (curl.exe test app).
16. Chocolate Doom + SDL2 (software renderer) + Freedoom: needs SDL2.dll
    coverage (threads, timers, audio, surfaces, events) — plan a
    sdl2-builtin shim layer over our backends.
17. Registry: RegEnumKeyA/W, RegDeleteKey, RegQueryInfoKey completeness.
18. Files: FindFirstFileExW, GetFileAttributesEx, FILE_FLAG_* semantics.
19. Chocolatey/installer support: setupapi + msi (much later).
20. Performance: PE map cache, futex batching, GDI present blits (DMA-BUF
    when Wayland lands), shader/pipeline cache under ~/.WinNux.
