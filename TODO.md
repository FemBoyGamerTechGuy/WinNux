# TODO.md — the prioritized backlog

Order = what real apps import/hit most. Every entry carries the evidence that
put it here. Never silently drop items; move them to STATUS.md when done.

## P0 — make PuTTY's config dialog USABLE (next user-visible milestone)

1. **Dialog visual fidelity**: per-control painting (Button with border +
   check state, Edit with sunken border + text, Static text layout,
   ListBox with item list + selection, ComboBox), dialog background
   GetSysColor(COLOR_BTNFACE), font-accurate text layout. Evidence:
   putty config dialog is mapped but controls draw as flat boxes; the
   xtree screenshot shows only gray/white/black.
2. **End-to-end dialog interaction**: click → WM_COMMAND to the dlgproc
   (BN_CLICKED with control id), keyboard focus ring, list selection
   messages, then verify putty's Category tree + Session list + host
   name edit box respond. Evidence: putty's modal loop runs but no
   WM_COMMAND routing proof yet.
3. **PuTTY SSH session start**: once the dialog works, Open button →
   winsock connect path (ws2_32 is proven; needs the terminal window +
   per-character rendering). This is the acceptance target from the task
   brief ("PuTTY config dialog complete, can initiate SSH connection").
4. **user32 surface still stubbed that putty hits**: menus
   (CreateMenu/AppendMenu/TrackPopupMenu — putty's system menu),
   GetSysColor/Brush batch, GetSystemMetrics completeness, monitor APIs
   (GetMonitorInfoA/MonitorFromWindow), SystemParametersInfoA,
   keyboard state (GetKeyboardState, ToAsciiEx/ToUnicodeEx), FlashWindowEx.
   Evidence: STUB lines in the putty trace (info level).

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

7. **32-bit (WoW64-style) PE support** — user-reported: a 32-bit installer
   fails with "i386 images not supported yet". Requires: PE32 header path,
   32-bit thunks (WOW64 segment emulation on x86_64 via __builtin_ia32... is
   NOT possible directly — plan: load 32-bit images and run them with a
   32-bit thunk layer using X32 or an interpreter; realistically: a separate
   32-bit helper process (like real WoW64), or restricting to CPUs with
   X32-ABI support). This is a MAJOR project; tracked after SEH per the
   task brief. `winnux imports` already parses 32-bit import tables
   (7zr.exe is the first driver case).
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
