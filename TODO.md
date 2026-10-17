# TODO.md — the prioritized backlog

Order = what real apps import/hit most. Every entry carries the evidence that
put it here. Never silently drop items; move them to STATUS.md when done.

## P0 — unblocks real apps right now

1. **Dialog engine** (user32): CreateDialogParamA/W, DialogBoxParamA/W,
   DLGTEMPLATE/DLGTEMPLATEEX parsing, dialog message proc, IsDialogMessage,
   EndDialog. Evidence: putty.exe config dialog is a dialog + child controls;
   `[stub] CreateDialogParamA` in every putty run.
2. **Child control window classes** (user32): "Button", "Edit", "Static",
   "ListBox", "ComboBox", "ScrollBar" + comctl32 "SysTabControl32",
   tooltips. Evidence: putty config dialog is built from these.
3. **user32 surface putty needs**: LoadCursorA, LoadIconA, SetWindowLongPtrA/
   GetWindowLongPtrA, SetWindowPos, MoveWindow, GetDlgItem, SetDlgItemText,
   EnableWindow, IsDlgButtonChecked, CheckRadioButton, menus
   (CreateMenu/AppendMenu/TrackPopupMenu), GetSysColor/Brush, GetSystemMetrics,
   SystemParametersInfoA, keyboard state (GetKeyboardState, ToAsciiEx).
4. **gdi32 font/text batch**: CreateFont(Indirect)A, GetTextMetricsA,
   GetTextExtentPoint32A, ExtTextOutA, SetTextAlign, GetCharWidth32.
   Evidence: putty terminal rendering is text-based; stubs in every run.

## P1 — next milestone (SEH table unwinding)

5. **x64 SEH unwinding** (.pdata/.xdata): RtlLookupFunctionEntry,
   RtlVirtualUnwind, RtlUnwind/RtlUnwindEx, RtlCaptureContext (in ntdll or
   kernel32 re-export). Guest `__try/__except` + CRT abort/terminate paths
   depend on it (putty's abort() walked exactly these stubs).
   SEH opcodes: pushnonvol, allocsmall/large, setfpreg, unwindsave...
6. **Resource loading** (kernel32): FindResourceA/LoadResource/LockResource/
   SizeofResource over PE .rsrc (putty embeds its dialogs as resources;
   version.dll can then read VS_VERSIONINFO too).

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
