# STATUS.md — the honest ledger

Updated every session. Format: what works (with the test that proves it),
what is broken, what is untested, what is next. Never claim success that was
not observed.

## Date: 2026-10-17 (session 2)

### Portability fix (user-reported: first build on GCC 15 failed)

* Building on a user machine with GCC 15 tripped
  `-Werror=discarded-qualifiers` in msvcrt.c: GCC 15 const-propagates the
  first argument's qualifier into `strchr`/`strrchr`/`strstr` builtin return
  types, so returning them as `char *` (the MSVC CRT contract:
  const-in/mutable-out) became an implicit const-discard. Fixed with
  explicit casts + a comment explaining the intent.
* Audited the whole tree for the same class: every other strchr-family
  use stores into `const char *` or a boolean context — safe on any GCC.
  `calloc` argument orders audited too (no transposed-args sites).
* Verified after fix: clean full rebuild, 13/13 tests on GCC 14.2 (Debian).

## Date: 2026-10-17 (session 1, part 3)

### Working — proven by `make test` (13/13 pass)

| Area | Proof |
|------|-------|
| PE32+ loading (map, relocs, imports, TLS, protections) + recursive PE DLL loading | all tests; t08 loads real `libwinpthread-1.dll` |
| ms_abi ABI bridge, TEB/PEB/GS-base, LDR lists | all tests |
| Console I/O + in-tree printf engine (MS-ABI varargs) | t01, t02 |
| args/env/CWD, GetCommandLine | t03 |
| Files (CI-reopen, delete, size, seek) | t04 |
| Directories + FindFirstFile (Windows dot semantics) | t05 |
| Threads + critical sections | t06 |
| Events/semaphores/WFMO/recursive mutex | t07 |
| Static `__thread` TLS + Tls API | t08 |
| Module APIs | t09 |
| VirtualAlloc/Protect/Query/Free + heap | t10 |
| **GUI vertical slice: X11 via dlopen, window, message loop, WM_PAINT, GDI FillRect/TextOut (server-rendered fonts via glyph cache), timers, destroy** | **t11 under Xvfb** |
| Winsock (TCP roundtrip, select, nonblocking) | t12 |
| Guest crash handling: SIGSEGV → EXCEPTION_ACCESS_VIOLATION report (module+rva, registers) + exception-code exit | t13 |

### Sockets (new this session)

* ws2_32 builtin over host BSD sockets: socket/bind/listen/accept/connect/
  send/recv/shutdown/closesocket, ioctlsocket FIONBIO, select with the
  **Windows fd_set layout** (count + SOCKET array, translated to host
  fd_set and back), __WSAFDIsSet, inet_addr/ntoa, gethostbyname,
  WSAStartup. SO_REUSEADDR on stream sockets matches Windows rebind
  behavior. **Proof: t12 — in-guest TCP server+client roundtrip with
  select() and nonblocking accept: 12/12 suite pass.**

### GUI architecture (as of this session)

* `src/backends/`: backend abstraction; X11 implemented with **zero X11
  headers** (dlopen + dlsym + wire-ABI overlay structs). Text rendering
  draws glyphs server-side into a scratch pixmap and reads them back with
  XGetImage — real fonts, no font library linked.
* user32: classes, windows, message queue (eventfd wake), timers,
  keysym->VK translation, DefWindowProc.
* gdi32: DCs over software BGRA buffers; window DIB layout == X11 32bpp
  ZPixmap, so present() is zero-conversion.
* Wayland: hand-marshalled wire protocol; display connect + registry +
  sync roundtrip verified; surface path (xdg_shell/shm) in progress —
  init() currently fails honestly and the selector falls back to X11.

### Broken / partial (unchanged from part 2 unless noted)

- SEH table-based unwinding (x64 .pdata/.xdata) still not implemented;
  guest `__try`/`__except` will not find scope handlers. Crash capture,
  VEH and the Windows-style report ARE proven (t13). POSIX truncates
  guest exit codes to 8 bits (0xC0000005 shows as 5) — same as Wine.
- MessageBox, dialogs, child windows, scrollbars: not implemented (stubs).
- Graphics: only software rendering; Vulkan loader present but no
  D3D/GL translation yet (`make bench` reports what exists).
- musl build not attempted.

### Environment notes

* Xvfb started automatically by the test runner for GUI cases.
* ASan found and we fixed: missing msvcrt export terminator, stub-info
  realloc use-after-free, XImage ABI offsets (my overlay struct had
  wrong member alignment), GetMessage timer starvation (pure pump(-1)),
  double-free in DestroyWindow.

### Fuzzing + bench (this session)

* `make fuzz`: fork-based mutation fuzzer over the PE loader core
  (map + relocations + export resolution + unmap), built against the
  ASan/UBSan objects. Campaign: 11 seeds x 1000 mutations = **22,000
  inputs, zero crashes**; malformed inputs are rejected loudly and
  cleanly (see the log spam in the runner for examples).
* `winnux bench` now measures real things: pe-map+reloc 34-36 us/image
  (3.4-3.6 GB/s), futex no-op wake ~0.15 us, checksummed memset ~7 GB/s.
* Vulkan: dlopen + two-stage entry resolution (global then instance
  level) implemented and exercised — vkCreateInstance returns
  VK_ERROR_INCOMPATIBLE_DRIVER on this box (no ICD), which is the honest
  result; the code path is proven by the raw-loader probe test. Surface
  + swapchain follow.

### Next

1. Wayland surface path (xdg_shell + shm present + seat input).
2. SEH x64 table-based unwinding (.pdata/.xdata) so guest `__try`/`__except`
   scope handlers actually run (crash capture already works).
3. Vulkan surface (Xlib) + swapchain once a GPU/ICD is available; D3D9
   translation start (shader decode can be developed headless).
4. Real-world app testing (Notepad-class tools, installers).
