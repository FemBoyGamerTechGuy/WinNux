# STATUS.md — the honest ledger

Updated every session. Format: what works (with the test that proves it),
what is broken, what is untested, what is next. Never claim success that was
not observed.

## Date: 2026-10-18 (session 4)

### PuTTY STAYS ALIVE (the headline)

`winnux run putty.exe` under Xvfb now **runs until killed** (exit 124 after
a 30-40s timeout = a live GUI app in its message loop), with the
"PuTTY Configuration" dialog and "hidden timing window" mapped in the X
window tree, a QUIET log (only the three known optional-DLL notes:
wship6/hhctrl/shcore), and **40 minutes-equivalent soak: zero
AddressSanitizer/UBSan reports**. This session found and fixed the chain
that used to kill putty ~50ms after startup:

1. **gdi32 GetTextMetricsA wrote 32 bytes past TEXTMETRICA** (memset 0x58 +
   a write at offset 0x54 into a 56-byte struct). Putty's stack canary sat
   exactly after the 56-byte caller buffer → MSVC /GS failure →
   `__report_gsfailure` → `TerminateProcess(GetCurrentProcess(),
   0xC0000409 STATUS_STACK_BUFFER_OVERRUN)`. Fixed with the exact x64
   layout (tmItalic@0x30, tmPitchAndFamily@0x33, tmCharSet@0x34; total
   0x38). Found by disassembling putty's report path + stack archaeology
   (the failing function's RA and corrupted canary were recovered from the
   report_gsfailure frame).
2. **user32 LoadCursor/LoadIcon(A/W) dereferenced MAKEINTRESOURCE
   values** (IDC_ARROW = 32512 = 0x7f00 passed as a "string"). Fixed:
   `IS_INTRESOURCE` check (< 0x10000) in res_name_to_id + the W variants.
3. **IsDialogMessage had a one-arg signature** — it takes (hDlg, lpMsg);
   RCX is the dialog handle, RDX the MSG. The old code faulted reading the
   handle as the MSG pointer.
4. **loader DLL probe loop read cands[2] OUT OF BOUNDS**: when a
   LoadLibrary path had no ".dll" suffix (hhctrl.ocx), the `.dll`-append
   branch filled the last NULL slot and the loop walked one past the array
   into stack garbage (the "unreadable win-path pointer 0x6" spam).
   Fixed: cands[3] with a mandatory NULL terminator + Windows semantics
   (.dll is appended ONLY to extension-less names — "hhctrl.ocx" is probed
   as-is).
5. **MoveWindow + SetWindowPos are real now** (was a stub putty's dialog
   layout hits): child coordinates + parent recompose; top-level resize
   through a new backend op `win_move_resize` (X11: XMoveResizeWindow via
   dlsym + pixel-buffer realloc). WM_SIZE/WM_MOVE posted.
6. kernel32: **Rtl* unwinding exports** (RtlCaptureContext raw asm,
   RtlLookupFunctionEntry .pdata binary search, RtlVirtualUnwind full
   unwind-code interpreter incl. XMM saves/CHAINED opcodes, RtlPcToFileHeader,
   RtlUnwind v1 walk), **RaiseException** (real, routes through the VEH /
   crash-report path), **UnhandledExceptionFilter** (routes to the app's
   SetUnhandledExceptionFilter function). Putty's abort/SEH path calls
   exactly these.

Putty's config dialog: window + OK/Cancel buttons + controls are created
and the modal loop runs; the dialog is NOT yet visually complete (controls
draw as flat boxes; no per-control painting fidelity; keyboard nav exists
via IsDialogMessage but no end-to-end session creation yet — see TODO P0).

### Regression status this session

15/15 tests (t01-t15); lua.exe (`print(1+2*3, ("win"):upper())` → `7 WIN`)
and sqlite3.exe (`SELECT id, upper(name)` → `1|ALPHA 2|BETA 3|GAMMA`)
re-verified; putty 40s ASan/UBSan soak clean.

### The X11 input path was dead — now it is alive (same session, part 2)

Synthetic clicks (scripts/dev/xtree.c "click" mode, XSendEvent) proved the
whole X11 event path had never worked: events reached handle_event, then
vanished. Three bugs fixed:

1. **win_for compared X window IDs against stored priv POINTERS** — could
   never match, so Expose/Key/Button/Motion dispatch was all dead (painting
   worked only because generate_paints drives present() from timers).
   Fixed with a backend-local xwin→bwin map (x11_backend.c winmap_*).
2. **xkey overlay had `uint32_t time`** where LP64 X11 `Time` is 8 bytes
   (unsigned long) — every field after it shifted by 4: coordinates wrong,
   button read from `state`. Fixed: time is uint64_t, x@64/y@68,
   state@80, keycode/button@84.
3. **Dialog windows were message black holes**: class #32770 used ctl_proc
   which never forwarded to the guest dlgproc. Now every dialog message
   (WM_COMMAND from controls, WM_CLOSE, ...) is routed to putty's dlgproc;
   a synthetic click on the OK button makes putty's own handlers run
   (proven: putty called RegisterWindowMessageA + ReleaseCapture in
   direct response).

Also: WS_VISIBLE children now set their visible flag at creation
(previously only ShowWindow set it — dialog controls were invisible to
hit-testing); SetCapture/ReleaseCapture/GetCapture (mouse capture routing)
and RegisterWindowMessageA/W (ids ≥ 0xC000) are real.

**Proof of the full chain**: XSendEvent click at (80,500) → x11 trace →
user32 mouse handler (correct button + coords) → hit-test to the Button
child → WM_LBUTTONDOWN → ctl_proc → WM_COMMAND → dialog proc → guest
dlgproc → putty's handler code executes. Zero ASan/UBSan reports with
clicks; 15/15 suite.

### Part 3 (same session): dialog paints again + keyboard events arrive

- Dialog WM_PAINT is handled by the layer (face-color fill + child compose
  + present) BEFORE forwarding to the dlgproc — routing every message to
  the guest dlgproc had left nobody painting the background (putty's
  dlgproc ignores WM_PAINT like most do; DefDlgProc owns erasing).
  Screenshot now shows gray dialog + dark text pixels in the dialog
  region (xtree root capture; the PPM reader in xtree was also fixed to
  real 32bpp reads).
- Keyboard events reach the guest too (synthetic 'a' key via
  `xtree key <win> 0x61`: KeyPress/KeyRelease logged, routed to the focus
  window). Putty moved its own config dialog with our real MoveWindow —
  partially off-screen (600x1008 at 340,-104) because the monitor/DPI
  APIs are stubs; that placement (GetMonitorInfo/MonitorFromWindow/
  GetSystemMetricsForDpi) is the next visual-fidelity item.
- xtree (dev tool) gained: window geometry in the tree dump, PPM capture
  with correct 32bpp reads, synthetic click + key injection.

## Date: 2026-10-17 (session 3)

### Real applications (the headline)

| App | Result | Proof |
|-----|--------|-------|
| **lua.exe 5.4.7** (mingw build, loads lua54.dll) | **RUNS**: real language, strings, tables | `winnux run lua.exe -e 'print(1+2*3, ("win"):upper())'` → `7 WIN`; `table.concat` loops; ASan-clean |
| **sqlite3.exe 3.50.4** (mingw build) | **RUNS**: real SQL engine | `sqlite3.exe :memory: "CREATE TABLE t(...); INSERT...; SELECT id, upper(name) ..."` → `2\|BETA 3\|GAMMA`, `count/sum` aggregate — **zero stub hits**; ASan-clean; stdin script mode prints `42` |
| **putty.exe** (official x64, MSVC) | **STARTS: all 348 imports resolve; creates a window** | Xvfb window tree shows `PuTTY: hidden timing window` (scripts/xprobe); fatal box "Unable to load any WinSock library" ELIMINATED by path-aware LoadLibrary + wsock32 |
| 7zr.exe (32-bit) | analyzed only | `winnux imports` parses its PE32 import table; runtime = WoW64 TODO (P2) |

**UPDATE (same session): PuTTY's CONFIGURATION DIALOG EXISTS.** The dialog
engine landed: .rsrc resource walking (FindResourceA/LoadResource/
LockResource/SizeofResource), DLGTEMPLATE/DLGTEMPLATEEX parsing (incl. the
EX item layout and MAKEINTRESOURCE id resolution), child windows with
offscreen surfaces composed onto the parent, builtin control classes
(Button/Edit/Static/ListBox/ComboBox), DialogBoxParam modal loop. Proof:
`xprobe :95` shows `PuTTY Configuration` + the log shows its real control
tree (STATIC/EDIT/BUTTON ids 1041..1050 from the embedded template), zero
crashes; screenshot saved via scripts/xprobe. Remaining for putty: visual
fidelity (window sizing/painting), dialog message navigation, GDI fonts —
see TODO.md P0. Its abort/SEH path calls RtlLookupFunctionEntry/RtlUnwind —
confirming the SEH milestone priority.

### New: `winnux imports <exe> [-v]`

Static import analyzer for PE32+ and PE32, regular + delay-load imports;
classifies every function as ok / stub / native / native-missing / MISSING
DLL; builtin ordinal exports (`#N`) recognized. Exit 1 on missing DLL or
32-bit image. This is now the tool that drives priorities: run it on any
new app before touching code.

### New builtin DLLs (25+, proactive batch)

imm32, comctl32, comdlg32, shell32, shlwapi, ole32, oleaut32 (incl. ordinal
exports 7-Zip uses), rpcrt4 + uuid alias, version, psapi, dbghelp, setupapi,
winspool.drv/.dll, wininet, winhttp, mswsock, iphlpapi, dnsapi, crypt32,
bcrypt + cryptbase, secur32 + sspicli, userenv, uxtheme, dwmapi, winmm,
msvcp140 family (presence), wsock32 → ws2_32, api-set routing
(api-ms-win-crt-* → ucrtbase, other api-ms-/ext-ms- → kernelbase).

REAL inside them: CommandLineToArgvW (full quoting rules), SHGetFolderPath,
BSTRs/Sys*, GUID parse/format, UuidCreate (urandom), DnsQuery A/AAAA/PTR
via getaddrinfo, BCryptGenRandom/SystemFunction036 (urandom), base64
(CryptStringToBinary), psapi module enumeration, userenv environment
blocks, winmm timeGetTime. Everything else: documented honest failures
with WARN logs — never silent fake success.

### Loader + kernel32/msvcrt fixes found by real apps

- **LoadLibrary("C:\windows\system32\kernel32.dll") now works**: builtins
  match by basename; explicit paths resolve through the prefix. (This
  single bug blocked putty's winsock.)
- FLS (FlsAlloc/GetValue/SetValue/Free + thread-exit callbacks) over the
  Tls index space.
- LoadLibraryExW, GetModuleHandleExW/A (FROM_ADDRESS), GetSystemDirectory,
  GetWindowsDirectory, GetEnvironmentStringsW, Get/SetCurrentDirectoryW,
  MulDiv, InitializeSListHead, IsValidCodePage, SetConsoleCtrlHandler.
- msvcrt: ctype batch, **real `_setjmp`/`_longjmp` (raw asm, MS x64
  jmp_buf)**, fgets, _wfopen, _fileno, _isatty, _access/_waccess, _setmode,
  _time64.
- IsProcessorFeaturePresent: PF_FASTFAIL_AVAILABLE(23)=0 — returning 1 made
  MSVC's abort() fire `int 0x29` immediately.
- user32 MessageBoxA/W prints the text to the log and returns IDOK
  (diagnostic aid; the window is not fake-drawn).
- Crash report: RBP frame-chain backtrace (MSVC builds keep frame pointers).
- Out-of-bounds utf16 reads fixed (LoadLibraryW/GetModuleHandleW used the
  length parameter wrongly).

### Quality gates this session

13/13 tests; ASan/UBSan clean on the whole suite AND on real lua/sqlite
runs; fuzzing clean (600 iterations × 11 seeds after clean obj-dbg);
zero-warning build under GCC 14.2 (user's GCC 15 covered by the
discarded-qualifiers fix from session 2).

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
