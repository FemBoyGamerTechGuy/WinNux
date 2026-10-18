## Date: 2026-10-18 (session 6)

### The PuTTY config box is now the REAL dialog

The category pane root cause was found by downloading putty 0.85's source
(the config box is built around a **SysTreeView32** that putty creates
dynamically — our unknown-class path returned 0 **silently**, so the pane
was empty). Three fixes landed:

1. **SysTreeView32 builtin control class** (user32): TVM_INSERTITEM/
   GETITEM/SETITEM/GETNEXTITEM/SELECTITEM/EXPAND/GETCOUNT/GETITEMRECT,
   TVN_SELCHANGED notifications (synchronous WM_NOTIFY, exactly how
   Windows delivers them inside TreeView_SelectItem), painted tree with
   +/− boxes and selection highlight, click + arrow-key navigation.
2. **The Win64 TVI_* sign-extension trap**: putty passes TVI_ROOT as
   0xFFFFFFFFFFFF0000 (it is `(HTREEITEM)(ULONG_PTR)-0x10000`); our
   zero-extended 0xFFFF0000 constant rejected every ROOT insert, so the
   walk degenerated and Session/Terminal/Window/Connection vanished.
   Found by disassembling the TVI_ROOT immediate in putty.exe. With the
   fix the tree is EXACTLY real putty's: Session->Logging,
   Terminal->Keyboard/Bell/Features, Window->Appearance/Behaviour/
   Translation->Copy/Selection/Colours, Connection->Data/Proxy/SSH->
   Kex/Host keys/Cipher/Auth->Credentials/GSSAPI/TTY/X11/Tunnels/Bugs/
   More bugs/Serial/Telnet/Rlogin/SUPDUP — and the initial selection is
   **Session** (Host Name panel), like Windows.
3. **BS_GROUPBOX is 0x7, not 0x5** (0x5 is BS_3STATE — our comment lied).
   Group boxes now paint their frame+label directly onto the PARENT
   canvas with a transparent interior (Windows composes them last, top
   of the sibling z-order; blitting their opaque child surface covered
   the fields — the "gray overlay boxes"). VLM-verified: Host Name,
   Port, Connection-type radios and the Saved Sessions list are all
   visible in the Session panel.

Also fixed this session (user-reported): the **EMFILE registry failure**
(ensure_gui never set state=1 on success — every CreateWindowEx re-ran
wn_backend_init and LEAKED an eventfd; ~1 per dialog item, putty's fds
were at 72 while idle → now 5), **& accelerator prefixes** (DrawText now
parses '&x'/'&&' unless DT_NOPREFIX; "Cate&gory:" renders correctly),
**ShellExecuteA/W/Ex** (URLs/files via xdg-open, .exe/.bat re-launch
through our own loader; putty's About-box link previously failed with
SE_ERR_NOASSOC), and **resize hardening** (XSetWMNormalHints min==max
for windows without WS_THICKFRAME — X11 WMs resize anything, Windows
dialogs are fixed; plus gdi32 window DCs re-bind their pixel buffer
lazily in gdi_get() so a DC held across a resize cannot draw through
freed memory).

### 32-bit (i386): the loader, the build, and the re-exec — all landed

`winnux run app.exe` on a PE32 (i386) image now re-execs **bin/winnux32**
(a complete i386 build of the runtime). Everything statically verifiable
is verified on this box; RUNTIME verification needs a machine whose
kernel allows 32-bit syscalls (this container's seccomp kills ANY
i386 code — even a static exit(42) — with SIGSYS; the user's Arch box
runs it fine):

- **PE32 parsing is real**: `winnux imports 7zr.exe` walks all 6
  sections and classifies every import (previously rejected at the
  machine check). A mingw-i686-built test exe parses with **50/50
  imports OK, zero stubs**.
- **make winnux32 links**: ELF 32-bit LSB executable. Verified IN THE
  BINARY: stdcall `ret N` sequences in the exports (compile-time
  convention dispatch — Wine's model), the i386 stub trampoline bytes
  (push info/jmp; pop eax; 6 cdecl args; plain ret), `modify_ldt`
  (push 0x7b) + `mov fs,eax` (TEB hosting via LDT — glibc owns %gs).
- **i386 TEB/PEB/LDR/critsect layouts** with per-arch _Static_asserts
  (fs:0x18 self, fs:0x2C TLS, fs:0x30 PEB, fs:0x34 last error).
- **msvcrt is cdecl (WN_CRTAPI) + varargs decode is per-bitness**
  (4-byte slots, 8-aligned doubles on i386); the __p__* mingw startup
  family (__p__iob/__p__fmode/__p__commode/__p___initenv/
  __p___mb_cur_max/__lc_codepage) is implemented — every i686 mingw
  exe calls them at startup.
- **Toolchain discovery in the Makefile**: native -m32 (Arch needs the
  **[multilib] repo enabled in /etc/pacman.conf** first —
  `sudo pacman -Ss gcc-multilib` finds nothing without it — then
  `pacman -S gcc-multilib lib32-gcc-libs`), or a local sysroot
  (WINNUX_M32_SYSROOT; this dev box uses extracted glibc32 debs).

Honest limits: 32-bit GUI structures (MSG/TVITEM/DRAWITEMSTRUCT ...) are
still x64-shaped — the i386 milestone is console-first (7zr.exe is the
acceptance case). The stdcall STUB path (unimplemented imports only)
cannot pop the guest's args without per-export arg-count metadata —
real exports carry their convention at compile time, so only missing
APIs leak a frame per call.

### Regression status

15/15 tests. putty: tree renders with all categories, Session panel
selected, panels switch on click/keys (VLM-verified screenshots),
zero queue overflows, 5 fds. x64 build zero warnings; the whole tree
compiles -m32 with the same flags and links bin/winnux32.

# STATUS.md — the honest ledger

Updated every session. Format: what works (with the test that proves it),
what is broken, what is untested, what is next. Never claim success that was
not observed.

## Date: 2026-10-18 (session 5)

### The user's bug list: fixed and verified

All five issues from the user's run were reproduced locally under Xvfb
(synthetic clicks via the rebuilt `scripts/dev/xtree.c`), root-caused, and
fixed:

1. **`user32: message queue overflow (dropped 0x5/0xf/0x200)` spam —
   GONE.** Root cause: putty's layout code posted WM_SIZE+WM_PAINT per
   MoveWindow (3 queue slots × ~50 controls) and every WM_MOUSEMOVE went
   into a fixed 128-slot ring, so real input got DROPPED. Fixes, matching
   Windows semantics: WM_SIZE/WM_MOVE are now DELIVERED SYNCHRONOUSLY from
   inside MoveWindow/SetWindowPos (never queued); WM_PAINT is only ever
   synthesized from the per-window dirty flag by the pump (direct posts
   removed everywhere); WM_MOUSEMOVE coalesces in place (newest position,
   queue order kept); the ring grows 128→8192 if a burst survives
   coalescing; PeekMessage honors PM_NOREMOVE and pumps input (modal
   loops used to starve the whole input path). Evidence: putty soak now
   logs ZERO overflow lines.
2. **The About-button segfault — FIXED.** Reproduced exactly (same
   backtrace as the user). Chain: dialogs passed an owner as "parent"
   were created as CHILD windows; u32_ShowWindow then called the backend's
   win_show on a child's bwin (priv=NULL) → SIG11 in x11_win_show.
   Dialogs are now top-level OWNED popups (WS_CHILD decides child-vs-
   owned, per Windows), with owner-relative template positioning
   (DS_ABSALIGN honored). The About box opens as its own X11 window
   (540x544), survives interaction, and closes cleanly via the
   WM_DELETE_WINDOW ClientMessage (xtree `close`) — the full modal
   lifecycle (open → interact → close → owner re-enabled) works.
3. **`wship6.dll / hhctrl.ocx / shcore.dll not found` — GONE.** All three
   are builtins now (auto-placeholders in drive_c/windows/system32):
   wship6 = getaddrinfo/freeaddrinfo/getnameinfo over the host resolver
   with the addrinfo list deep-copied and **AF_INET6 translated
   (Linux 10 → Windows 23)**; shcore = SetProcessDpiAwareness/
   GetDpiForMonitor/GetScaleFactorForMonitor; hhctrl = loud honest
   HtmlHelp stubs.
4. **`EnableWindow` / `MessageBeep` STUBs — real.** EnableWindow sets
   WS_DISABLED, moves focus away, returns the previous state, and the
   input path now IGNORES clicks on disabled windows (the hit-test skips
   them; that is why putty's owner must be disabled during modal About).
   MessageBeep rings XBell through a new backend `beep` op.
5. **`registry: cannot save .../system.reg` — hardened.** The save is now
   atomic (tmp + rename, crash-truncation impossible) and reports errno
   with the REASON on failure; a stale/protected destination gets an
   unlink+rename retry. Not reproducible here (saves work locally) —
   if it still fails on the user's box, the log will now say exactly why
   (most likely EACCES from a prefix created by an earlier root run).

### PuTTY's config box now places itself correctly

Monitor/DPI APIs are real: GetSystemMetrics (full metric table),
MonitorFromWindow/Rect/Point (POINT BY VALUE — the 8-byte struct arrives
packed in RCX under the MS x64 ABI; a naive (x,y,flags) signature reads
y from RDX), GetMonitorInfoA/W, EnumDisplayMonitors, SystemParametersInfo
(SPI_GETWORKAREA), GetDpiForWindow/System, SetProcessDPIAware,
ScreenToClient/ClientToScreen, GetParent, GetWindowPlacement/
SetWindowPlacement. Two blockers found on the way: top-level windows
never had cw/ch set (GetWindowRect returned 0-size → putty center
shrank the box to 1x1), and the desktop pseudo-window was hardcoded
1280x800. Both fixed — putty's `centre_dialog(GetDesktopWindow())` now
centers the config box EXACTLY: 600x1008 at (660,36) on 1920x1080.

### Text is now FreeType-rendered (the "readable but not great" fix)

New `src/gfx/font_ft.c`: libfreetype.so.6 is dlopen'd at runtime (zero
compile-time deps, per project rules) and glyph structs are accessed via
hand overlays whose offsets were PROBED against the real headers
(FT_FaceRec.glyph@0x98, size@0xA0; GlyphSlot advance@0x80, format@0x90,
bitmap@0x98, bitmap_left@0xC0). Nothing is trusted blindly: init renders
'A', then locates the glyph-slot/size pointers by structural signature,
with every candidate pointer validated against a /proc/self/maps
snapshot (refreshed per scan — a stale snapshot made verification flaky).
On any mismatch we fall back to the embedded bitmap atlas and log it.
Rendering: alpha-blended glyphs, per-glyph advances, surrogate pairs,
family matching (Courier New/Consolas→mono, Times→serif, everything else
sans; DejaVu/Liberation/Free/Noto probed on Arch and Debian layouts),
bold/oblique variants with double-strike synthesis when only regular
exists. GetTextMetrics/GetTextExtentPoint use REAL metrics (ascent/
descent from the face; tmAveCharWidth = the 'x' advance — a face's
max_advance is a lie, DejaVu Bold reports 4129 units = 2× the em).
Also fixed on the way: XGetWindowAttributes wrote a ~136-byte struct
into a 24-byte overlay (stack smash in x11_init — the wild-pointer
crashes of the "1x1 config box" hunt).

### Interaction API batch (user32)

InvalidateRect/ValidateRect (dirty-flag semantics), GetSysColor/
GetSysColorBrush (classic palette), GetCursorPos/GetKeyboardState/
SetKeyboardState/GetKeyboardLayout/GetQueueStatus/GetMessageTime/
GetDoubleClickTime/GetCaretBlinkTime/IsIconic/IsZoomed/FlashWindow/
SetForegroundWindow, caret family (CreateCaret/SetCaretPos/ShowCaret/
HideCaret/DestroyCaret), FindWindowA, LoadImageA(icons), DestroyIcon,
DrawEdge (gdi32: real 3D borders), MsgBoxIndirectW, W-variants for
message/dispatch/text APIs, SendDlgItemMessageA/W, Get/SetDlgItemText,
MsgWaitForMultipleObjects (queue-aware wait with 0-timeout handle
probes through the sync engine). Push buttons now draw 3D frames +
dotted focus rects; disabled controls paint gray text (COLOR_GRAYTEXT).

### Dialog-engine fixes found by the About-box screenshots

DS_SETFONT dialog templates carry a font section after the title
(pointsize + fontname, plus weight/italic/charset in EX form) that the
item parser did not skip — every item after the first misaligned, which
is why putty's About box created only 2 controls and rendered no text.
With the skip: the About box renders its full text (595 dark + 1532
antialiased pixels measured in the region). Top-level windows also
honor their requested creation position now (X windows were born at
(0,0); the About box lands at (280,160), fully on-screen).

### 32-bit (WoW64) groundwork — source-level

`make check32` compiles the whole tree with -m32 (i386) when a multilib
toolchain exists (this container lacks 32-bit libc headers; the target
prints install hints and skips — it will run on the user's Arch box
with gcc-multilib). WN_API maps to cdecl on i386 for now; the x64-only
asm blocks (stub trampoline, RtlCaptureContext, _setjmp/_longjmp,
gs-TEB access) are guarded with i386 variants or compile-stubs, so the
tree stays buildable on both. What 32-bit STILL needs before a single
32-bit exe runs (documented in TODO P2): per-export stdcall/cdecl
dispatch metadata (Win32 i386 APIs clean the stack; varargs are cdecl),
i386 TEB/PEB layouts + a set_thread_area TLS scheme (gs:0x30 → fs:0x18),
i386 CONTEXT/EXCEPTION layouts for SEH, and a separate 32-bit build of
the runtime (Wine's model: 32-bit process, 32-bit X11 via dlopen).

### Regression status

15/15 tests (t14/t15 updated: wship6 is now a real DLL so the
missing-DLL test uses a permanently-missing name; text-extent checks
accept proportional metrics). lua.exe and sqlite3.exe re-verified.
Putty: 40s ASan soak clean (x2); interactions verified via xtree
(clicks, key typing, About modal cycle, WM_DELETE close). ASan exit-time
notes: memory CORRUPTION is zero everywhere; LeakSanitizer still flags
the per-thread TEB allocation (24B, freed-never at process death —
freeing it inside wn_process_exit is riskier than the leak) — the
exe_path strdup leak from cmd_run was fixed. Known gaps: putty's
Open button fires WM_COMMAND(BN_CLICKED) into its dlgproc but no
session launch follows (next session's target: trace the wndproc path
from WM_COMMAND to launch — likely needs the config→registry save and
the launch-thread flow); SysLink control class unknown (About box link
falls back); X11 clipboard/menus remain stubs.

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
