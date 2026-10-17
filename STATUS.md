# STATUS.md — the honest ledger

Updated every session. Format: what works (with the test that proves it),
what is broken, what is untested, what is next. Never claim success that was
not observed.

## Date: 2026-10-17 (session 1, part 2)

### Working — proven by `make test` (10/10 pass)

| Area | Proof |
|------|-------|
| PE32+ loading (map, relocs, imports, TLS dir, protections) | every test runs a real mingw-w64 exe |
| PE DLL recursive loading (import DLLs from app dir) | t08 loads a real `libwinpthread-1.dll` |
| ms_abi ABI bridge (guest calls builtins directly) | all tests |
| TEB/PEB/GS-base, LDR lists | t03, t09 |
| Console: WriteFile, WriteConsoleA, printf family (in-tree formatter with MS-ABI varargs decode) | t01, t02 |
| argc/argv/env, GetCommandLine, GetEnvironmentVariable, CWD | t03 |
| Files: create/read/write/CI-reopen/DeleteFile/GetFileSize/seek | t04 |
| Directories + FindFirstFile/FindNextFile (Windows dot semantics) | t05 |
| Threads: CreateThread/exit codes/WaitForSingleObject | t06 |
| Critical sections (contended, 4x1000 ops) | t06 |
| Events (auto/manual), semaphores, WFMO(any), recursive mutex | t07 |
| Static TLS (`__thread`) + TlsAlloc/GetValue/SetValue cross-thread | t08 |
| GetModuleHandle/LoadLibrary/GetProcAddress/GetModuleFileName | t09 |
| VirtualAlloc/Protect/Query/Free + HeapAlloc loops (10k) | t10 |
| SEH: signal capture -> VEH dispatch -> Windows-style crash report | crash reports observed; VEH used by CRT |
| Loud stubs with call-site resolution (never fake success) | seen live (DuplicateHandle before it was implemented) |
| Registry: file-backed tree + advapi32 basics | manual smoke (RegOpenKey/SetValue) |

### Also observed working (not yet a named test)

- `winnux --version`, `winnux run` CLI, WINNUX_LOG/TRACE env knobs
- Crash-proof stub call reporter (raw-syscall first line)

### Broken / partial

- **SEH table-based unwinding (x64 .pdata/.xdata) not implemented** —
  `__try`/`except` in guest code will not find handlers; unhandled guest
  exceptions produce a crash report + exit code (no `RtlUnwind`).
  `__C_specific_handler` returns CONTINUE_SEARCH (logged).
- `SignalObjectAndWait`, APCs, `SetStdHandle` unimplemented (stubs).
- Console input: ReadConsole works raw; no line editing/echo emulation.
- Named kernel objects share one namespace but no cross-process sharing.
- `SuspendThread` races documented in thread.c (SIGUSR1-based).
- musl build not attempted yet.

### Environment notes

* mingw-w64 14.2 extracted locally under `/home/z/my-project/toolchain/root`
  (no root on this box) — used ONLY to build test binaries.
* Xvfb + libX11 + libvulkan present — GUI milestone testable here.
* ASan/UBSan build (`make debug`) catches loader bugs: it found and we fixed
  a missing export-table terminator and a stub-info realloc use-after-free.

### Next

1. Fuzz the PE loader under ASan (tests/fuzz) + fix everything found.
2. X11 backend (dlopen libX11) + user32/gdi32 vertical slice under Xvfb.
3. Wayland backend (hand-marshalled wire protocol).
4. Vulkan loader + surface + bench; D3D9/GL translation begins.
5. Real-world app testing (Notepad-class tools, installers).
