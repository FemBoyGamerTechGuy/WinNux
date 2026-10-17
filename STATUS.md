# STATUS.md — the honest ledger

Updated every session. Format: what works (with the test that proves it),
what is broken, what is untested, what is next. Never claim success that was
not observed.

## Date: 2026-10-17 (session 1)

### Working

Nothing yet. Repository scaffolded, build system written, first code being
written in this session. See "In progress" below.

### In progress

* PE loader (PE32+/PE32): map, relocations, imports, exports, TLS directory.
* Windows ABI bridge: ms_abi builtin DLLs, TEB/PEB, GS-base setup.
* kernel32 + msvcrt builtin subset sufficient for mingw-w64 console
  executables (import surface measured from a real `hello.exe`).

### Broken

* (nothing yet — nothing runs yet)

### Untested

* Wayland backend: not written yet.
* Vulkan translation (D3D9/D3D11 → Vulkan): not written yet.
* musl libc build: intended, not yet attempted.
* 32-bit (PE32/i386) executables: not yet supported.

### Environment notes

* Toolchain: Debian 13, gcc 14.2 (x86_64), GNU make 4.4, git 2.47.
* mingw-w64 cross compiler extracted locally (no root available) under
  `/home/z/my-project/toolchain/root` — used ONLY to build test .exe files.
* Xvfb present: GUI tests can run against a real X server here.
* libX11.so.6 and libvulkan.so.1 present: backends can be exercised.
* No GPU: Vulkan will enumerate whatever the loader exposes (possibly
  nothing); performance claims must come from `winnux bench`, not assumptions.

### Next

1. Vertical slice: PE loader + kernel32/msvcrt console subset, run a real
   mingw-compiled `hello.exe` with working stdout.
2. Test runner + growing test suite (files, threads, sync, TLS).
3. ASan/UBSan + PE fuzzer hardening.
4. X11 backend + user32/gdi32 window slice under Xvfb.
