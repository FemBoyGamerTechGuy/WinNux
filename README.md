# WinNux

A Windows application/game compatibility layer for Linux, written in raw C
(C11/C17) with almost zero link-time dependencies. Link-time: libc, libm,
libpthread, libdl only — everything else (X11, FreeType, Vulkan) is dlopen'd
at runtime. PE32 (i386, NEW) and PE32+ (x86-64) images are loaded and run
natively on the CPU.

## Build

    make            # bin/winnux (64-bit loader + runtime)
    make winnux32   # bin/winnux32 (32-bit loader, for i386 PE images)
    make test       # 15 mingw-compiled test cases
    make check32    # compile the whole tree -m32 (CI-style check)

`winnux run app.exe` automatically re-execs `bin/winnux32` when the image
is 32-bit (i386) — like Wine's wine/wine split, inverted. Build BOTH
targets for full 32-bit app support.

### 32-bit toolchain

- **Arch**: enable the `[multilib]` repository in `/etc/pacman.conf`
  (uncomment the `[multilib]` section — `pacman -Ss gcc-multilib` finds
  NOTHING without it), then:
  `sudo pacman -Syu && sudo pacman -S gcc-multilib lib32-gcc-libs`
- **Debian/Ubuntu**: `sudo apt install gcc-multilib`
- No multilib, no root? Set `WINNUX_M32_SYSROOT=/path/to/glibc32-sysroot`
  (see HANDOFF.md for the deb-extraction recipe).

## Run

    ./bin/winnux run app.exe [args...]
    ./bin/winnux run C:\path\to\app.exe       # windows drive paths
    ./bin/winnux imports app.exe                # import coverage report
    ./bin/winnux bench                          # loader/futex/mem perf
    ./bin/winnux run --backend x11 app.exe      # or wayland/auto

Per-user prefix: `~/.WinNux/default/` (drives, registry, users);
override with `--prefix DIR` or `WINNUX_HOME`.

## Status

See STATUS.md (the honest ledger: what works, what is broken, proof for
every claim), TODO.md (prioritized backlog) and HANDOFF.md (session
hand-off notes + gotchas). 64-bit console apps (Lua, SQLite CLI) and
PuTTY's configuration dialog are the current proven frontiers; 32-bit
(i386) loader support just landed — see STATUS.md "session 6".
