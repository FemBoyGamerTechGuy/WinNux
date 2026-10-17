# WinNux architecture

This document explains the layering and the decisions behind it. STATUS.md
tracks what actually works.

## Layer map (bottom = host, top = Windows program)

```
+-------------------------------------------------------------+
| Windows PE32+ program (mingw-w64 built, real imports)        |
+-------------------------------------------------------------+
| IAT entries -> ms_abi builtin functions (direct calls)      |
+-------------------------------------------------------------+
| Win32 layer: kernel32, user32, gdi32, advapi32, ws2_32      |
| CRT: msvcrt/ucrtbase (in-tree printf engine, FILE shells)   |
| NT layer: ntdll (Rtl*, VEH, critsects)                      |
+-------------------------------------------------------------+
| Windows ABI bridge: TEB/PEB (exact x64 offsets), GS base,  |
| LDR lists, stub trampoline page, SEH signal capture         |
+-------------------------------------------------------------+
| WinNux core: PE loader, module registry, handles, sync      |
| (futex), files (prefix + case-insensitive), virtual memory, |
| registry, logging                                            |
+-------------------------------------------------------------+
| Backend abstraction (wn_backend.h): windows + presentation  |
|   +-- X11 backend (dlopen libX11, no headers, wire ABI)     |
|   +-- Wayland backend (hand-marshalled wire protocol)       |
+-------------------------------------------------------------+
| Linux: mmap, futex, pthreads, eventfd, epoll-ish poll,      |
| write/read, dlopen                                           |
+-------------------------------------------------------------+
```

## Key decisions

### 1. ms_abi direct calls — no thunks on the hot path
GCC/Clang on x86_64 Linux can compile functions with the Microsoft x64
calling convention (`__attribute__((ms_abi))`). Every builtin DLL function
is `WN_API` (ms_abi), so the guest calls it through the IAT exactly like it
calls a real Windows DLL: zero register shuffling, zero wrapper layers.
Varargs (printf family) decode the MS-ABI 8-byte argument slots by hand in
`msvcrt.c` — that is how the MS CRT's own va_list behaves.

### 2. TEB at GS base, Windows-exact offsets
Guest code reads `gs:0x30` (TEB self), `gs:0x58` (TLS array), `gs:0x60`
(PEB), `gs:0x68` (last error). We map a TEB+TLS-array block per thread and
set the thread's GS base with `arch_prctl(ARCH_SET_GS)`. glibc uses FS and
never touches GS, so the two coexist. All structure offsets are pinned with
`_Static_assert` (see `wn_process.h`, `seh.c`).

### 3. Loud stubs instead of silent fake success
Missing imports resolve to generated trampolines (RWX page, MAP_32BIT when
available): `mov r10, info; jmp trampoline`. The trampoline preserves the
guest argument registers, captures the guest return address, calls a C
logger, and returns 0/NULL with `GetLastError()=120`. First use and every
1000th use is logged at ERROR with `dll!api called from module+rva`. The
first line is written with a raw `write(2)` so the report survives even if
the rest of logging is broken.

### 4. Files: prefix + case-insensitivity
`C:\` maps to `<prefix>/drive_c`, `Z:\` maps to `/` (host bridge). Paths
resolve per component with `readdir` + case-insensitive compare when the
exact-case file is missing — Windows semantics, Linux filesystems.
Relative paths go through the Windows CWD, which is kept in sync with the
host CWD.

### 5. Sync objects on futexes
Events/mutexes/semaphores are small structs with a futex word; single waits
block on the object's own word. WaitForMultipleObjects(any) polls and
sleeps on a global wake channel (correct, some thundering herd — noted as
a future optimization). Critical sections operate in-place on guest memory
(xchg on LockCount + futex when contended).

### 6. GUI: software framebuffers behind a backend interface
user32/gdi32 never touch X11 or Wayland. Every window has a BGRA buffer
whose byte layout (B,G,R,X) is identical to both a Win32 32bpp DIB and an
X11 32bpp ZPixmap LSBFirst image, so presentation is a zero-conversion
`XPutImage` (and will be a zero-copy shm/DMA-BUF pass in the Wayland and
Vulkan paths). Text renders through the backend's server-side rasterizer
with a glyph cache — real fonts, zero font libraries.

### 7. Honest graphics progression
The plan is: software correctness first (works everywhere), then Vulkan
(dlopen) for hardware, with the D3D9/D3D11 -> Vulkan translators consuming
the same window/swapchain plumbing. `winnux bench` measures; STATUS.md
records.

### 8. X11 without headers
The X11 backend dlopens `libX11.so.6`, resolves functions with dlsym, and
accesses `XEvent`/`XImage` through layout-exact overlay structs (offsets
asserted at compile time where the ABI allows). The X11 wire ABI has been
stable for decades; the overlay structs document every offset used.

### 9. Wayland without wayland-scanner or libwayland-client
The Wayland backend marshals the wire protocol by hand (see
`wayland_backend.c`): unix socket connect, wl_display.get_registry, sync
roundtrip. This keeps the build free of Wayland tooling while the surface
path (xdg_shell, wl_shm) is completed.

## Threading model (current, documented)

One GUI thread per process for message queues (v1); guest threads work
freely for compute. PostMessage from other threads wakes the GUI thread
through an eventfd. The migration to per-thread queues follows Wine's
model and is planned with the input milestone.

## Globals (documented)

* `g_proc` — the single process context (PEB/TEB/env/prefix).
* module list, handle table, stub page, GUI registries — all in their
  owning .c files with a comment where the lock-free/single-thread
  assumption applies.
