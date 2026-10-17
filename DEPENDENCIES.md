# DEPENDENCIES.md — every external thing, justified

Goal: the list stays nearly empty. Anything that can be dlopen'd at runtime
with graceful fallback, is. Anything tiny enough to vendor, is vendored.

## Link time (the only ones)

| Library      | Why                                                     | Avoidable? |
|--------------|---------------------------------------------------------|------------|
| libc (glibc) | syscalls wrappers, malloc, string functions, dlopen     | No         |
| libm         | math used by benchmarks / float formatting              | Mostly (-lm is a no-op on glibc where all funcs are in libc; kept explicit for musl) |
| libpthread   | threads (already in glibc on modern systems; kept for musl) | Yes where merged into libc |
| libdl        | dlopen/dlsym (in glibc; kept for musl)                  | Yes where merged |

## Runtime, optional, dlopen'd with graceful fallback

| Library        | Why                                             | Fallback when absent           |
|----------------|-------------------------------------------------|--------------------------------|
| libX11.so.6    | X11 windowing backend                           | Try Wayland; else no GUI       |
| libvulkan.so.1 | Vulkan loader for hardware graphics             | Software rasterizer (slow but correct) |
| (future) libpipewire / libpulse / libasound | audio | silence + loud log |

No Wayland client library is linked or loaded: the Wayland wire protocol is
marshalled by hand in C (`src/backends/wayland_backend.c`), per project rules
(no wayland-scanner at build time).

## Vendored in-tree

Nothing yet. Candidates if ever needed: a small hash (we write our own),
an inflate decompressor (for reading .zip-based installers later).

## Test-only tools (never part of the product)

* mingw-w64 cross compiler — builds Windows test binaries (tests/).
* Xvfb — headless X server so GUI tests run in CI-like environments.
