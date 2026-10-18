# HANDOFF.md — what was happening, and the next 3 steps

Read this before continuing. Pair with STATUS.md (what works + proof) and
TODO.md (prioritized backlog).

## Last session (session 7) — what happened

The user's "teb: modify_ldt failed: Success" abort was OUR bug: the
kernel returns 0 for modify_ldt(func=1 write) — the check compared
against sizeof(desc). One-line fix; his kernel was fine. The big unlock:
**qemu-i386 (toolchain/qemu) executes the 32-bit build locally** despite
the container's seccomp — `qemu-i386 -L toolchain/root32 bin/winnux32
run app.exe` is the local 32-bit loop (modify_ldt AND %fs LDT hosting
pass through qemu; the sysroot was rebuilt from Debian debs after the
sandbox reset wiped session 6's toolchain/root32 — setup is
scripts/setup_root32.sh + the debs in toolchain/debs).

qemu immediately exposed the bug class 64-bit could never show: every
uint64_t-typed builtin param where Windows uses a pointer-width type
(SIZE_T/WPARAM/LPARAM/HWND/callbacks) SKEWERS the i386 guest stack
(ret-N computed for 16 bytes vs 12 pushed; garbage upper dwords —
HeapAlloc read "size" 0x40D0516000000000 for a 128 ask; session 6's
"working" hello32 was luck). Landed: wn_abiword/wn_abiword_s (8B x64 /
4B i386) + 203 signatures converted; guest-shaped MSG (28B i386) fill
AND read; window-proc typedefs + RegisterClassA/W i386 WNDCLASS; MSVC
FILE stride 32B on i386 (mingw stdout = _iob()+N*sizeof(FILE) — the
wrong stride made every fwrite silently no-op; printf output vanished);
new exports GetVersion/GetVersionExW, wsprintfA/W + wvsprintfA/W
(engine gained wide-mode; family is CDECL — varargs can't be stdcall),
_onexit, localtime/_localtime32/_localtime64/gmtime (36-byte MSVC tm),
qsort (in-tree heapsort, comparator via WN_CRTAPI fn-ptr), _strupr/
_strlwr. Makefile: obj32/ dir rule was missing (fresh clones failed
`make winnux32`) + sysroot include fix + gcc-version-dir autodetect.

Proof: hello32/heap32/torture32 (printf/malloc/stdio/qsort/argv/env/
time) all pass under qemu with zero stubs; argv forwards through the
re-exec (`winnux run x.exe -e ...`); 64-bit suite 15/15.

## Next 3 steps (exactly this order)

1. **Real-hardware validation loop**: the user runs `make winnux32 &&
   ./bin/winnux run LuaForWindows_v5.1.5-52.exe -e 'print(...)'` on his
   Artix box (lib32/multilib enabled, gcc-multilib installed). First
   failures there drive the next fixes — watch for DLL-name coverage
   (NSIS-era: setupapi, RichEdit) and CRT startup edges. qemu is the
   pre-flight, his box is the truth.
2. **i386 WinMain-CRT exit crash** (TODO P0.2a, precise repro ready):
   gui32.exe dies after WinMain returns (SIGSEGV 0xfffffffc; main()-
   entry builds exit cleanly; with/without X11 — NOT the GUI path).
   Likely frame-SEH chain (fs:0 list is NULL) or the CRT exit handler;
   ALSO our SEH handler dies before logging on i386 guest faults —
   suspect dispatch_veh/crash_report handing 64-bit-shaped
   EXCEPTION_POINTERS to the 32-bit filter. 32-bit X11 under qemu is
   DONE (i386 libX11/xcb/xau/xdmcp extracted to root32/usr/lib32 via
   symlinks — dlopen works; gui32 opens a window and maps it before
   the crash).
3. **PuTTY Open -> session** (unchanged from session 6): the config box
   works; drive the Open button to the terminal window.

## Dead ends / gotchas (do not repeat)

- `modify_ldt` write returns 0 on success — byte counts are for READS.
- NEVER type a Windows pointer-width builtin param uint64_t: on i386
  the mismatch skews the guest stack. Use wn_abiword/wn_abiword_s.
- MSVC FILE is 48B x64 / 32B i386; struct tm is 36B on BOTH (no
  tm_gmtoff/tm_zone like glibc).
- wsprintf/wvsprintf family is CDECL on i386 (varargs), and %s follows
  the A/W direction while %S flips (engine: wn_vformat wide flag).
- The Edit/Write tools convert TABs to spaces — NEVER edit the Makefile
  with them; use `sed` or `python` line-rewrite (a session was lost to
  "missing separator" once already). Session 7 updated the Makefile
  exclusively via python heredocs.
- `wn_utf16_to_utf8(w, len16)`: second arg is the INPUT length in UTF-16
  units, not bytes, not a capacity. Two people got this wrong already.
- The sandbox resets wipe toolchain/ between sessions: the recovery is
  scripts/setup_root32.sh + dpkg -x of toolchain/debs/*.deb (mingw
  i686+x86_64, root32 libc, qemu-user) — all re-downloadable with
  apt-get download (no root needed).