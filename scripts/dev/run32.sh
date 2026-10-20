#!/bin/sh
# run32.sh — local 32-bit (i386) execution loop via qemu-user.
#
# The dev container's seccomp kills native i386 syscalls (SIGSYS), but
# qemu-i386 translates them to x86_64 — INCLUDING modify_ldt (verified:
# LDT install returns 0, %fs hosting reads back fs:0x18). This is how
# WinNux 32-bit changes are tested without real hardware.
#
# Setup (if toolchain/ was wiped — see HANDOFF.md):
#   cd toolchain/debs && apt-get download qemu-user libc6-dev-i386 \
#       libc6-i386 lib32gcc-14-dev gcc-14-multilib \
#       gcc-mingw-w64-i686-posix binutils-mingw-w64-i686 \
#       mingw-w64-i686-dev mingw-w64-common
#   for d in *.deb; do dpkg -x "$d" ../root32/ (libc) or ../root/ (mingw); done
#   sh /home/z/my-project/scripts/setup_root32.sh
#   mkdir -p ../root32/lib && ln -sf $PWD/../root32/usr/lib32/ld-linux.so.2 \
#       ../root32/lib/ld-linux.so.2
#
# Usage: sh scripts/dev/run32.sh path/to/app32.exe [guest args...]
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
QEMU=${QEMU:-/home/z/my-project/toolchain/qemu/usr/bin/qemu-i386}
SYSROOT=${SYSROOT:-/home/z/my-project/toolchain/root32}
W32="$ROOT/bin/winnux32"

if [ ! -x "$QEMU" ]; then
    echo "run32: qemu-i386 not found at $QEMU (see header for setup)" >&2
    exit 2
fi
if [ ! -x "$W32" ]; then
    echo "run32: $W32 not built (make winnux32)" >&2
    exit 2
fi
if [ ! -d "$SYSROOT/usr/lib32" ]; then
    echo "run32: sysroot $SYSROOT missing (see header for setup)" >&2
    exit 2
fi

# Process trees: under qemu-user, /proc/self/exe is the EMULATOR, so the
# guest's CreateProcess would exec qemu with loader args. WINNUX_CHILD_CMD
# re-routes child spawns through the same qemu+winnux32 loop.
export WINNUX_CHILD_CMD="$QEMU -L $SYSROOT $W32"

exec "$QEMU" -L "$SYSROOT" "$W32" run "$@"
