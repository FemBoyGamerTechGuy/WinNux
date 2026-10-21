#!/bin/sh
# repro_silent_install.sh — the /S silent path of the SAME engine: no wizard,
# pure install logic. Success = files in the prefix + uninstall registry
# entry + lua.exe runs. Failure here = the install-path bug isolated from
# the wizard (and /LOG shows the exact step where it stops).
set -x
W=/home/z/my-project/WinNux
QEMU=/home/z/my-project/toolchain/qemu/usr/bin/qemu-i386
SYSROOT=/home/z/my-project/toolchain/root32
PREF=$HOME/.WinNux/default

rm -f "$PREF/drive_c/inno.log" /tmp/silent.log
pkill -f "Xvfb :97" 2>/dev/null; sleep 0.5
Xvfb :97 -screen 0 1024x768x24 >/tmp/x97.log 2>&1 &
XPID=$!
sleep 1.5
export DISPLAY=:97
cd $W
export WINNUX_CHILD_CMD="$QEMU -L $SYSROOT $W/bin/winnux32"
export LD_LIBRARY_PATH="$SYSROOT/usr/lib/i386-linux-gnu:$SYSROOT/usr/lib32"
export WINNUX_KEEP_TEMP=1
export WINNUX_LOG=debug

timeout 420 "$QEMU" -L "$SYSROOT" ./bin/winnux32 run \
    ~/test/LuaForWindows_v5.1.5-52.exe /S /LOG=C:/inno.log > /tmp/silent.log 2>&1
RC=$?
echo "rc=$RC"

echo "== inno log:"
cat "$PREF/drive_c/inno.log" 2>/dev/null | tail -30
echo "== winnux log tail (non-dispatch):"
grep -v "dispatch:\|-> proc\|msg=15" /tmp/silent.log | tail -40
echo "== prefix state:"
find "$PREF/drive_c/Program Files" -maxdepth 4 2>/dev/null | head -20
find "$PREF/drive_c" -name "unins*" 2>/dev/null | head
kill $XPID 2>/dev/null
true
