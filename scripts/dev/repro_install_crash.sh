#!/bin/sh
# repro_install_crash.sh — drive the Inno wizard with REAL XTEST server-side
# input through to the Install click, with /LOG=, to reproduce and capture
# the install-time engine crash (reported by the user on real X11).
#
# One bash call = the whole run (the sandbox reaps backgrounded processes
# between calls). Output: /tmp/wiz9.log (guest log), /tmp/wiz9_*.ppm shots,
# /tmp/wiz9_exit (final rc), inno log under the prefix.
set -x
W=/home/z/my-project/WinNux
QEMU=/home/z/my-project/toolchain/qemu/usr/bin/qemu-i386
SYSROOT=/home/z/my-project/toolchain/root32
PREF=$HOME/.WinNux/default
export PYTHONPATH=/home/z/.local/lib/python3.13/site-packages
XI="python3 $W/scripts/dev/xinject.py"
DISP=${DISP:-:95}

rm -f /tmp/wiz9.log /tmp/wiz9_exit "$PREF/drive_c/inno.log" 2>/dev/null
pkill -f "Xvfb $DISP" 2>/dev/null
sleep 0.5
Xvfb $DISP -screen 0 1024x768x24 >/tmp/wiz9_xvfb.log 2>&1 &
XVFBPID=$!
sleep 1.5

cd $W
export WINNUX_CHILD_CMD="$QEMU -g 12346 -L $SYSROOT $W/bin/winnux32"
export LD_LIBRARY_PATH="$SYSROOT/usr/lib/i386-linux-gnu:$SYSROOT/usr/lib32"
export WINNUX_KEEP_TEMP=1
export WINNUX_MSGBOX_AUTO=yes
# Short by default (warnings + one stub summary at exit) so crash logs stay
# readable; set WINNUX_DEBUG=1 for the full WINNUX_LOG=debug dispatch trace.
[ -n "$WINNUX_DEBUG" ] && export WINNUX_LOG=debug
export DISPLAY=$DISP

timeout 500 "$QEMU" -L "$SYSROOT" ./bin/winnux32 run \
    ~/test/LuaForWindows_v5.1.5-52.exe "/LOG=C:/inno.log" > /tmp/wiz9.log 2>&1 &
WPID=$!

# one persistent gdb-remote session on the engine's stub: continue now,
# snapshot at +215s (just after the Install click lands)
python3 $W/scripts/dev/gdbstub_session.py 12346 /tmp/wiz9_guest_stack.txt 215     >/tmp/wiz9_stub.log 2>&1 &
STUBPID=$!

# wait for the wizard toplevel to map (boot under qemu is slow)
WIZ=""
for i in $(seq 1 120); do
    sleep 2
    LINE=$($XI waitwin 'Setup' 4 2>/dev/null | head -1)
    case "$LINE" in 0x*) WIZ=$(echo "$LINE" | awk '{print $1}'); break;; esac
    kill -0 $WPID 2>/dev/null || break
done
echo "WIZ=$WIZ"
[ -z "$WIZ" ] && { echo "wizard never mapped"; tail -30 /tmp/wiz9.log; exit 1; }
sleep 10
$XI shot /tmp/wiz9_welcome.ppm

echo "== welcome: Next =="
$XI click "$WIZ" 426 338; sleep 20
$XI shot /tmp/wiz9_license.ppm

echo "== license: accept radio + Next =="
$XI click "$WIZ" 76 276; sleep 10
$XI click "$WIZ" 426 338; sleep 25
$XI shot /tmp/wiz9_components.ppm

echo "== components: click checklist row then Next =="
$XI click "$WIZ" 66 200; sleep 8
$XI click "$WIZ" 426 338; sleep 25
$XI shot /tmp/wiz9_dir.ppm

echo "== dir page: Install =="
$XI click "$WIZ" 426 338; sleep 30
$XI shot /tmp/wiz9_install_clicked.ppm
$XI tree > /tmp/wiz9_tree_after_install.txt

echo "== waiting for crash/exit (up to 200s) =="
for i in $(seq 1 40); do
    sleep 5
    if ! kill -0 $WPID 2>/dev/null; then break; fi
    if [ $((i % 4)) -eq 0 ]; then $XI shot /tmp/wiz9_installing_$i.ppm 2>/dev/null; fi
    if [ $((i % 2)) -eq 0 ]; then
        # ALL qemu processes: the outer extractor AND the engine child
        QP=$(pgrep -f "qemu-i386" 2>/dev/null | tr '\n' ' ')
        for ONE in $QP; do
            echo "=== QEMU $ONE: $(tr '\0' ' ' < /proc/$ONE/cmdline | tail -c 130)" >> /tmp/wiz9_diag.txt
            ps -o pid,stat,pcpu,wchan:24,etime,comm -p $ONE >> /tmp/wiz9_diag.txt
            grep -E "State|Threads|voluntary" /proc/$ONE/status >> /tmp/wiz9_diag.txt 2>/dev/null
            for T in /proc/$ONE/task/*/syscall; do
                echo "-- $T" >> /tmp/wiz9_diag.txt
                cat "$T" 2>/dev/null >> /tmp/wiz9_diag.txt
            done
            if [ ! -f /tmp/wiz9_memdump_$ONE.bin ]; then
                python3 - "$ONE" <<'PYEOF' >> /tmp/wiz9_diag.txt 2>&1
import sys, struct, glob
pid = int(sys.argv[1])
uaddr = None
for sc in glob.glob(f"/proc/{pid}/task/*/syscall"):
    try:
        data = open(sc).read().split()
        if data and data[0] == '202':
            a = int(data[1], 0)
            if a < 0x100000000:
                uaddr = a
                break
    except Exception:
        pass
print(f"uaddr found: {hex(uaddr) if uaddr else None}")
if uaddr:
    base = uaddr - 64
    mem = open(f"/proc/{pid}/mem", "rb")
    mem.seek(base)
    data = mem.read(192)
    print(f"word at uaddr: {hex(struct.unpack('<I', data[64:68])[0])}")
    for off in range(0, 192, 16):
        print(f"  {base+off:#010x}: " + " ".join(f"{b:02x}" for b in data[off:off+16]))
    for line in open(f"/proc/{pid}/maps"):
        lo, hi = line.split()[0].split('-')
        if int(lo, 16) <= uaddr < int(hi, 16):
            print("region:", line.strip())
PYEOF
                cp /proc/$ONE/maps /tmp/wiz9_maps_$ONE.txt 2>/dev/null
                touch /tmp/wiz9_memdump_$ONE.bin
                echo "=== guest stack code-pointer scan" >> /tmp/wiz9_diag.txt
                python3 - "$ONE" <<'PYEOF2' >> /tmp/wiz9_diag.txt 2>&1
import sys, glob, struct
pid = int(sys.argv[1])
lo, hi = 0x40acd000, 0x40be0000
print(f"guest main stack: {lo:#x}-{hi:#x}")
mem = open(f"/proc/{pid}/mem", "rb")
mem.seek(lo)
data = mem.read(hi - lo)
for off in range(0, len(data) - 4, 4):
    v = struct.unpack("<I", data[off:off+4])[0]
    addr = lo + off
    tag = None
    if 0x401000 <= v < 0x49a000:
        tag = "engine"
    elif 0x804a000 <= v < 0x80c5000:
        tag = "winnux32"
    elif 0x4083d000 <= v < 0x40a70000:
        tag = "libc"
    if tag:
        print(f"  {addr:#010x}: {v:#010x} {tag}")
PYEOF2
            fi
        done
    fi
done
$XI shot /tmp/wiz9_final.ppm 2>/dev/null
wait $WPID; RC=$?
echo $RC > /tmp/wiz9_exit
echo "== EXIT rc=$RC =="
tail -40 /tmp/wiz9.log
echo "== inno log search =="
find "$PREF/drive_c" -maxdepth 3 -name 'inno*.log' -exec ls -la {} \; -exec tail -40 {} \;
pkill -f "Xvfb $DISP" 2>/dev/null
true
