#!/bin/sh
# tests/e2e/run_e2e.sh — REAL server-side input (XTEST) regression suite.
#
# The old harness injected clicks with XSendEvent, which delivers events
# DIRECTLY to a window and bypasses the server entirely: no implicit
# grab, no capture routing, no client-coordinate translation, no Z-order
# window selection. Everything "looked right" under Xvfb while real
# pointers (the user's machine) failed: dead scrollbars, unclickable
# checkboxes, wrong windows receiving clicks. This suite drives the
# same code paths a real pointer exercises, via the XTEST extension
# (xinject.py) - the pointer moves through the SERVER's normal delivery.
#
# Cases:
#   t24_router       sibling Z-order hit-test, capture client-coords,
#                    capture auto-release at UP
#   t25_scroll_input arrows, trough click, thumb drag (motion outside the
#                    bar under pointer grab), mouse wheel 4/5
#   t26_check_input  checkbox click/Space/mnemonic, BM_GETCHECK,
#                    BN_CLICKED, immediate repaint (glyph pixels flip)
#
# Plus (scripts/dev/repro_install_crash.sh) the full-wizard E2E: the
# dir-page-after-Next regression and the Install-click flow.
set -u
W=$(cd "$(dirname "$0")/../.." && pwd)
MG=${MXGCC:-/home/z/my-project/toolchain/root/usr/bin/x86_64-w64-mingw32-gcc-posix}
XI="python3 $W/scripts/dev/xinject.py"
export PYTHONPATH=${PYTHONPATH:-/home/z/.local/lib/python3.13/site-packages}
OUT=/tmp/e2e_out
mkdir -p $OUT
PASS=0; FAIL=0

say() { printf '  %s\n' "$*"; }
ok()  { PASS=$((PASS+1)); say "PASS: $1"; }
bad() { FAIL=$((FAIL+1)); say "FAIL: $1"; }

DISP=${E2E_DISP:-:93}
pkill -f "Xvfb $DISP" 2>/dev/null; sleep 0.5
Xvfb $DISP -screen 0 1024x768x24 >/tmp/e2e_xvfb.log 2>&1 &
XPID=$!
sleep 1.5
export DISPLAY=$DISP

build() {
    name=$1
    shift
    deps="$@"
    "$MG" -O2 -o "$OUT/$name.exe" "$W/tests/e2e/$name.c" $deps 2>&1 | head -3
    [ -x "$OUT/$name.exe" ]
}

run_guest() {
    name=$1
    shift
    ( timeout 45 "$W/bin/winnux" run "$OUT/$name.exe" > "$OUT/$name.log" 2>&1 ) &
    sleep 3
    eval "$@"
    sleep 2
}

# ---------------------------------------------------------------- t24
if build t24_router -luser32 -lgdi32; then
    run_guest t24_router '
        FID=$($XI waitwin T24RouterForm 20 | awk "{print \$1}")
        if [ -n "$FID" ]; then
            $XI click "$FID" 200 100       # new_child area -> NEW on top
            $XI click "$FID" 30 30         # outside NEW -> OLD
            $XI click "$FID" 200 100       # again after capture churn
        fi
    '
    if grep -q "DOWN id2 at 100,50" "$OUT/t24_router.log" 2>/dev/null; then
        ok "t24 z-order: click routed to topmost sibling (id2)"
    else
        bad "t24 z-order: expected DOWN id2 at 100,50; got: $(grep DOWN $OUT/t24_router.log 2>/dev/null | head -3 | tr '\n' ' ')"
    fi
    if grep -q "DOWN id1 at 30,30" "$OUT/t24_router.log" 2>/dev/null; then
        ok "t24 z-order: non-overlap falls through to lower sibling (id1)"
    else
        bad "t24 z-order: expected DOWN id1 at 30,30"
    fi
else
    bad "t24 build"
fi

# ---------------------------------------------------------------- t25
if build t25_scroll_input -luser32 -lgdi32; then
    ( T25_HOLD=14000 timeout 30 "$W/bin/winnux" run "$OUT/t25_scroll_input.exe" > "$OUT/t25_scroll_input.log" 2>&1 ) &
    sleep 3
    FID=$($XI waitwin T25ScrollForm 20 | awk "{print \$1}")
    if [ -n "$FID" ]; then
        $XI click "$FID" 388 260     # BOTTOM arrow: SB_LINEDOWN 0 -> >0
        $XI click "$FID" 388 130     # trough below thumb: SB_PAGEDOWN
        $XI drag "$FID" 388 60 388 220 10    # thumb drag, motion past the bar
        $XI rdrag 190 200 190 200 1          # move onto the edit (grab churn)
        $XI wheel down 3                      # wheel over the edit
        $XI wheel up 1
    fi
    sleep 12
    if grep -q "sb pos final=[1-9]" "$OUT/t25_scroll_input.log" 2>/dev/null; then
        ok "t25 scrollbar: arrows/trough/thumb-drag moved the SB position"
    else
        bad "t25 scrollbar: position unchanged ($(tail -3 $OUT/t25_scroll_input.log 2>/dev/null | tr '\n' ' '))"
    fi
    if grep -q "edit first visible=[1-9]" "$OUT/t25_scroll_input.log" 2>/dev/null; then
        ok "t25 edit: real wheel scrolled the content"
    else
        bad "t25 edit: wheel did not scroll ($(tail -3 $OUT/t25_scroll_input.log 2>/dev/null | tr '\n' ' '))"
    fi
else
    bad "t25 build"
fi

# ---------------------------------------------------------------- t26
if build t26_check_input -luser32 -lgdi32; then
    ( T26_HOLD=14000 timeout 30 "$W/bin/winnux" run "$OUT/t26_check_input.exe" > "$OUT/t26_check_input.log" 2>&1 ) &
    sleep 3
    FID=$($XI waitwin T26Check 20 | awk "{print \$1}")
    if [ -n "$FID" ]; then
        $XI click "$FID" 26 60       # click the checkbox glyph (DLG units: x2/x4)
        $XI key space                 # Space toggles the focused checkbox
        $XI chord Alt_L d             # Alt+D mnemonic via the dialog manager
    fi
    sleep 12
    if [ "$(grep -c "BN_CLICKED" "$OUT/t26_check_input.log" 2>/dev/null)" -ge 3 ]; then
        ok "t26 checkbox: click + Space + mnemonic all notified BN_CLICKED"
    else
        bad "t26 checkbox: BN_CLICKED count $(grep -c BN_CLICKED $OUT/t26_check_input.log 2>/dev/null)/3"
    fi
    if grep -q "state 0->1" "$OUT/t26_check_input.log" 2>/dev/null && \
       grep -q "state 1->0" "$OUT/t26_check_input.log" 2>/dev/null; then
        ok "t26 checkbox: BM_GETCHECK flipped both ways"
    else
        bad "t26 checkbox: check state never flipped"
    fi
    if grep -q "glyph0=" "$OUT/t26_check_input.log" 2>/dev/null && \
       ! grep -q "glyph0=000000" "$OUT/t26_check_input.log" 2>/dev/null; then
        ok "t26 checkbox: glyph pixels are drawn (GetPixel readback)"
    else
        bad "t26 checkbox: glyph readback missing or black ($(grep glyph0 $OUT/t26_check_input.log 2>/dev/null | head -1))"
    fi
else
    bad "t26 build"
fi

kill $XPID 2>/dev/null
echo
echo "e2e real-input: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
