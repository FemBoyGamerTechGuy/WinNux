#!/bin/sh
# WinNux test suite runner.
# Builds every tests/cases/*.c with the mingw cross compiler (if available),
# runs it under bin/winnux, and compares stdout + exit code against
# tests/expected/<name>.txt.
#
# Expected-file format:
#   line 1: expected exit code
#   other lines: exact match on stdout (CR stripped);
#     a line starting with '~' matches by prefix (for variable paths/values).
#
# A case marked in XFAIL (file tests/cases/<name>.xfail with reason text) is
# reported as XFAIL (expected-fail) instead of FAIL, and never removed.

set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN="$ROOT/bin/winnux"
CASES="$ROOT/tests/cases"
EXP="$ROOT/tests/expected"
OUTDIR="$ROOT/tests/bin"
RESULTS="$ROOT/tests/results"
MXGCC=${MXGCC:-x86_64-w64-mingw32-gcc}

mkdir -p "$OUTDIR" "$RESULTS"
# Ship the mingw winpthreads DLL next to the tests: real PE DLL load test.
PTHREAD_DLL=$(dirname "$MXGCC")/../x86_64-w64-mingw32/lib/libwinpthread-1.dll 2>/dev/null
if [ -f "$PTHREAD_DLL" ]; then
    [ "$PTHREAD_DLL" -nt "$OUTDIR/libwinpthread-1.dll" ] && cp "$PTHREAD_DLL" "$OUTDIR/"
fi

if [ ! -x "$BIN" ]; then
    echo "FATAL: $BIN not built (run make)" >&2
    exit 2
fi

# Discover the cross compiler (PATH, then common local roots).
if ! command -v "$MXGCC" >/dev/null 2>&1; then
    for cand in \
        /home/z/my-project/toolchain/root/usr/bin/x86_64-w64-mingw32-gcc-posix \
        /usr/bin/x86_64-w64-mingw32-gcc \
        /usr/local/bin/x86_64-w64-mingw32-gcc; do
        if [ -x "$cand" ]; then MXGCC="$cand"; break; fi
    done
fi

HAVE_MX=0
if command -v "$MXGCC" >/dev/null 2>&1; then HAVE_MX=1; fi

pass=0; fail=0; xfail=0; skip=0; failed_names=""

summary() {
    {
        echo "WinNux test results $(date -u '+%Y-%m-%d %H:%M UTC')"
        echo "cross-compiler: $([ $HAVE_MX = 1 ] && echo "$MXGCC" || echo MISSING)"
        echo "pass=$pass fail=$fail xfail=$xfail skip=$skip"
        [ -n "$failed_names" ] && echo "failed: $failed_names"
        echo
    } > "$RESULTS/summary.txt"
    cat "$RESULTS/summary.txt"
}

run_one() {
    name=$1
    src="$CASES/$name.c"
    exe="$OUTDIR/$name.exe"
    exp="$EXP/$name.txt"

    if [ $HAVE_MX = 0 ]; then
        echo "SKIP $name (no cross compiler)"
        skip=$((skip+1))
        return
    fi
    if ! "$MXGCC" -O2 -o "$exe" "$src" 2>>"$RESULTS/build.log"; then
        echo "FAIL $name (build error, see results/build.log)"
        fail=$((fail+1)); failed_names="$failed_names $name(build)"
        return
    fi

    args=""
    [ -f "$CASES/$name.args" ] && args=$(cat "$CASES/$name.args")

    actual="$RESULTS/$name.out"
    timeout 30 "$BIN" run "$exe" $args >"$actual" 2>"$RESULTS/$name.err"
    rc=$?
    # Strip CR (console translation) for comparison.
    tr -d '\r' < "$actual" > "$actual.n"

    want_rc=$(head -1 "$exp")
    ok=1
    if [ "$rc" != "$want_rc" ]; then
        ok=0
        echo "      exit code: got $rc want $want_rc"
    fi
    # Compare remaining lines.
    tail -n +2 "$exp" > "$RESULTS/$name.want"
    cat "$actual.n" > "$RESULTS/$name.got"
    ln_want=$(wc -l < "$RESULTS/$name.want")
    ln_got=$(wc -l < "$RESULTS/$name.got")
    if [ "$ln_want" != "$ln_got" ]; then
        ok=0
        echo "      line count: got $ln_got want $ln_want"
    fi
    i=0
    while IFS= read -r wantline; do
        i=$((i+1))
        gotline=$(sed -n "${i}p" "$RESULTS/$name.got")
        case "$wantline" in
        '~'*)
            prefix=${wantline#\~}
            case "$gotline" in
            "$prefix"*) : ;;
            *) ok=0; echo "      line $i: got '$gotline' want prefix '$prefix'";;
            esac
            ;;
        *)
            if [ "$gotline" != "$wantline" ]; then
                ok=0
                echo "      line $i: got '$gotline' want '$wantline'"
            fi
            ;;
        esac
    done < "$RESULTS/$name.want"

    if [ $ok = 1 ]; then
        if [ -f "$CASES/$name.xfail" ]; then
            echo "PASS! $name (was XFAIL: $(cat "$CASES/$name.xfail"))"
            pass=$((pass+1))
        else
            echo "PASS  $name"
            pass=$((pass+1))
        fi
    else
        if [ -f "$CASES/$name.xfail" ]; then
            echo "XFAIL $name ($(cat "$CASES/$name.xfail"))"
            xfail=$((xfail+1))
        else
            echo "FAIL  $name"
            fail=$((fail+1)); failed_names="$failed_names $name"
        fi
    fi
}

echo "== WinNux test suite =="
for src in "$CASES"/*.c; do
    [ -e "$src" ] || continue
    name=$(basename "$src" .c)
    run_one "$name"
done

summary
[ "$fail" = 0 ]
