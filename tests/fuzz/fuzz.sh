#!/bin/sh
# PE-loader fuzzing: builds the fork-based harness against the ASan debug
# objects and mutates the shipped test binaries as seeds.
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
DBG="$ROOT/obj-dbg"
OUT="$ROOT/bin/fuzz-pe"
CRASHES="$ROOT/tests/fuzz/crashes"

if [ ! -f "$DBG/pe/pe.o" ]; then
    echo "building debug objects (make debug)..."
    (cd "$ROOT" && make debug >/dev/null) || exit 2
fi

# Link every debug object except main.o (the fuzzer provides main()).
OBJS=""
for o in $(find "$DBG" -name '*.o' | sort); do
    case "$o" in
    */main.o) ;;
    *) OBJS="$OBJS $o" ;;
    esac
done

cc -std=c11 -Wall -Wextra -Werror -D_GNU_SOURCE -I"$ROOT/include" \
    -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
    -o "$OUT" "$ROOT/tests/fuzz/fuzz_pe.c" $OBJS -lpthread -ldl -lm || exit 2

ITER=${FUZZ_ITER:-3000}
total_crashes=0
for seed in "$ROOT"/tests/bin/*.exe; do
    [ -e "$seed" ] || continue
    echo "== fuzzing seed $(basename "$seed") ($ITER iterations) =="
    ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
        "$OUT" "$seed" "$ITER" "$CRASHES" || total_crashes=$((total_crashes+1))
done

if [ "$total_crashes" = 0 ]; then
    echo "FUZZ: no crashes (all inputs handled or cleanly rejected)"
    exit 0
else
    echo "FUZZ: $total_crashes seed(s) produced crashes — inputs saved in tests/fuzz/crashes/"
    exit 1
fi
