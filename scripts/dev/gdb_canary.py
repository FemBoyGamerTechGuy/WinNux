#!/usr/bin/env python3
# gdb_canary.py — run inside gdb (python): find who smashes the canary of
# load_string_lookup (called from u32_LoadStringA) in bin/winnux32.
#
# Usage:
#   qemu-i386 -g 12341 -L <root32> bin/winnux32 run app.exe [args] &
#   gdb -q -ex "set pagination off" \
#       -ex "python exec(open('scripts/dev/gdb_canary.py').read())" bin/winnux32
#
# Method: break right after the canary store (0x80623ee); find the call
# frame whose return address lands inside u32_LoadStringA; hardware-watch
# the 4 canary bytes; continue until the value diverges from the freshly
# stored canary (the entry store restores it each call) -> dump writer PC.
import gdb

BRK_AFTER_CANARY_STORE = 0x80623ee          # mov %ebx,0x1c(%esp) done
RETADDR_SLOT_OFF = 0x3c                     # esp at 0x80623ee
CANARY_OFF = 0x1c
LOADSTRING_A_RANGE = (0x8062490, 0x8062540) # u32_LoadStringA

gdb.execute("set pagination off")
gdb.execute("set confirm off")
gdb.execute("target remote :12341")

# stop at exec entry is already done by -g; set our breakpoint
gdb.execute("break *%d" % BRK_AFTER_CANARY_STORE)

can_addr = None
for attempt in range(4000):
    gdb.execute("continue")
    esp = int(gdb.parse_and_eval("$esp"))
    ra = int(gdb.parse_and_eval("*(unsigned int*)%d" % (esp + RETADDR_SLOT_OFF)))
    if LOADSTRING_A_RANGE[0] <= ra < LOADSTRING_A_RANGE[1]:
        can_addr = esp + CANARY_OFF
        can_val = int(gdb.parse_and_eval("*(unsigned int*)%d" % can_addr))
        print("TARGET FRAME: esp=0x%x ra=0x%x canary@0x%x=0x%x"
              % (esp, ra, can_addr, can_val))
        break
if can_addr is None:
    print("never saw u32_LoadStringA->load_string_lookup call")
    gdb.execute("detach")
else:
    gdb.execute("delete")
    gdb.execute("set can-use-hw-watchpoints 0")
    gdb.execute("watch *(unsigned int*)%d" % can_addr)
    smashed = False
    for i in range(500):
        gdb.execute("continue")
        v = int(gdb.parse_and_eval("*(unsigned int*)%d" % can_addr))
        if v != can_val:
            print("SMASH at watchpoint stop %d: canary 0x%x -> 0x%x"
                  % (i, can_val, v))
            gdb.execute("info registers eip esp ebp eax ebx ecx edx esi edi")
            print("--- code around writer ---")
            try:
                gdb.execute("x/24i $eip-32")
            except gdb.error:
                pass
            print("--- stack words ---")
            gdb.execute("x/24xw $esp")
            smashed = True
            break
    if not smashed:
        print("no smash observed in 500 watchpoint stops")
    gdb.execute("detach")
