#!/usr/bin/env python3
"""gdbstub_session.py — ONE persistent gdb-remote session driving the
qemu-i386 gdbstub of the Inno engine child.

  gdbstub_session.py PORT SNAPFILE SNAP_AFTER_SECONDS

Connects (retrying until the engine's qemu listens), immediately sends
'c' (continue — qemu -g parks the vCPU until then), sleeps, then
interrupts, reads registers + the live stack, and writes the snapshot.
One process = one session (qemu's stub does not survive a re-attach
after the first client detaches).
"""
import socket
import sys
import time


def connect(port, deadline_s):
    while time.time() < deadline_s:
        try:
            return socket.create_connection(("127.0.0.1", port), timeout=5)
        except OSError:
            time.sleep(1)
    raise SystemExit("no stub")


class P:
    def __init__(self, s):
        self.s = s
        self.buf = b""

    def send(self, data):
        ck = 0
        for ch in data.encode():
            ck = (ck + ch) & 0xFF
        self.s.sendall(f"${data}#{ck:02x}".encode())

    def sendraw(self, data):
        self.s.sendall(data)

    def recv(self, timeout=30):
        deadline = time.time() + timeout
        while time.time() < deadline:
            start = self.buf.find(b"$")
            if start >= 0:
                end = self.buf.find(b"#", start)
                if end >= 0 and end + 3 <= len(self.buf):
                    pkt = self.buf[start + 1:end]
                    self.buf = self.buf[end + 3:]
                    self.s.sendall(b"+")
                    return pkt.decode("latin1")
            try:
                chunk = self.s.recv(4096)
                if not chunk:
                    return None
                self.buf += chunk
            except socket.timeout:
                return None
        return None

    def cmd(self, data, timeout=10):
        self.send(data)
        # drain any pending '+'
        return self.recv(timeout)


CODE = [
    (0x401000, 0x49a000, "ENGINE"),
    (0x804aa40, 0x8091200, "WINNUX32"),
    (0x4083d000, 0x40a70000, "LIBC"),
    (0x40801000, 0x40838000, "LD"),
]


def cls(v):
    for lo, hi, t in CODE:
        if lo <= v < hi:
            return t
    return None


def main():
    port, snapfile, wait_s = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])
    s = connect(port, time.time() + 180)
    p = P(s)
    p.cmd("qSupported", 5)          # hello (reply optional)
    p.send("c")                      # vCPU GO
    print("continued; sleeping", wait_s, file=sys.stderr)
    time.sleep(wait_s)
    # interrupt
    p.sendraw(b"\x03")
    stop = p.recv(15)
    print("stop reply:", stop, file=sys.stderr)
    out = open(snapfile, "w")
    print("stop reply:", stop, file=out)
    regs = p.cmd("g", 10)
    if not regs:
        print("no regs", file=out)
        print("REG-FAIL")
        return 1
    b = bytes.fromhex(regs)
    names = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "eip",
             "eflags", "cs", "ss", "ds", "es", "fs", "gs"]
    r = {}
    for i, n in enumerate(names):
        if len(b) >= (i + 1) * 4:
            r[n] = int.from_bytes(b[i * 4:(i + 1) * 4], "little")
    print("regs:", {k: hex(v) for k, v in r.items()}, file=out)
    esp, ebp, eip = r.get("esp", 0), r.get("ebp", 0), r.get("eip", 0)
    print(f"\n== EIP {eip:#x} ({cls(eip)}) ESP {esp:#x} EBP {ebp:#x}",
          file=out)
    # disasm context bytes at eip
    ctx = None
    for lo, hi, _t in CODE:
        pass
    data = None
    try:
        m = p.cmd(f"m{esp:x},4000", 15)
        if m and not m.startswith("E"):
            data = bytes.fromhex(m)
    except Exception as e:
        print("mem err", e, file=out)
    if data:
        print("live stack scan (esp..+16k):", file=out)
        for off in range(0, len(data) - 4, 4):
            v = int.from_bytes(data[off:off + 4], "little")
            t = cls(v)
            if t:
                print(f"  {esp + off:#010x}: {v:#010x} {t}", file=out)
    # ebp chain
    print("ebp chain:", file=out)
    seen = 0
    while ebp and seen < 50:
        m = p.cmd(f"m{ebp:x},8", 10)
        if not m or m.startswith("E"):
            break
        f = bytes.fromhex(m)
        saved = int.from_bytes(f[0:4], "little")
        ret = int.from_bytes(f[4:8], "little")
        print(f"  ebp={ebp:#x} ret={ret:#x} ({cls(ret)})", file=out)
        if saved <= ebp:
            break
        ebp = saved
        seen += 1
    out.close()
    print("SNAP-OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
