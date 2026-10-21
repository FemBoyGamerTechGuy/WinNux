#!/usr/bin/env python3
"""gdbstub_client.py — minimal GDB remote-serial client for qemu-i386 -g.

Drives the qemu gdbstub WITHOUT gdb: continue, break-in, dump registers,
read guest memory, and reconstruct the live guest call stack.

Usage:
  gdbstub_client.py continue PORT           # attach + continue immediately
  gdbstub_client.py snapshot PORT OUTFILE   # break in; regs + stack scan
"""
import socket
import sys
import time


class Stub:
    def __init__(self, port):
        self.s = socket.create_connection(("127.0.0.1", port), timeout=30)
        self.buf = b""

    def _send(self, data):
        ck = 0
        for ch in data.encode():
            ck = (ck + ch) & 0xFF
        pkt = f"${data}#{ck:02x}".encode()
        self.s.sendall(pkt)
        # wait for '+'
        self._drain_ack()

    def _drain_ack(self):
        deadline = time.time() + 2
        while time.time() < deadline:
            try:
                b = self.s.recv(1)
            except socket.timeout:
                return
            if b == b"+":
                return

    def recv_pkt(self, timeout=60):
        deadline = time.time() + timeout
        raw = b""
        while time.time() < deadline:
            need = max(1, 4096 - len(self.buf))
            try:
                chunk = self.s.recv(need)
            except socket.timeout:
                return None
            if not chunk:
                return None
            self.buf += chunk
            # look for $...#
            start = self.buf.find(b"$")
            if start >= 0:
                end = self.buf.find(b"#", start)
                if end >= 0 and end + 2 < len(self.buf) + 1:
                    if end + 3 <= len(self.buf):
                        pkt = self.buf[start + 1:end]
                        self.buf = self.buf[end + 3:]
                        self.s.sendall(b"+")
                        return pkt.decode("latin1")
        return None

    def cmd(self, data, timeout=60):
        self._send(data)
        return self.recv_pkt(timeout)

    def continue_run(self):
        self._send("c")

    def interrupt(self):
        self.s.sendall(b"\x03")
        return self.recv_pkt(10)

    def regs(self):
        r = self.cmd("g", 10)
        return r

    def mem(self, addr, length):
        r = self.cmd(f"m{addr:x},{length:x}", 10)
        if not r or r.startswith("E"):
            return None
        try:
            return bytes.fromhex(r)
        except ValueError:
            return None


def parse_i386_regs(hexstr):
    """i386 'g': eax,ecx,edx,ebx,esp,ebp,esi,edi,eip,eflags,cs..gs"""
    b = bytes.fromhex(hexstr)
    names = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "eip",
             "eflags", "cs", "ss", "ds", "es", "fs", "gs"]
    out = {}
    for i, n in enumerate(names):
        if len(b) >= (i + 1) * 4:
            out[n] = int.from_bytes(b[i * 4:(i + 1) * 4], "little")
    return out


CODE_RANGES = [
    (0x401000, 0x49a000, "ENGINE"),
    (0x804aa40, 0x8091200, "WINNUX32"),
    (0x4083d000, 0x40a70000, "LIBC"),
    (0x40801000, 0x40838000, "LD"),
]


def classify(v):
    for lo, hi, tag in CODE_RANGES:
        if lo <= v < hi:
            return tag
    return None


def main():
    mode, port, *rest = sys.argv[1:]
    port = int(port)
    st = Stub(port)
    if mode == "continue":
        st.continue_run()
        print("continued")
        # keep the socket open so the stub stays attached? qemu continues
        # regardless; we just exit.
        time.sleep(0.2)
        return 0
    if mode == "snapshot":
        out = open(rest[0], "w")
        rep = st.interrupt()
        print("interrupt reply:", rep, file=out)
        regs = st.regs()
        r = parse_i386_regs(regs) if regs else {}
        print("regs:", {k: hex(v) for k, v in r.items()}, file=out)
        esp = r.get("esp", 0)
        eip = r.get("eip", 0)
        print(f"eip={eip:#x} esp={esp:#x}", file=out)
        # walk the stack: read 16KB from esp upward
        data = st.mem(esp, 0x4000)
        if data:
            print("live stack code pointers (esp..esp+16k):", file=out)
            for off in range(0, len(data) - 4, 4):
                v = int.from_bytes(data[off:off + 4], "little")
                tag = classify(v)
                if tag:
                    print(f"  {esp + off:#010x}: {v:#010x} {tag}", file=out)
        # ebp chain
        ebp = r.get("ebp", 0)
        seen = 0
        while ebp and seen < 40:
            frame = st.mem(ebp, 8)
            if not frame:
                break
            saved_ebp = int.from_bytes(frame[0:4], "little")
            ret = int.from_bytes(frame[4:8], "little")
            tag = classify(ret) or "?"
            print(f"  frame ebp={ebp:#x} ret={ret:#x} ({tag})", file=out)
            if saved_ebp <= ebp:
                break
            ebp = saved_ebp
            seen += 1
        out.close()
        print("snapshot written")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
