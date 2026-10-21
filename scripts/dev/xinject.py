#!/usr/bin/env python3
"""xinject.py — REAL server-side input injection via the XTEST extension.

Dev-only host tool (like xtree.c): speaks XTEST 2.2 so injected events go
through the SERVER's normal delivery path — true pointer position, implicit
grab on press, motion routing during the grab, EnterNotify/LeaveNotify,
wheel as buttons 4/5. XSendEvent (the old harness) bypasses all of that,
which is why things can "look right" under Xvfb but fail with a real
pointer on the user's machine.

Needs python-xlib (pip install --break-system-packages python-xlib).

Usage (DISPLAY env or :95 default):
  tree [pattern]              window tree, absolute geometry; filter by title regex
  waitwin PATTERN [secs]       poll until a matching mapped window exists; print id line
  click WIN X Y [button]       XTEST press+release at window-relative (X,Y)
  rclick X Y [button]         same at root-absolute coords
  press WIN X Y / release WIN X Y   split click (grab stays open between)
  drag WIN X1 Y1 X2 Y2 [steps]     press, interpolated motions, release
  rdrag X1 Y1 X2 Y2 [steps]        root-absolute drag
  wheel up|down [n]           XTEST buttons 4/5
  key NAME                    keysym name (Return, Escape, space, Alt_L+understood via press+release)
  chord MOD NAME              press MOD, press NAME, release both (Alt+n etc.)
  type TEXT                   type ASCII text
  query                       XQueryPointer
  shot FILE [WIN]             PPM screenshot of root or WIN
  focus WIN                   XSetInputFocus
"""
import re
import sys
import time

sys.path.insert(0, '/home/z/.local/lib/python3.13/site-packages')

from Xlib import X, XK  # noqa: E402
from Xlib.display import Display  # noqa: E402
from Xlib.ext import xtest  # noqa: E402


def open_display():
    d = Display()
    # Fail loudly if XTEST is missing (vanilla Xvfb ships it).
    try:
        ver = d.xtest_get_version(2, 2)
    except Exception as e:  # pragma: no cover
        print(f"xinject: no XTEST extension: {e}", file=sys.stderr)
        raise SystemExit(3)
    return d


def root_of(d):
    return d.screen().root


def win_geom(d, w):
    """Absolute (x, y, width, height) of window w on the root — via the
    parent-walk (see to_root note; translate_coords is broken here)."""
    x, y = to_root(d, w, 0, 0)
    g = w.get_geometry()
    return x, y, g.width, g.height


def find_by_hex(d, hexid):
    return d.create_resource_object('window', int(hexid, 0))


def dump_tree(d, w, depth, pat, out):
    try:
        name = w.get_wm_name()
    except Exception:
        name = None
    try:
        wa = w.get_attributes()
    except Exception:
        return
    if not name:
        name = ''
    if isinstance(name, bytes):
        name = name.decode('latin1', 'replace')
    if depth <= 6 or pat:
        x, y, wd, ht = win_geom(d, w)
        line = (f"{w.id:#010x}  {name!r}  {wd}x{ht} at {x},{y} "
                f"map={'IsViewable' if wa.map_state == X.IsViewable else wa.map_state}")
        if not pat or re.search(pat, name):
            out.append(line)
    kids = w.query_tree().children
    for k in kids:
        dump_tree(d, k, depth + 1, pat, out)


def to_root(d, w, x, y):
    """Window-relative -> root-absolute, by walking the parent chain and
    summing geometry positions. (translate_coords returns garbage in this
    python-xlib build - verified empirically: window truly at (222,204)
    reported as (-222,-204); raw get_geometry().x/.y is the server truth.)"""
    r = root_of(d)
    cx, cy = x, y
    cur = w
    while True:
        g = cur.get_geometry()
        cx += g.x
        cy += g.y
        t = cur.query_tree()
        par = t.parent
        pid = par if isinstance(par, int) else (par.id if par else 0)
        if not pid or pid == r.id:
            break
        cur = d.create_resource_object('window', pid)
    return cx, cy


def motion(d, x, y):
    xtest.fake_input(d, X.MotionNotify, detail=0, x=int(x), y=int(y))
    d.flush()


def button(d, evtype, btn):
    xtest.fake_input(d, evtype, detail=btn)
    d.flush()


def sleep_or(v, default=0.06):
    try:
        time.sleep(float(v))
    except ValueError:
        time.sleep(default)


def click_root(d, x, y, btn=1):
    motion(d, x, y)
    time.sleep(0.02)
    button(d, X.ButtonPress, btn)
    time.sleep(0.03)
    button(d, X.ButtonRelease, btn)
    d.flush()


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return 0
    d = open_display()
    cmd, args = args[0], args[1:]

    if cmd == 'tree':
        pat = args[0] if args else None
        out = []
        dump_tree(d, root_of(d), 0, pat, out)
        print('\n'.join(out))
        return 0

    if cmd == 'waitwin':
        pat = args[0]
        deadline = time.time() + (float(args[1]) if len(args) > 1 else 60.0)
        while time.time() < deadline:
            out = []
            dump_tree(d, root_of(d), 0, pat, out)
            for line in out:
                if 'IsViewable' in line:
                    print(line)
                    return 0
            time.sleep(0.4)
        print('waitwin: timeout', file=sys.stderr)
        return 4

    if cmd in ('click', 'press', 'release'):
        w = find_by_hex(d, args[0])
        x, y = to_root(d, w, int(args[1]), int(args[2]))
        btn = int(args[3]) if len(args) > 3 else 1
        if cmd == 'click':
            click_root(d, x, y, btn)
            print(f"click win {args[0]} rel {args[1]},{args[2]} -> root {x},{y}")
        elif cmd == 'press':
            motion(d, x, y)
            time.sleep(0.02)
            button(d, X.ButtonPress, btn)
            print(f"press at root {x},{y}")
        else:
            button(d, X.ButtonRelease, btn)
            print(f"release at root {x},{y}")
        return 0

    if cmd == 'rclick':
        click_root(d, int(args[0]), int(args[1]), int(args[2]) if len(args) > 2 else 1)
        return 0

    if cmd in ('drag', 'rdrag'):
        if cmd == 'drag':
            w = find_by_hex(d, args[0])
            x1, y1 = to_root(d, w, int(args[1]), int(args[2]))
            x2, y2 = to_root(d, w, int(args[3]), int(args[4]))
        else:
            x1, y1, x2, y2 = (int(a) for a in args[:4])
        steps = int(args[5]) if cmd == 'drag' and len(args) > 5 else (
            int(args[4]) if cmd == 'rdrag' and len(args) > 4 else 8)
        motion(d, x1, y1)
        time.sleep(0.05)
        button(d, X.ButtonPress, 1)
        time.sleep(0.05)
        for i in range(1, steps + 1):
            motion(d, x1 + (x2 - x1) * i // steps, y1 + (y2 - y1) * i // steps)
            time.sleep(0.04)
        time.sleep(0.08)
        button(d, X.ButtonRelease, 1)
        d.flush()
        print(f"drag {x1},{y1} -> {x2},{y2} ({steps} steps)")
        return 0

    if cmd == 'wheel':
        direction = args[0]
        n = int(args[1]) if len(args) > 1 else 1
        btn = 4 if direction == 'up' else 5
        for _ in range(n):
            button(d, X.ButtonPress, btn)
            time.sleep(0.03)
            button(d, X.ButtonRelease, btn)
            time.sleep(0.05)
        d.flush()
        print(f"wheel {direction} x{n}")
        return 0

    if cmd == 'key' or cmd == 'chord':
        XK.load_keysym_group('xf86')
        if cmd == 'key':
            names = [args[0]]
        else:
            names = [args[0], args[1]]
        codes = []
        for nm in names:
            ks = XK.string_to_keysym(nm)
            if ks == X.NoSymbol:
                print(f"xinject: unknown keysym {nm}", file=sys.stderr)
                return 5
            kc = d.keysym_to_keycode(ks)
            if not kc:
                print(f"xinject: no keycode for {nm}", file=sys.stderr)
                return 5
            codes.append(kc)
        xtest.fake_input(d, X.KeyPress, detail=codes[0])
        if len(codes) > 1:
            xtest.fake_input(d, X.KeyPress, detail=codes[1])
            xtest.fake_input(d, X.KeyRelease, detail=codes[1])
        xtest.fake_input(d, X.KeyRelease, detail=codes[0])
        d.flush()
        print(f"key {'+'.join(names)}")
        return 0

    if cmd == 'type':
        XK.load_keysym_group('xf86')
        for ch in args[0]:
            ks = XK.string_to_keysym(ch if ch.isalnum() else {
                ' ': 'space', '.': 'period', '/': 'slash', '-': 'minus',
                '\\': 'backslash', '_': 'underscore', ':': 'colon',
                ';': 'semicolon', '\n': 'Return', '\t': 'Tab',
            }.get(ch, ch))
            kc = d.keysym_to_keycode(ks)
            if not kc:
                print(f"xinject: no keycode for {ch!r}", file=sys.stderr)
                return 5
            xtest.fake_input(d, X.KeyPress, detail=kc)
            xtest.fake_input(d, X.KeyRelease, detail=kc)
        d.flush()
        print(f"typed {len(args[0])} chars")
        return 0

    if cmd == 'query':
        p = root_of(d).query_pointer()
        print(f"pointer at {p.root_x},{p.root_y} child={hex(p.child) if isinstance(p.child, int) else hex(p.child.id)}")
        return 0

    if cmd == 'shot':
        path = args[0]
        r = root_of(d)
        w = find_by_hex(d, args[1]) if len(args) > 1 else r
        if w.id == r.id:
            g = r.get_geometry()
            wx = wy = 0
            wd, ht = g.width, g.height
        else:
            wx, wy, wd, ht = win_geom(d, w)
        im = r.get_image(max(wx, 0), max(wy, 0), wd, ht, 2, 0xffffffff)  # ZPixmap crop
        data = im.data
        bpl = len(data) // ht
        with open(path, 'wb') as f:
            f.write(f"P6\n{wd} {ht}\n255\n".encode())
            for row in range(ht):
                line = data[row * bpl: row * bpl + wd * 4]
                out = bytearray(wd * 3)
                for i in range(wd):
                    # 32bpp LSBFirst: bytes = [B, G, R, pad]
                    out[3 * i] = line[4 * i + 2]      # R
                    out[3 * i + 1] = line[4 * i + 1]  # G
                    out[3 * i + 2] = line[4 * i]      # B
                f.write(out)
        print(f"shot {path} {wd}x{ht} bpl={bpl}")
        return 0

    if cmd == 'focus':
        w = find_by_hex(d, args[0])
        w.set_input_focus(X.RevertToParent, X.CurrentTime)
        d.flush()
        print("focus set")
        return 0

    print(f"xinject: unknown command {cmd}", file=sys.stderr)
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
