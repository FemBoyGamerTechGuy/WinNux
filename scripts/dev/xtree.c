/* xtree.c — HOST-ONLY dev tool for driving the guest GUI under Xvfb.
 *
 * NOT part of the WinNux product: compiled with `cc -O2 -o /tmp/xtree
 * scripts/dev/xtree.c -lX11` and linked against host libX11 directly.
 * (A previous version of this tool was lost by never being committed —
 * this one lives in git.)
 *
 * Usage:
 *   xtree :95 tree                     dump window tree + geometry
 *   xtree :95 shot out.ppm             capture the root screen to PPM
 *   xtree :95 click <xwin> <x> <y>     synthetic ButtonPress+Release
 *   xtree :95 move  <xwin> <x> <y>     synthetic MotionNotify
 *   xtree :95 key   <xwin> <keysym>    synthetic KeyPress+Release
 */
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void dump_tree(Display *d, Window w, int depth)
{
    Window r, parent, *kids = NULL;
    unsigned nkids = 0;
    XWindowAttributes wa;
    char *name = NULL;
    int x = 0, y = 0;
    Window child;
    if (XGetWindowAttributes(d, w, &wa) &&
        XTranslateCoordinates(d, w, DefaultRootWindow(d), 0, 0, &x, &y, &child)) {
        /* x,y = absolute origin of the window */
    }
    if (XFetchName(d, w, &name) == 0 || !name)
        name = NULL;
    printf("%*s0x%lx %dx%d at %d,%d%s%s map=%s\n", depth * 2, "", w,
           wa.width, wa.height, x - wa.border_width, y - wa.border_width,
           name ? " \"" : "", name ? name : "",
           wa.map_state == IsViewable ? "viewable" : "hidden");
    XFree(name);
    if (XQueryTree(d, w, &r, &parent, &kids, &nkids)) {
        for (unsigned i = 0; i < nkids; i++)
            dump_tree(d, kids[i], depth + 1);
        XFree(kids);
    }
}

static void shot(Display *d, const char *out)
{
    Window root = DefaultRootWindow(d);
    int W = DisplayWidth(d, DefaultScreen(d));
    int H = DisplayHeight(d, DefaultScreen(d));
    XImage *img = XGetImage(d, root, 0, 0, W, H, AllPlanes, ZPixmap);
    if (!img) {
        fprintf(stderr, "XGetImage failed\n");
        exit(1);
    }
    FILE *f = fopen(out, "wb");
    if (!f) {
        perror(out);
        exit(1);
    }
    fprintf(f, "P6\n%d %d\n255\n", W, H);
    for (int y = 0; y < H; y++) {
        for (int x = 0; x < W; x++) {
            unsigned long px = XGetPixel(img, x, y);
            unsigned char rgb[3] = {
                (unsigned char)((px >> 16) & 0xFF),
                (unsigned char)((px >> 8) & 0xFF),
                (unsigned char)(px & 0xFF),
            };
            fwrite(rgb, 1, 3, f);
        }
    }
    fclose(f);
    XDestroyImage(img);
    printf("wrote %s (%dx%d)\n", out, W, H);
}

static void send_click(Display *d, Window w, int x, int y, int press)
{
    XButtonEvent ev;
    memset(&ev, 0, sizeof ev);
    ev.type = press ? ButtonPress : ButtonRelease;
    ev.display = d;
    ev.window = w;
    ev.root = DefaultRootWindow(d);
    ev.subwindow = None;
    ev.time = CurrentTime;
    ev.x = x;
    ev.y = y;
    ev.x_root = x;
    ev.y_root = y;
    ev.state = press ? 0 : Button1Mask;
    ev.button = 1;
    ev.same_screen = 1;
    XSendEvent(d, w, True, press ? ButtonPressMask : ButtonReleaseMask,
               (XEvent *)&ev);
}

static void send_move(Display *d, Window w, int x, int y)
{
    XMotionEvent ev;
    memset(&ev, 0, sizeof ev);
    ev.type = MotionNotify;
    ev.display = d;
    ev.window = w;
    ev.root = DefaultRootWindow(d);
    ev.subwindow = None;
    ev.time = CurrentTime;
    ev.x = x;
    ev.y = y;
    ev.x_root = x;
    ev.y_root = y;
    ev.state = 0;
    ev.is_hint = 0;
    ev.same_screen = 1;
    XSendEvent(d, w, True, PointerMotionMask, (XEvent *)&ev);
}

static void send_key(Display *d, Window w, long sym)
{
    XKeyEvent ev;
    memset(&ev, 0, sizeof ev);
    ev.display = d;
    ev.window = w;
    ev.root = DefaultRootWindow(d);
    ev.subwindow = None;
    ev.time = CurrentTime;
    ev.same_screen = 1;
    KeyCode kc = XKeysymToKeycode(d, sym);
    if (!kc) {
        fprintf(stderr, "no keycode for keysym 0x%lx\n", sym);
        return;
    }
    ev.type = KeyPress;
    ev.keycode = kc;
    XSendEvent(d, w, True, KeyPressMask, (XEvent *)&ev);
    ev.type = KeyRelease;
    ev.state = 0;
    XSendEvent(d, w, True, KeyReleaseMask, (XEvent *)&ev);
    XFlush(d);
}

/* Synthetic window-manager close: WM_DELETE_WINDOW ClientMessage — exactly
 * what a WM sends when the user clicks the title-bar X. */
static void send_close(Display *d, Window w)
{
    Atom wm_delete = XInternAtom(d, "WM_DELETE_WINDOW", False);
    if (!wm_delete) {
        fprintf(stderr, "no WM_DELETE_WINDOW atom\n");
        return;
    }
    XClientMessageEvent ev;
    memset(&ev, 0, sizeof ev);
    ev.type = ClientMessage;
    ev.display = d;
    ev.window = w;
    ev.message_type = wm_delete;
    ev.format = 32;
    ev.data.l[0] = (long)wm_delete;
    XSendEvent(d, w, False, NoEventMask, (XEvent *)&ev);
    XFlush(d);
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <display> tree|shot|click|move|key ...\n",
                argv[0]);
        return 2;
    }
    Display *d = XOpenDisplay(argv[1]);
    if (!d) {
        fprintf(stderr, "cannot open display %s\n", argv[1]);
        return 1;
    }
    if (!strcmp(argv[2], "tree")) {
        dump_tree(d, DefaultRootWindow(d), 0);
    } else if (!strcmp(argv[2], "shot") && argc >= 4) {
        shot(d, argv[3]);
    } else if (!strcmp(argv[2], "click") && argc >= 6) {
        Window w = strtoul(argv[3], NULL, 0);
        int x = atoi(argv[4]), y = atoi(argv[5]);
        send_click(d, w, x, y, 1);
        XFlush(d);
        usleep(30000);
        send_click(d, w, x, y, 0);
        XFlush(d);
        printf("clicked 0x%lx at %d,%d\n", (unsigned long)w, x, y);
    } else if (!strcmp(argv[2], "move") && argc >= 6) {
        Window w = strtoul(argv[3], NULL, 0);
        send_move(d, w, atoi(argv[4]), atoi(argv[5]));
        XFlush(d);
    } else if (!strcmp(argv[2], "key") && argc >= 5) {
        Window w = strtoul(argv[3], NULL, 0);
        long sym = strtol(argv[4], NULL, 0);
        send_key(d, w, sym);
    } else if (!strcmp(argv[2], "close") && argc >= 4) {
        Window w = strtoul(argv[3], NULL, 0);
        send_close(d, w);
        printf("sent WM_DELETE to 0x%lx\n", (unsigned long)w);
    } else {
        fprintf(stderr, "bad command\n");
        return 2;
    }
    XCloseDisplay(d);
    return 0;
}
