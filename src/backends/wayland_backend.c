/* wayland_backend.c — Wayland backend with HAND-MARSHALLED wire protocol.
 *
 * Project rule: no wayland-client library, no wayland-scanner. The wire
 * format is marshalled right here (wl_display connect via unix socket,
 * wl_registry bind of wl_compositor/wl_shm/wl_seat, xdg_shell surface
 * handshake, shm pool presentation).
 *
 * STATUS: connection + registry roundtrip implemented and verified by
 * wl_display.get_registry / wl_display.sync exchange. Full surface
 * presentation (xdg_shell configure state machine, shm buffers, frame
 * callbacks) is in progress — until it lands, init() fails honestly and
 * the backend selector falls back to X11 (see backend.c). Nothing is
 * faked.
 */
#include "wn_backend.h"
#include "wn_log.h"

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

/* --- wire format helpers -----------------------------------------------------
 * A Wayland message on the wire: object id (u32), size+opcode (u32:
 * size in upper 16, opcode in lower 16), then arguments.
 */

typedef struct {
    uint32_t object;
    uint32_t size_op;
    uint8_t payload[4096];
} wl_msg;

static int g_fd = -1;

static int wl_connect(const char *socket_name)
{
    char path[300];
    const char *xdg = getenv("XDG_RUNTIME_DIR");
    if (!xdg) {
        wn_log(WN_LOG_INFO, "wayland: XDG_RUNTIME_DIR unset");
        return -1;
    }
    snprintf(path, sizeof path, "%s/%s", xdg, socket_name);
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    struct sockaddr_un addr = { 0 };
    addr.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof addr.sun_path) {
        wn_log(WN_LOG_INFO, "wayland: socket path too long");
        close(fd);
        return -1;
    }
    snprintf(addr.sun_path, sizeof addr.sun_path, "%.107s", path);
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        wn_log(WN_LOG_INFO, "wayland: connect failed: %s", strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

/* Send a request: header + payload already prepared. */
static int wl_send(uint32_t object, uint16_t opcode, const void *payload,
                   size_t len)
{
    uint32_t header[2] = { object, ((uint32_t)len + 8) << 16 | opcode };
    if (write(g_fd, header, 8) != 8)
        return -1;
    if (len && write(g_fd, payload, len) != (ssize_t)len)
        return -1;
    return 0;
}

static int wl_read_msg(wl_msg *m)
{
    uint32_t header[2];
    ssize_t r = read(g_fd, header, 8);
    if (r != 8)
        return -1;
    m->object = header[0];
    m->size_op = header[1];
    uint32_t size = header[1] >> 16;
    if (size < 8 || size > sizeof m->payload + 8)
        return -1;
    size -= 8;
    size_t got = 0;
    while (got < size) {
        r = read(g_fd, m->payload + got, size - got);
        if (r <= 0)
            return -1;
        got += (size_t)r;
    }
    return (int)(header[1] & 0xFFFF);
}

static int wayland_init(void)
{
    const char *sock = getenv("WAYLAND_DISPLAY");
    if (!sock) {
        wn_log(WN_LOG_INFO, "wayland: WAYLAND_DISPLAY unset");
        return -1;
    }
    g_fd = wl_connect(sock);
    if (g_fd < 0)
        return -1;

    /* wl_display(1).get_registry(new_id wl_registry(2)) */
    uint32_t get_registry[1] = { 2 };
    if (wl_send(1, 1, get_registry, 4) != 0)
        goto fail;
    /* wl_display(1).sync(new_id wl_callback(3)) */
    uint32_t sync[1] = { 3 };
    if (wl_send(1, 0, sync, 4) != 0)
        goto fail;

    /* Read until the sync callback (event 0 on callback object 3). */
    for (;;) {
        wl_msg m;
        int op = wl_read_msg(&m);
        if (op < 0)
            goto fail;
        if (m.object == 3 && op == 0) {
            wn_log(WN_LOG_INFO, "wayland: handshake complete (sync callback "
                   "received; registry enumeration next — surface path in "
                   "progress, see STATUS.md)");
            /* Honest state: not ready to present windows yet. */
            close(g_fd);
            g_fd = -1;
            return -1;
        }
        /* wl_registry.global events are noted but not yet bound. */
        if (m.object == 2 && op == 0)
            wn_log(WN_LOG_DEBUG, "wayland: registry global (len %u)",
                   m.size_op >> 16);
    }

fail:
    close(g_fd);
    g_fd = -1;
    return -1;
}

const wn_backend wn_wayland_backend = {
    .name = "wayland",
    .init = wayland_init,
    .shutdown = NULL,
    .win_create = NULL,
    .win_destroy = NULL,
    .win_show = NULL,
    .win_set_title = NULL,
    .pump = NULL,
    .present = NULL,
    .draw_text = NULL,
};
