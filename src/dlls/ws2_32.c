/* ws2_32.c — builtin ws2_32.dll: Winsock over host BSD sockets.
 *
 * Winsock SOCKET = 64-bit handle; our sockets live in the handle table
 * (type WN_HTYPE_FILE? no: own tag inside). fd_set layouts DIFFER between
 * Winsock (count + SOCKET array) and BSD (bitmap) — translated here.
 */
#include "wn_dll.h"
#include "wn_process.h"
#include "wn_handle.h"
#include "wn_log.h"
#include "wn_util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* WSA error codes (subset). */
#define WSAEWOULDBLOCK  10035
#define WSAEINVAL        10022
#define WSAENOTSOCK      10038
#define WSAEAFNOSUPPORT  10047
#define WSAECONNREFUSED  10061

static uint32_t g_wsa_err;

static void set_wsa_from_errno(void)
{
    switch (errno) {
    case EAGAIN:      g_wsa_err = WSAEWOULDBLOCK; break;
    case EINVAL:      g_wsa_err = WSAEINVAL; break;
    case EBADF:       g_wsa_err = WSAENOTSOCK; break;
    case EAFNOSUPPORT: g_wsa_err = WSAEAFNOSUPPORT; break;
    case ECONNREFUSED: g_wsa_err = WSAECONNREFUSED; break;
    default:          g_wsa_err = (uint32_t)errno | 0x10000; break;
    }
    wn_last_error_set(g_wsa_err);
}

typedef struct {
    int fd;
    int nonblocking;
} wn_sock;

static wn_sock *sock_of(uint64_t s)
{
    wn_object *o = wn_handle_get((wn_handle)(uintptr_t)s, WN_HTYPE_FILE);
    if (!o)
        return NULL;
    return o->ptr;   /* sockets stored with the FILE tag; fd validates us */
}

static uint64_t sock_new(int fd)
{
    wn_sock *sk = wn_xcalloc(1, sizeof *sk);
    sk->fd = fd;
    return (uint64_t)(uintptr_t)wn_handle_alloc(WN_HTYPE_FILE, sk);
}

/* --- startup ---------------------------------------------------------------- */

/* WSADATA x64: wVersion(2), wHighVersion(2), iMaxSockets(2), iMaxUdpDg(2),
 * szDescription[257], szSystemStatus[129], iMaxSockets2? — 400 bytes safe. */
static WN_API int32_t w2_WSAStartup(uint32_t requested, void *data)
{
    (void)requested;   /* we always speak 2.2 */
    memset(data, 0, 400);
    uint16_t w = 0x0202;
    memcpy(data, &w, 2);
    memcpy((uint8_t *)data + 2, &w, 2);
    snprintf((char *)data + 4, 257, "WinNux Winsock 2.2");
    snprintf((char *)data + 261, 129, "Running");
    return 0;
}

static WN_API int32_t w2_WSACleanup(void)
{
    return 0;
}

static WN_API int32_t w2_WSAGetLastError(void)
{
    return (int32_t)g_wsa_err;
}

/* --- core sockets ------------------------------------------------------------- */

static WN_API uint64_t w2_socket(int32_t af, int32_t type, int32_t proto)
{
    int fd = socket(af, type, proto);
    if (fd < 0) {
        set_wsa_from_errno();
        return (uint64_t)(uintptr_t)-1;
    }
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    /* Windows lets a listener rebind right after close (no TIME_WAIT
     * collision); SO_REUSEADDR reproduces that behavior on Linux. */
    if (type == SOCK_STREAM) {
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    }
    return sock_new(fd);
}

static WN_API int32_t w2_closesocket(wn_abiword s)
{
    wn_sock *sk = sock_of(s);
    if (!sk) {
        g_wsa_err = WSAENOTSOCK;
        return -1;
    }
    close(sk->fd);
    wn_handle_close((wn_handle)(uintptr_t)s);
    return 0;
}

static WN_API int32_t w2_connect(wn_abiword s, const void *name, int32_t namelen)
{
    wn_sock *sk = sock_of(s);
    if (!sk || !name)
        return -1;
    if (connect(sk->fd, name, (socklen_t)namelen) != 0) {
        set_wsa_from_errno();
        return -1;
    }
    return 0;
}

static WN_API int32_t w2_bind(wn_abiword s, const void *name, int32_t namelen)
{
    wn_sock *sk = sock_of(s);
    if (!sk || !name)
        return -1;
    if (bind(sk->fd, name, (socklen_t)namelen) != 0) {
        set_wsa_from_errno();
        return -1;
    }
    return 0;
}

static WN_API int32_t w2_listen(wn_abiword s, int32_t backlog)
{
    wn_sock *sk = sock_of(s);
    if (!sk)
        return -1;
    if (listen(sk->fd, backlog) != 0) {
        set_wsa_from_errno();
        return -1;
    }
    return 0;
}

static WN_API uint64_t w2_accept(wn_abiword s, void *addr, int32_t *addrlen)
{
    wn_sock *sk = sock_of(s);
    if (!sk)
        return (uint64_t)(uintptr_t)-1;
    socklen_t al = addrlen ? (socklen_t)*addrlen : 0;
    int fd = accept(sk->fd, addr, addrlen ? &al : NULL);
    if (fd < 0) {
        set_wsa_from_errno();
        return (uint64_t)(uintptr_t)-1;
    }
    if (addrlen)
        *addrlen = (int32_t)al;
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    return sock_new(fd);
}

static WN_API int32_t w2_send(wn_abiword s, const void *buf, int32_t len,
                              int32_t flags)
{
    wn_sock *sk = sock_of(s);
    if (!sk || !buf || len < 0)
        return -1;
    ssize_t r = send(sk->fd, buf, (size_t)len, flags);
    if (r < 0)
        set_wsa_from_errno();
    return (int32_t)r;
}

static WN_API int32_t w2_recv(wn_abiword s, void *buf, int32_t len, int32_t flags)
{
    wn_sock *sk = sock_of(s);
    if (!sk || !buf || len < 0)
        return -1;
    ssize_t r = recv(sk->fd, buf, (size_t)len, flags);
    if (r < 0)
        set_wsa_from_errno();
    return (int32_t)r;
}

static WN_API int32_t w2_shutdown(wn_abiword s, int32_t how)
{
    wn_sock *sk = sock_of(s);
    if (!sk)
        return -1;
    return shutdown(sk->fd, how);
}

static WN_API int32_t w2_ioctlsocket(wn_abiword s, int32_t cmd, uint32_t *argp)
{
    wn_sock *sk = sock_of(s);
    if (!sk || !argp)
        return -1;
    if ((uint32_t)cmd == 0x8004667Eu /* FIONBIO */) {
        int flags = fcntl(sk->fd, F_GETFL, 0);
        if (*argp)
            flags |= O_NONBLOCK;
        else
            flags &= ~O_NONBLOCK;
        fcntl(sk->fd, F_SETFL, flags);
        sk->nonblocking = (int)*argp;
        return 0;
    }
    g_wsa_err = WSAEINVAL;
    return -1;
}

/* --- select with fd_set translation --------------------------------------------- */

/* Winsock fd_set: {u_long fd_count; SOCKET fd_array[FD_SETSIZE=64]},
 * x64 size = 8 + 64*8 = 520. */
#define WN_FD_SET_SIZE 64

typedef struct {
    uint32_t fd_count;
    uint32_t pad;
    uint64_t fd_array[WN_FD_SET_SIZE];
} win_fd_set;

static int build_host_set(win_fd_set *w, fd_set *h)
{
    FD_ZERO(h);
    if (!w)
        return 0;
    if (w->fd_count > WN_FD_SET_SIZE) {
        g_wsa_err = WSAEINVAL;
        return -1;
    }
    for (uint32_t i = 0; i < w->fd_count; i++) {
        wn_sock *sk = sock_of(w->fd_array[i]);
        if (!sk) {
            g_wsa_err = WSAENOTSOCK;
            return -1;
        }
        FD_SET(sk->fd, h);
    }
    return 0;
}

static void write_back_set(win_fd_set *w, fd_set *h)
{
    if (!w)
        return;
    uint32_t n = 0;
    for (uint32_t i = 0; i < w->fd_count && n < (uint32_t)WN_FD_SET_SIZE; i++) {
        wn_sock *sk = sock_of(w->fd_array[i]);
        if (sk && FD_ISSET(sk->fd, h))
            w->fd_array[n++] = w->fd_array[i];
    }
    w->fd_count = n;
}

static WN_API int32_t w2_select(int32_t nfds, void *rs, void *ws_, void *es,
                                void *timeout)
{
    (void)nfds;   /* ignored on Windows; derived from the sets */
    fd_set hrs, hws, hes;
    if (build_host_set((win_fd_set *)rs, &hrs) != 0)
        return -1;
    if (build_host_set((win_fd_set *)ws_, &hws) != 0)
        return -1;
    if (build_host_set((win_fd_set *)es, &hes) != 0)
        return -1;
    int maxfd = 0;
    for (int fd = 0; fd < FD_SETSIZE; fd++)
        if (FD_ISSET(fd, &hrs) || FD_ISSET(fd, &hws) || FD_ISSET(fd, &hes))
            if (fd + 1 > maxfd)
                maxfd = fd + 1;
    struct timeval tv = { 0, 0 };
    struct timeval *tvp = NULL;
    if (timeout) {
        memcpy(&tv, timeout, sizeof tv);
        tvp = &tv;
    }
    int r = select(maxfd, rs ? &hrs : NULL, ws_ ? &hws : NULL,
                   es ? &hes : NULL, tvp);
    if (r < 0) {
        set_wsa_from_errno();
        return -1;
    }
    write_back_set((win_fd_set *)rs, &hrs);
    write_back_set((win_fd_set *)ws_, &hws);
    write_back_set((win_fd_set *)es, &hes);
    return r;
}

/* FD_ISSET on Windows compiles to this imported helper. */
static WN_API int32_t w2___WSAFDIsSet(wn_abiword s, void *setp)
{
    win_fd_set *set = setp;
    if (!set)
        return 0;
    for (uint32_t i = 0; i < set->fd_count; i++)
        if (set->fd_array[i] == s)
            return 1;
    return 0;
}

/* --- address helpers ---------------------------------------------------------------- */

static WN_API uint32_t w2_htons(uint16_t v) { return htons(v); }
static WN_API uint32_t w2_htonl(uint32_t v) { return htonl(v); }
static WN_API uint32_t w2_ntohs(uint16_t v) { return ntohs(v); }
static WN_API uint32_t w2_ntohl(uint32_t v) { return ntohl(v); }

static WN_API uint32_t w2_inet_addr(const char *cp)
{
    return inet_addr(cp);
}

static WN_API char *w2_inet_ntoa(uint32_t addr)
{
    struct in_addr a = { .s_addr = addr };
    /* Static like Windows (single buffer, documented). */
    static char buf[32];
    const char *r = inet_ntop(AF_INET, &a, buf, sizeof buf);
    return r ? buf : NULL;
}

/* hostent x64 layout: {char* h_name; char** h_aliases; short h_addrtype;
 * short h_length; char** h_addr_list;} — build in static storage. */
static WN_API void *w2_gethostbyname(const char *name)
{
    static struct hostent he;
    static char *aliases[1] = { NULL };
    static char *addr_list[2] = { NULL, NULL };
    static struct { uint32_t addr; } addr_storage;
    if (!name)
        return NULL;
    struct hostent *h = gethostbyname(name);
    if (!h || h->h_addrtype != AF_INET) {
        g_wsa_err = 10093;   /* WSANO_DATA-ish */
        return NULL;
    }
    he.h_name = h->h_name;
    he.h_aliases = aliases;
    he.h_addrtype = h->h_addrtype;
    he.h_length = h->h_length;
    memcpy(&addr_storage.addr, h->h_addr_list[0], 4);
    addr_list[0] = (char *)&addr_storage;
    he.h_addr_list = addr_list;
    return &he;
}

const wn_export_entry wn_ws2_32_exports[] = {
    { "__WSAFDIsSet", w2___WSAFDIsSet },
    { "WSACleanup", w2_WSACleanup },
    { "WSAGetLastError", w2_WSAGetLastError },
    { "WSAStartup", w2_WSAStartup },
    { "accept", w2_accept },
    { "bind", w2_bind },
    { "closesocket", w2_closesocket },
    { "connect", w2_connect },
    { "gethostbyname", w2_gethostbyname },
    { "htonl", w2_htonl },
    { "htons", w2_htons },
    { "inet_addr", w2_inet_addr },
    { "inet_ntoa", w2_inet_ntoa },
    { "ioctlsocket", w2_ioctlsocket },
    { "listen", w2_listen },
    { "ntohl", w2_ntohl },
    { "ntohs", w2_ntohs },
    { "recv", w2_recv },
    { "select", w2_select },
    { "send", w2_send },
    { "shutdown", w2_shutdown },
    { "socket", w2_socket },
    { NULL, NULL },
};
