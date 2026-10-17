/* wship6.c — builtin wship6.dll: the IPv6 WinSock helper (XP-era
 * getaddrinfo entry points that PuTTY delay-loads).
 *
 * The host glibc addrinfo is field-layout-compatible with the Windows one
 * on x64 (flags/family/socktype/protocol/addrlen/canonname/addr/next), and
 * sockaddr_in/in6 layouts match too — EXCEPT the family CONSTANTS:
 * AF_INET6 is 10 on Linux and 23 on Windows. The list is deep-copied and
 * translated so guests see true Windows values.
 */
#include "wn_dll.h"
#include "wn_log.h"
#include "wn_util.h"

#include <netdb.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Windows AF_ values (winsock2.h). */
#define WIN_AF_INET   2
#define WIN_AF_INET6  23

/* Windows addrinfo x64: 48 bytes — compatible offsets with glibc. */
typedef struct win_addrinfo {
    int32_t ai_flags;
    int32_t ai_family;
    int32_t ai_socktype;
    int32_t ai_protocol;
    uint64_t ai_addrlen;            /* size_t */
    char *ai_canonname;
    uint8_t *ai_addr;
    struct win_addrinfo *ai_next;
} win_addrinfo;

static int host_to_win_family(int af)
{
    if (af == AF_INET)
        return WIN_AF_INET;
    if (af == AF_INET6)
        return WIN_AF_INET6;
    return af;
}

static int win_to_host_family(int af)
{
    if (af == WIN_AF_INET)
        return AF_INET;
    if (af == WIN_AF_INET6)
        return AF_INET6;
    return af;
}

static WN_API int32_t ship_getaddrinfo(const char *node, const char *service,
                                       const void *hints, void *res_out)
{
    if (!res_out)
        return -1;                   /* EAI_FAIL-ish; WSA not initialized */
    struct addrinfo *out = NULL;
    struct addrinfo hhints;
    const struct addrinfo *use_hints = NULL;
    if (hints) {
        const win_addrinfo *wh = hints;
        memset(&hhints, 0, sizeof hhints);
        hhints.ai_flags = wh->ai_flags;
        hhints.ai_family = win_to_host_family(wh->ai_family);
        hhints.ai_socktype = wh->ai_socktype;
        hhints.ai_protocol = wh->ai_protocol;
        use_hints = &hhints;
    }
    int rc = getaddrinfo(node, service, use_hints, &out);
    if (rc != 0) {
        wn_log(WN_LOG_DEBUG, "wship6: getaddrinfo('%s') -> %d (%s)", node ? node : "",
               rc, gai_strerror(rc));
        /* map a few EAI codes to Windows WSA error space (WSAHOST_NOT_FOUND
         * 11001, WSATYPE_NOT_FOUND 10109, EAI_NONAME -> 11001) */
        return -1;
    }
    /* deep-copy with family translation */
    win_addrinfo **tail = (win_addrinfo **)res_out;
    *tail = NULL;
    for (struct addrinfo *a = out; a; a = a->ai_next) {
        win_addrinfo *w = wn_xcalloc(1, sizeof *w);
        w->ai_flags = a->ai_flags;
        w->ai_family = host_to_win_family(a->ai_family);
        w->ai_socktype = a->ai_socktype;
        w->ai_protocol = a->ai_protocol;
        w->ai_addrlen = a->ai_addrlen;
        if (a->ai_canonname)
            w->ai_canonname = wn_xstrdup(a->ai_canonname);
        if (a->ai_addr && a->ai_addrlen <= 128) {
            w->ai_addr = wn_xmalloc(a->ai_addrlen);
            memcpy(w->ai_addr, a->ai_addr, a->ai_addrlen);
            *(uint16_t *)w->ai_addr = (uint16_t)w->ai_family;
        }
        *tail = w;
        tail = &w->ai_next;
    }
    freeaddrinfo(out);
    return 0;
}

static WN_API void ship_freeaddrinfo(void *res)
{
    win_addrinfo *a = res;
    while (a) {
        win_addrinfo *n = a->ai_next;
        free(a->ai_canonname);
        free(a->ai_addr);
        free(a);
        a = n;
    }
}

/* Windows getnameinfo: (sockaddr, len, host, hostlen, serv, servlen, flags) */
static WN_API int32_t ship_getnameinfo(const void *sa, uint32_t salen,
                                       char *host, uint32_t hostlen,
                                       char *serv, uint32_t servlen,
                                       uint32_t flags)
{
    if (!sa)
        return -1;
    /* copy + translate the family back to host values */
    uint8_t buf[128];
    uint32_t n = salen < sizeof buf ? salen : (uint32_t)sizeof buf;
    memcpy(buf, sa, n);
    *(uint16_t *)buf = (uint16_t)win_to_host_family(*(uint16_t *)sa);
    return getnameinfo((const struct sockaddr *)buf, (socklen_t)n,
                       host, (socklen_t)hostlen, serv, (socklen_t)servlen,
                       (int)flags);
}

const wn_export_entry wn_wship6_exports[] = {
    { "getaddrinfo", ship_getaddrinfo },
    { "freeaddrinfo", ship_freeaddrinfo },
    { "getnameinfo", ship_getnameinfo },
    { NULL, NULL },
};
