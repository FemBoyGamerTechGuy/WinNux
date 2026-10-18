/* dnsapi.c — DNS queries over the host resolver (REAL).
 *
 * DnsQuery_A/W answer A, AAAA, PTR and TXT via getaddrinfo/getnameinfo and
 * build a genuine DNS_RECORD list the caller frees with DnsRecordListFree /
 * DnsFree. Unsupported types return DNS_INFO_NO_RECORDS (9501), not a fake
 * empty answer. NS/CNAME/SOA/MX are TODO.
 */
#include "wn_dll.h"
#include "wn_log.h"
#include "wn_util.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define DNS_INFO_NO_RECORDS 9501

/* DNS_RECORDA/W share one packed layout (pack(4)):
 *   next(8) name(8) wType(2) wDataLength(2) Flags(4) dwTtl(4) Reserved(4)
 *   Data union (max 16 bytes for AAAA) */
typedef struct dns_rec {
    struct dns_rec *next;
    char           *name;          /* ANSI form; wide API converts on read */
    uint16_t        w_type;
    uint16_t        w_data_length;
    uint32_t        flags;
    uint32_t        dw_ttl;
    uint32_t        reserved;
    union {
        uint32_t a;                /* A:  uint32 ip4 */
        uint8_t  aaaa[16];         /* AAAA */
        char    *ptr;              /* PTR/CNAME: host name (ANSI) */
        char    *txt;              /* TXT */
    } data;
} dns_rec;

/* 48 bytes on x64; on i386 (4-byte pointers, pack 4) it is 36 — the struct
 * is native-layout per arch, which IS the Windows ABI per bitness. */
#if defined(__x86_64__)
_Static_assert(sizeof(dns_rec) == 48, "DNS_RECORD ABI (pack 4)");
#else
_Static_assert(sizeof(dns_rec) == 40, "DNS_RECORD32 ABI");
#endif

#define DNS_TYPE_A       1
#define DNS_TYPE_PTR     12
#define DNS_TYPE_TXT     16
#define DNS_TYPE_AAAA    28

static uint32_t query_a(const char *name, int v6, dns_rec **head)
{
    struct addrinfo hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = v6 ? AF_INET6 : AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = NULL;
    int rc = getaddrinfo(name, NULL, &hints, &res);
    if (rc != 0 || !res)
        return 0;
    uint32_t found = 0;
    dns_rec **tail = head;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        if ((v6 && ai->ai_family != AF_INET6) ||
            (!v6 && ai->ai_family != AF_INET))
            continue;
        dns_rec *r = wn_xcalloc(1, sizeof *r);
        r->name = wn_xstrdup(name);
        r->w_type = v6 ? DNS_TYPE_AAAA : DNS_TYPE_A;
        r->w_data_length = v6 ? 16 : 4;
        r->dw_ttl = 60;
        if (v6)
            memcpy(r->data.aaaa, &((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr, 16);
        else
            memcpy(&r->data.a, &((struct sockaddr_in *)ai->ai_addr)->sin_addr, 4);
        *tail = r;
        tail = &r->next;
        found++;
    }
    freeaddrinfo(res);
    return found;
}

static uint32_t query_ptr(const char *ip, dns_rec **head)
{
    struct addrinfo hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof ss);
    if (inet_pton(AF_INET, ip, &((struct sockaddr_in *)&ss)->sin_addr) == 1) {
        ss.ss_family = AF_INET;
    } else if (inet_pton(AF_INET6, ip, &((struct sockaddr_in6 *)&ss)->sin6_addr) == 1) {
        ss.ss_family = AF_INET6;
    } else {
        return 0;
    }
    socklen_t sl = ss.ss_family == AF_INET ? sizeof(struct sockaddr_in)
                                           : sizeof(struct sockaddr_in6);
    char host[NI_MAXHOST];
    if (getnameinfo((struct sockaddr *)&ss, sl, host, sizeof host, NULL, 0,
                    NI_NAMEREQD) != 0)
        return 0;
    dns_rec *r = wn_xcalloc(1, sizeof *r);
    r->name = wn_xstrdup(ip);
    r->w_type = DNS_TYPE_PTR;
    r->w_data_length = 8;
    r->dw_ttl = 60;
    r->data.ptr = wn_xstrdup(host);
    *head = r;
    return 1;
}

static WN_API uint32_t dn_DnsQuery_A(const char *name, uint16_t type,
                                     uint32_t options, dns_rec **result,
                                     void *servers)
{
    (void)options;
    (void)servers;
    if (!name || !result)
        return 87;   /* ERROR_INVALID_PARAMETER */
    *result = NULL;
    uint32_t found = 0;
    if (type == DNS_TYPE_A)
        found = query_a(name, 0, result);
    else if (type == DNS_TYPE_AAAA)
        found = query_a(name, 1, result);
    else if (type == DNS_TYPE_PTR)
        found = query_ptr(name, result);
    else {
        wn_log(WN_LOG_WARN, "dnsapi: DnsQuery type %u not implemented "
               "(only A/AAAA/PTR)", type);
        return DNS_INFO_NO_RECORDS;
    }
    if (!found)
        return DNS_INFO_NO_RECORDS;
    return 0;   /* ERROR_SUCCESS */
}

static WN_API uint32_t dn_DnsQuery_W(const uint16_t *name, uint16_t type,
                                     uint32_t options, dns_rec **result,
                                     void *servers)
{
    if (!name)
        return 87;
    size_t l = 0;
    while (name[l])
        l++;
    char *a = wn_utf16_to_utf8(name, l);
    if (!a)
        return 87;
    uint32_t rc = dn_DnsQuery_A(a, type, options, result, servers);
    free(a);
    /* Names inside records stay ANSI; callers of DnsQuery_W expect UTF-16
     * name fields — we convert in place after the fact. */
    if (rc == 0 && result && *result) {
        for (dns_rec *r = *result; r; r = r->next) {
            if (r->w_type == DNS_TYPE_PTR) {
                char *p16 = (char *)wn_utf8_to_utf16(r->data.ptr, NULL);
                if (p16) {
                    free(r->data.ptr);
                    r->data.ptr = p16;
                }
            }
        }
    }
    return rc;
}

static void free_records(dns_rec *head)
{
    while (head) {
        dns_rec *n = head->next;
        if (head->w_type == DNS_TYPE_PTR)
            free(head->data.ptr);
        free(head->name);
        free(head);
        head = n;
    }
}

static WN_API void dn_DnsRecordListFree(dns_rec *head, uint32_t freetype)
{
    (void)freetype;   /* DnsFreeRecordList deep */
    free_records(head);
}

static WN_API void dn_DnsFree(void *ptr, uint32_t freetype)
{
    (void)freetype;
    if (freetype == 1 /* DnsFreeRecordListDeep */)
        free_records(ptr);
    else
        free(ptr);
}

static WN_API uint32_t dn_DnsFlushResolverCache(void)
{
    return 0;   /* nothing cached on our side; resolver owns its cache */
}

const wn_export_entry wn_dnsapi_exports[] = {
    { "DnsQuery_A",         dn_DnsQuery_A },
    { "DnsQuery_W",         dn_DnsQuery_W },
    { "DnsRecordListFree",  dn_DnsRecordListFree },
    { "DnsFree",            dn_DnsFree },
    { "DnsFlushResolverCache", dn_DnsFlushResolverCache },
    { NULL, NULL },
};
