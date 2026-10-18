/* netshell.c — the "networking shell" DLL family that real apps import but
 * WinNux does not service yet: wininet, winhttp, mswsock, iphlpapi.
 *
 * Every entry point returns the documented failure for "service offline"
 * with a loud WARN on first use. Nothing fakes a handle or an IP address.
 * (Real implementations will ride ws2_32 sockets — see TODO.md.)
 *
 * The one exception with real behavior: mswsock!WSAAsyncSelect honestly
 * reports WSAEOPNOTSUPP, and iphlpapi enumerators report ERROR_NO_DATA
 * ("no adapters"), which is exactly what a box with no visible network
 * would answer.
 */
#include "wn_dll.h"
#include "wn_log.h"
#include "wn_process.h"

#include <stdint.h>

/* --- wininet ------------------------------------------------------------------ */

static WN_API void *ni_InternetOpenA(const char *agent, uint32_t type,
                                     const char *proxy, const char *bypass,
                                     uint32_t flags)
{
    (void)agent; (void)type; (void)proxy; (void)bypass; (void)flags;
    wn_log(WN_LOG_WARN, "wininet: InternetOpenA -> NULL (no wininet stack "
           "yet; app should treat as offline)");
    wn_last_error_set(WN_ERR_CALL_NOT_IMPLEMENTED);
    return NULL;
}

static WN_API void *ni_InternetOpenW(const uint16_t *agent, uint32_t type,
                                     const uint16_t *proxy,
                                     const uint16_t *bypass, uint32_t flags)
{
    (void)agent; (void)type; (void)proxy; (void)bypass; (void)flags;
    wn_log(WN_LOG_WARN, "wininet: InternetOpenW -> NULL (offline)");
    wn_last_error_set(WN_ERR_CALL_NOT_IMPLEMENTED);
    return NULL;
}

static WN_API int32_t ni_InternetCloseHandle(wn_abiword h)
{
    (void)h;
    return 0;
}

static WN_API void *ni_InternetConnectA(wn_abiword h, const char *server,
                                        uint32_t port, const char *user,
                                        const char *pass, uint32_t service,
                                        uint32_t flags, uint64_t ctx)
{
    (void)h; (void)server; (void)port; (void)user; (void)pass; (void)service;
    (void)flags; (void)ctx;
    wn_last_error_set(WN_ERR_CALL_NOT_IMPLEMENTED);
    return NULL;
}

static WN_API void *ni_HttpOpenRequestA(wn_abiword h, const char *verb,
                                        const char *obj, const char *ver,
                                        const char *ref, const char **types,
                                        uint32_t flags, uint64_t ctx)
{
    (void)h; (void)verb; (void)obj; (void)ver; (void)ref; (void)types;
    (void)flags; (void)ctx;
    wn_last_error_set(WN_ERR_CALL_NOT_IMPLEMENTED);
    return NULL;
}

static WN_API int32_t ni_InternetReadFile(wn_abiword h, void *buf, uint32_t want,
                                          uint32_t *got)
{
    (void)h; (void)buf; (void)want;
    if (got)
        *got = 0;
    wn_last_error_set(WN_ERR_CALL_NOT_IMPLEMENTED);
    return 0;
}

static WN_API int32_t ni_InternetGetConnectedState(uint32_t *flags, uint32_t rsv)
{
    (void)flags; (void)rsv;
    wn_log(WN_LOG_WARN, "wininet: InternetGetConnectedState -> FALSE "
           "(offline: no wininet stack)");
    return 0;
}

const wn_export_entry wn_wininet_exports[] = {
    { "InternetOpenA",             ni_InternetOpenA },
    { "InternetOpenW",             ni_InternetOpenW },
    { "InternetCloseHandle",       ni_InternetCloseHandle },
    { "InternetConnectA",          ni_InternetConnectA },
    { "HttpOpenRequestA",          ni_HttpOpenRequestA },
    { "InternetReadFile",          ni_InternetReadFile },
    { "InternetGetConnectedState", ni_InternetGetConnectedState },
    { NULL, NULL },
};

/* --- winhttp ------------------------------------------------------------------ */

static WN_API void *nh_WinHttpOpen(void)
{
    wn_log(WN_LOG_WARN, "winhttp: WinHttpOpen -> NULL (no winhttp stack yet)");
    wn_last_error_set(WN_ERR_CALL_NOT_IMPLEMENTED);
    return NULL;
}

static WN_API int32_t nh_WinHttpCloseHandle(wn_abiword h)
{
    (void)h;
    return 0;
}

static WN_API void *nh_WinHttpConnect(wn_abiword h, const uint16_t *server,
                                      uint32_t port, uint32_t rsv)
{
    (void)h; (void)server; (void)port; (void)rsv;
    wn_last_error_set(WN_ERR_CALL_NOT_IMPLEMENTED);
    return NULL;
}

const wn_export_entry wn_winhttp_exports[] = {
    { "WinHttpOpen",         nh_WinHttpOpen },
    { "WinHttpCloseHandle",  nh_WinHttpCloseHandle },
    { "WinHttpConnect",      nh_WinHttpConnect },
    { NULL, NULL },
};

/* --- mswsock ------------------------------------------------------------------ */

static WN_API int32_t ms_WSAAsyncSelect(wn_abiword sock, wn_abiword hwnd,
                                        uint32_t msg, uint32_t events)
{
    (void)sock; (void)hwnd; (void)msg; (void)events;
    wn_log(WN_LOG_WARN, "mswsock: WSAAsyncSelect not implemented -> "
           "SOCKET_ERROR (WSAEOPNOTSUPP); use nonblocking + select");
    wn_last_error_set(10045 /* WSAEOPNOTSUPP */);
    return -1;
}

const wn_export_entry wn_mswsock_exports[] = {
    { "WSAAsyncSelect", ms_WSAAsyncSelect },
    { NULL, NULL },
};

/* --- iphlpapi ----------------------------------------------------------------- */

static WN_API uint32_t ip_GetAdaptersInfo(void *info, uint32_t *size)
{
    (void)info;
    if (size)
        *size = 0;
    wn_log(WN_LOG_WARN, "iphlpapi: GetAdaptersInfo -> ERROR_NO_DATA "
           "(no adapters presented yet)");
    return 232;   /* ERROR_NO_DATA */
}

static WN_API uint32_t ip_GetAdaptersAddresses(uint32_t family,
                                               uint32_t flags, void *rsv,
                                               void *info, uint32_t *size)
{
    (void)family; (void)flags; (void)rsv; (void)info; (void)size;
    wn_log(WN_LOG_WARN, "iphlpapi: GetAdaptersAddresses -> ERROR_NO_DATA");
    return 232;
}

static WN_API uint32_t ip_GetIfTable(void *table, uint32_t *size, int32_t order)
{
    (void)table; (void)order;
    if (size)
        *size = 0;
    return 232;
}

static WN_API uint32_t ip_GetNetworkParams(void *params, uint32_t *size)
{
    (void)params;
    if (size)
        *size = 0;
    return 232;
}

static WN_API uint32_t ip_GetBestInterface(uint32_t dst, uint32_t *idx)
{
    (void)dst;
    if (idx)
        *idx = 0;
    return 232;
}

const wn_export_entry wn_iphlpapi_exports[] = {
    { "GetAdaptersInfo",        ip_GetAdaptersInfo },
    { "GetAdaptersAddresses",   ip_GetAdaptersAddresses },
    { "GetIfTable",             ip_GetIfTable },
    { "GetNetworkParams",       ip_GetNetworkParams },
    { "GetBestInterface",       ip_GetBestInterface },
    { NULL, NULL },
};
