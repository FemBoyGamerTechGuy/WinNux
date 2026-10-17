/* extras.c — presence shims: secur32/sspicli, msvcp140 family.
 *
 * secur32: no security packages (SSP) hosted; AcquireCredentialsHandle
 * honestly fails with SEC_E_NO_CREDENTIALS, package enumeration reports
 * zero packages. FreeContextBuffer is real (plain free — that contract we
 * can honor).
 * msvcp140/concrt140/vcomp140: registered so imports RESOLVE to loud stubs
 * instead of "DLL not found"; the C++ runtime surface is unimplemented.
 */
#include "wn_dll.h"
#include "wn_log.h"
#include "wn_process.h"
#include "wn_util.h"

#include <stdint.h>
#include <stdlib.h>

/* --- secur32 --------------------------------------------------------------------- */

#define SEC_E_OK              ((int32_t)0)
#define SEC_E_NO_CREDENTIALS  ((int32_t)0x8009030E)
#define SEC_E_SECPKG_NOT_FOUND ((int32_t)0x80090305)

static WN_API int32_t sec_AcquireCredentialsHandleA(const char *principal,
                                                    const char *pkg,
                                                    uint32_t fcreduse,
                                                    void *lid, void *pauth,
                                                    void *getkey, void *getarg,
                                                    uint64_t *handle,
                                                    void *expiry)
{
    (void)principal; (void)pkg; (void)fcreduse; (void)lid; (void)pauth;
    (void)getkey; (void)getarg; (void)expiry;
    if (handle)
        *handle = 0;
    wn_log(WN_LOG_WARN, "secur32: AcquireCredentialsHandleA('%s') -> "
           "SEC_E_NO_CREDENTIALS (no security packages hosted)", pkg ? pkg : "?");
    return SEC_E_NO_CREDENTIALS;
}

static WN_API int32_t sec_AcquireCredentialsHandleW(const uint16_t *principal,
                                                    const uint16_t *pkg,
                                                    uint32_t fcreduse,
                                                    void *lid, void *pauth,
                                                    void *getkey, void *getarg,
                                                    uint64_t *handle,
                                                    void *expiry)
{
    (void)principal; (void)pkg; (void)fcreduse; (void)lid; (void)pauth;
    (void)getkey; (void)getarg; (void)expiry;
    if (handle)
        *handle = 0;
    wn_log(WN_LOG_WARN, "secur32: AcquireCredentialsHandleW -> "
           "SEC_E_NO_CREDENTIALS (no security packages hosted)");
    return SEC_E_NO_CREDENTIALS;
}

static WN_API int32_t sec_EnumerateSecurityPackagesA(uint32_t *count,
                                                     void **packages)
{
    if (count)
        *count = 0;
    if (packages)
        *packages = NULL;
    return SEC_E_OK;   /* zero packages: the honest count */
}

static WN_API int32_t sec_EnumerateSecurityPackagesW(uint32_t *count,
                                                     void **packages)
{
    if (count)
        *count = 0;
    if (packages)
        *packages = NULL;
    return SEC_E_OK;
}

static WN_API int32_t sec_QuerySecurityPackageInfoA(const char *pkg, void *info)
{
    (void)pkg; (void)info;
    return SEC_E_SECPKG_NOT_FOUND;
}

static WN_API void sec_FreeContextBuffer(void *buf)
{
    free(buf);
}

static WN_API void *sec_InitSecurityInterfaceA(void)
{
    wn_log(WN_LOG_WARN, "secur32: InitSecurityInterfaceA -> NULL (no SSPs)");
    return NULL;
}

const wn_export_entry wn_secur32_exports[] = {
    { "AcquireCredentialsHandleA",      sec_AcquireCredentialsHandleA },
    { "AcquireCredentialsHandleW",      sec_AcquireCredentialsHandleW },
    { "EnumerateSecurityPackagesA",     sec_EnumerateSecurityPackagesA },
    { "EnumerateSecurityPackagesW",     sec_EnumerateSecurityPackagesW },
    { "QuerySecurityPackageInfoA",      sec_QuerySecurityPackageInfoA },
    { "FreeContextBuffer",              sec_FreeContextBuffer },
    { "InitSecurityInterfaceA",         sec_InitSecurityInterfaceA },
    { NULL, NULL },
};

/* --- msvcp140 family: presence only (all functions resolve to loud stubs) ------- */

const wn_export_entry wn_msvcp140_exports[] = {
    { NULL, NULL },
};
