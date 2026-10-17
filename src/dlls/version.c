/* version.c — file version queries.
 *
 * We do not parse version resources yet, so the honest answer is "this file
 * has no version information": size queries return 0, info fetches FALSE.
 * (Return-value semantics on Windows: 0 size == no version resource.)
 */
#include "wn_dll.h"
#include "wn_log.h"
#include "wn_process.h"

#include <stdint.h>

static WN_API uint32_t ve_GetFileVersionInfoSizeA(const char *file,
                                                  uint32_t *handle)
{
    (void)file;
    if (handle)
        *handle = 0;
    wn_log(WN_LOG_DEBUG, "version: GetFileVersionInfoSizeA('%s') -> 0 "
           "(version resources not parsed yet)", file ? file : "(null)");
    return 0;
}

static WN_API uint32_t ve_GetFileVersionInfoSizeW(const uint16_t *file,
                                                  uint32_t *handle)
{
    (void)file;
    if (handle)
        *handle = 0;
    wn_log(WN_LOG_DEBUG, "version: GetFileVersionInfoSizeW -> 0 "
           "(version resources not parsed yet)");
    return 0;
}

static WN_API int32_t ve_GetFileVersionInfoA(const char *file, uint32_t handle,
                                             uint32_t len, void *data)
{
    (void)file; (void)handle; (void)len; (void)data;
    wn_last_error_set(WN_ERR_CALL_NOT_IMPLEMENTED);
    return 0;
}

static WN_API int32_t ve_GetFileVersionInfoW(const uint16_t *file, uint32_t handle,
                                             uint32_t len, void *data)
{
    (void)file; (void)handle; (void)len; (void)data;
    wn_last_error_set(WN_ERR_CALL_NOT_IMPLEMENTED);
    return 0;
}

static WN_API int32_t ve_VerQueryValueA(const void *block, const char *sub,
                                        void **buf, uint32_t *len)
{
    (void)block; (void)sub; (void)buf; (void)len;
    wn_last_error_set(WN_ERR_CALL_NOT_IMPLEMENTED);
    return 0;
}

static WN_API int32_t ve_VerQueryValueW(const void *block, const uint16_t *sub,
                                        void **buf, uint32_t *len)
{
    (void)block; (void)sub; (void)buf; (void)len;
    wn_last_error_set(WN_ERR_CALL_NOT_IMPLEMENTED);
    return 0;
}

const wn_export_entry wn_version_exports[] = {
    { "GetFileVersionInfoSizeA", ve_GetFileVersionInfoSizeA },
    { "GetFileVersionInfoSizeW", ve_GetFileVersionInfoSizeW },
    { "GetFileVersionInfoA",     ve_GetFileVersionInfoA },
    { "GetFileVersionInfoW",     ve_GetFileVersionInfoW },
    { "VerQueryValueA",          ve_VerQueryValueA },
    { "VerQueryValueW",          ve_VerQueryValueW },
    { NULL, NULL },
};
