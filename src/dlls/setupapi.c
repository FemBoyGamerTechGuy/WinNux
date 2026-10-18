/* setupapi.c — device installation APIs (honest failures).
 *
 * WinNux presents no virtual device tree: every enumeration returns the
 * documented "no more data / empty set" result rather than fake devices.
 * INVALID_HANDLE_VALUE marks failed SetupDiGetClassDevs.
 */
#include "wn_dll.h"
#include "wn_log.h"
#include "wn_process.h"
#include "wn_types.h"

#include <stdint.h>

static WN_API uint64_t su_SetupDiGetClassDevsA(const void *cls, const char *enumid,
                                               wn_abiword hwnd, uint32_t flags)
{
    (void)cls; (void)enumid; (void)hwnd; (void)flags;
    wn_log(WN_LOG_WARN, "setupapi: SetupDiGetClassDevsA -> INVALID_HANDLE_VALUE "
           "(no device tree yet)");
    wn_last_error_set(WN_ERR_CALL_NOT_IMPLEMENTED);
    return (uint64_t)(uintptr_t)WN_INVALID_HANDLE_VALUE;
}

static WN_API uint64_t su_SetupDiGetClassDevsW(const void *cls,
                                               const uint16_t *enumid,
                                               wn_abiword hwnd, uint32_t flags)
{
    (void)cls; (void)enumid; (void)hwnd; (void)flags;
    wn_log(WN_LOG_WARN, "setupapi: SetupDiGetClassDevsW -> INVALID_HANDLE_VALUE "
           "(no device tree yet)");
    wn_last_error_set(WN_ERR_CALL_NOT_IMPLEMENTED);
    return (uint64_t)(uintptr_t)WN_INVALID_HANDLE_VALUE;
}

static WN_API int32_t su_SetupDiEnumDeviceInfo(wn_abiword set, uint32_t idx,
                                               void *info)
{
    (void)set; (void)idx; (void)info;
    wn_last_error_set(WN_ERR_NO_MORE_ITEMS);
    return 0;
}

static WN_API int32_t su_SetupDiGetDeviceInstanceIdA(wn_abiword set, void *info,
                                                     char *buf, uint32_t cap,
                                                     uint32_t *need)
{
    (void)set; (void)info; (void)buf; (void)cap;
    if (need)
        *need = 0;
    wn_last_error_set(WN_ERR_CALL_NOT_IMPLEMENTED);
    return 0;
}

static WN_API int32_t su_SetupDiDestroyDeviceInfoList(wn_abiword set)
{
    (void)set;
    return 0;   /* FALSE: nothing was ever created */
}

static WN_API int32_t su_SetupDiGetDeviceRegistryPropertyA(wn_abiword set,
                                                           void *info,
                                                           uint32_t prop,
                                                           uint32_t *type,
                                                           uint8_t *buf,
                                                           uint32_t cap,
                                                           uint32_t *need)
{
    (void)set; (void)info; (void)buf; (void)cap; (void)prop; (void)type; (void)buf; (void)cap;
    if (need)
        *need = 0;
    wn_last_error_set(WN_ERR_CALL_NOT_IMPLEMENTED);
    return 0;
}

static WN_API int32_t su_SetupDiCallClassInstaller(uint32_t op, wn_abiword set,
                                                   void *info)
{
    (void)op; (void)set; (void)info;
    wn_last_error_set(WN_ERR_CALL_NOT_IMPLEMENTED);
    return 0;
}

static WN_API int32_t su_SetupIterateCabinetA(const char *cab, uint32_t reserved,
                                              void *handler, void *ctx)
{
    (void)cab; (void)reserved; (void)handler; (void)ctx;
    wn_last_error_set(WN_ERR_CALL_NOT_IMPLEMENTED);
    return 0;
}

static WN_API int32_t su_SetupDecompressOrCopyFileA(const char *src,
                                                    const char *dst,
                                                    const uint32_t *type)
{
    (void)src; (void)dst; (void)type;
    wn_last_error_set(WN_ERR_CALL_NOT_IMPLEMENTED);
    return 0;
}

const wn_export_entry wn_setupapi_exports[] = {
    { "SetupDiGetClassDevsA",              su_SetupDiGetClassDevsA },
    { "SetupDiGetClassDevsW",              su_SetupDiGetClassDevsW },
    { "SetupDiEnumDeviceInfo",             su_SetupDiEnumDeviceInfo },
    { "SetupDiGetDeviceInstanceIdA",       su_SetupDiGetDeviceInstanceIdA },
    { "SetupDiDestroyDeviceInfoList",      su_SetupDiDestroyDeviceInfoList },
    { "SetupDiGetDeviceRegistryPropertyA", su_SetupDiGetDeviceRegistryPropertyA },
    { "SetupDiCallClassInstaller",         su_SetupDiCallClassInstaller },
    { "SetupIterateCabinetA",              su_SetupIterateCabinetA },
    { "SetupDecompressOrCopyFileA",        su_SetupDecompressOrCopyFileA },
    { NULL, NULL },
};
