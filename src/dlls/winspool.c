/* winspool.c — print spooler (honest: no printers).
 *
 * Registered under both winspool.drv (the real import name) and winspool.dll.
 */
#include "wn_dll.h"
#include "wn_log.h"
#include "wn_process.h"

#include <stdint.h>

static WN_API int32_t sp_OpenPrinterA(const char *name, uint64_t *printer, void *def)
{
    (void)name; (void)printer; (void)def;
    wn_log(WN_LOG_WARN, "winspool: OpenPrinterA('%s') -> FALSE (no print "
           "subsystem yet)", name ? name : "(null)");
    wn_last_error_set(WN_ERR_CALL_NOT_IMPLEMENTED);
    return 0;
}

static WN_API int32_t sp_OpenPrinterW(const uint16_t *name, uint64_t *printer, void *def)
{
    (void)name; (void)printer; (void)def;
    wn_log(WN_LOG_WARN, "winspool: OpenPrinterW -> FALSE (no print subsystem yet)");
    wn_last_error_set(WN_ERR_CALL_NOT_IMPLEMENTED);
    return 0;
}

static WN_API int32_t sp_ClosePrinter(uint64_t printer)
{
    (void)printer;
    return 0;
}

static WN_API int32_t sp_EnumPrintersA(uint32_t flags, const char *name,
                                       uint32_t level, uint8_t *buf,
                                       uint32_t cap, uint32_t *need,
                                       uint32_t *returned)
{
    (void)flags; (void)name; (void)level; (void)buf; (void)cap;
    if (need)
        *need = 0;
    if (returned)
        *returned = 0;
    wn_log(WN_LOG_DEBUG, "winspool: EnumPrintersA -> 0 printers (none exist)");
    return 1;
}

static WN_API int32_t sp_EnumPrintersW(uint32_t flags, const uint16_t *name,
                                       uint32_t level, uint8_t *buf,
                                       uint32_t cap, uint32_t *need,
                                       uint32_t *returned)
{
    (void)flags; (void)name; (void)level; (void)buf; (void)cap;
    if (need)
        *need = 0;
    if (returned)
        *returned = 0;
    return 1;
}

static WN_API int32_t sp_GetDefaultPrinterA(char *name, uint32_t *cap)
{
    (void)name; (void)cap;
    wn_last_error_set(WN_ERR_CALL_NOT_IMPLEMENTED);
    return 0;
}

static WN_API int32_t sp_GetDefaultPrinterW(uint16_t *name, uint32_t *cap)
{
    (void)name; (void)cap;
    wn_last_error_set(WN_ERR_CALL_NOT_IMPLEMENTED);
    return 0;
}

static WN_API int32_t sp_DocumentPropertiesA(uint64_t hwnd, uint64_t printer,
                                             const char *dev, void *out,
                                             void *in, uint32_t mode)
{
    (void)hwnd; (void)printer; (void)dev; (void)out; (void)in; (void)mode;
    return -1;   /* SP_ERROR */
}

static WN_API int32_t sp_WritePrinter(uint64_t printer, void *buf,
                                      uint32_t len, uint32_t *written)
{
    (void)printer; (void)buf; (void)len;
    if (written)
        *written = 0;
    return 0;
}

const wn_export_entry wn_winspool_exports[] = {
    { "OpenPrinterA",         sp_OpenPrinterA },
    { "OpenPrinterW",         sp_OpenPrinterW },
    { "ClosePrinter",         sp_ClosePrinter },
    { "EnumPrintersA",        sp_EnumPrintersA },
    { "EnumPrintersW",        sp_EnumPrintersW },
    { "GetDefaultPrinterA",   sp_GetDefaultPrinterA },
    { "GetDefaultPrinterW",   sp_GetDefaultPrinterW },
    { "DocumentPropertiesA",  sp_DocumentPropertiesA },
    { "WritePrinter",         sp_WritePrinter },
    { NULL, NULL },
};
