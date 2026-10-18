/* dbghelp.c — symbol/dump helpers (honest).
 *
 * Session bookkeeping succeeds (it is just state); every actual lookup or
 * dump honestly fails: WinNux has no PDB/COFF symbol engine yet. Loud logs
 * on the first call of each family so apps record why they degrade.
 */
#include "wn_dll.h"
#include "wn_log.h"
#include "wn_process.h"

#include <stdint.h>

static WN_API int32_t db_SymInitialize(wn_abiword h, const char *path,
                                       int32_t invade)
{
    (void)path; (void)invade;
    (void)h;
    wn_log(WN_LOG_WARN, "dbghelp: SymInitialize accepted, but symbol "
           "lookups are NOT implemented (all will fail honestly)");
    return 1;
}

static WN_API int32_t db_SymCleanup(wn_abiword h)
{
    (void)h;
    return 1;
}

static WN_API uint64_t db_SymLoadModule64(wn_abiword h, wn_abiword file,
                                          const char *name, const char *path,
                                          uint64_t base, uint32_t size)
{
    (void)h; (void)file; (void)name; (void)path; (void)base; (void)size;
    wn_log(WN_LOG_WARN, "dbghelp: SymLoadModule64('%s') -> 0 (no symbol "
           "engine)", path ? path : name ? name : "?");
    return 0;
}

static WN_API int32_t db_SymGetSymFromName(wn_abiword h, const char *name,
                                           void *sym)
{
    (void)h; (void)name; (void)sym;
    wn_last_error_set(WN_ERR_CALL_NOT_IMPLEMENTED);
    return 0;
}

static WN_API int32_t db_SymFromAddr(wn_abiword h, uint64_t addr, uint64_t *disp,
                                     void *sym)
{
    (void)h; (void)addr; (void)disp; (void)sym;
    wn_last_error_set(WN_ERR_CALL_NOT_IMPLEMENTED);
    return 0;
}

static WN_API int32_t db_StackWalk64(uint32_t machine, wn_abiword h,
                                     wn_abiword thread, void *ctx, void *frame,
                                     void *proc, void *fn, void *mod,
                                     void *data)
{
    (void)machine; (void)h; (void)thread; (void)ctx; (void)frame;
    (void)proc; (void)fn; (void)mod; (void)data;
    wn_last_error_set(WN_ERR_CALL_NOT_IMPLEMENTED);
    return 0;
}

static WN_API int32_t db_MiniDumpWriteDump(wn_abiword h, uint32_t pid,
                                           wn_abiword file, uint32_t type,
                                           void *exc, void *cb, void *param)
{
    (void)h; (void)pid; (void)file; (void)type; (void)exc; (void)cb; (void)param;
    wn_log(WN_LOG_WARN, "dbghelp: MiniDumpWriteDump not implemented -> FALSE");
    wn_last_error_set(WN_ERR_CALL_NOT_IMPLEMENTED);
    return 0;
}

const wn_export_entry wn_dbghelp_exports[] = {
    { "SymInitialize",     db_SymInitialize },
    { "SymCleanup",        db_SymCleanup },
    { "SymLoadModule64",   db_SymLoadModule64 },
    { "SymGetSymFromName", db_SymGetSymFromName },
    { "SymFromAddr",       db_SymFromAddr },
    { "StackWalk64",       db_StackWalk64 },
    { "MiniDumpWriteDump", db_MiniDumpWriteDump },
    { NULL, NULL },
};
