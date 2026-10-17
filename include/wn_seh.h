/* seh.h — structured exception handling: signal capture, VEH dispatch,
 * crash reporting. Table-based x64 unwinding (RTL_UNWIND via .pdata) is
 * NOT yet implemented — recorded honestly in STATUS.md.
 */
#ifndef WN_SEH_H
#define WN_SEH_H

#include "wn_types.h"

/* Install crash/exception signal handlers for this process. */
void wn_seh_init(void);

/* Raise a Windows-style exception (RaiseException). Codes 0xC0000005 etc.
 * Dispatches to VEH handlers; if one continues execution the call returns,
 * otherwise the process exits with the exception code. */
void wn_seh_raise(uint32_t code, uint32_t flags, uint32_t nparams,
                  const uint64_t *params);

/* Vectored handlers (RtlAddVectoredExceptionHandler). Returns a
 * non-NULL registration handle or 0 on failure. */
void *wn_seh_veh_add(void *handler, int first);
void  wn_seh_veh_remove(void *registration);

/* Unhandled exception filter (SetUnhandledExceptionFilter). */
void *wn_seh_set_unhandled_filter(void *filter);

#endif /* WN_SEH_H */
