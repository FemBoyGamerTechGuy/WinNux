/* wn_format.h — Windows-semantics printf engine, shared by msvcrt
 * (printf family) and user32 (wsprintf family).
 *
 * The va_list model is MS-shaped: 'ap' is a pointer to a char* cursor into
 * the caller's argument spill area (register save area + stack slots), NOT a
 * stdarg va_list. On x86_64 that is __builtin_ms_va_list; on i386 it is the
 * same plain char* — see src/dlls/msvcrt.c "MS-va_list note" for the trap.
 */
#ifndef WN_FORMAT_H
#define WN_FORMAT_H

#include <stddef.h>
#include <stdint.h>

typedef void (*wn_emit_fn)(void *ctx, const char *data, size_t n);

/* Bounded char-buffer emitter: writes at most left-1 bytes, always NUL
 * terminates, stops consuming once full. ctx = struct wn_emit_buf*. */
struct wn_emit_buf {
    char *p;
    size_t left;
};

void wn_emit_to_buf(void *ctx, const char *data, size_t n);

/* Core formatter. wide selects the %s/%c direction:
 *   wide=0  (A-side: printf/wsprintfA):  %s = ANSI, %S = UTF-16
 *   wide=1  (W-side: swprintf/wsprintfW): %s = UTF-16, %S = ANSI
 * %ls is always UTF-16 and %hs always narrow, independent of the mode.
 * Returns 0 on success, -1 on bad arguments. */
int wn_vformat(wn_emit_fn emit, void *ctx, const char *fmt, char **ap,
               int wide);

/* wsprintf-family convenience used by user32: formats with a bounded output
 * (dst always NUL-terminated, cap includes the NUL). Returns the number of
 * chars written excluding the NUL, or -1 on bad args. */
int64_t wn_wsprintf_buf(char *dst, size_t cap, const char *fmt, char *ap,
                        int wide);

#endif

/* --- MS-shaped varargs for variadic exports ----------------------------------
 * SysV <stdarg.h> va_list is an ARRAY type: passing it on decays to its
 * ADDRESS, so a helper receiving `va_list ap` + `(char*)ap` reads the
 * pointer itself as the first argument (found via putty/t14 debugging:
 * every sprintf %s produced garbage). GCC lowers va_start correctly only
 * when the walk stays inside one function.
 *
 * Correct model (matches Windows, where va_list is a plain char*):
 *   - every variadic export uses WN_VA_START and extracts
 *     `char *argp = (char *)ap` IN THE SAME FUNCTION;
 *   - v-family exports take `char *ap` BY VALUE (that IS what guests pass);
 *   - the formatter always receives char** and advances its own copy. */
#if defined(__x86_64__)
typedef __builtin_ms_va_list wn_ms_va;
#define WN_VA_START(ap, last) __builtin_ms_va_start(ap, last)
#define WN_VA_END(ap)         __builtin_ms_va_end(ap)
#else
/* i386: MSVC va_list IS a plain char* (args at ascending addresses), and
 * GCC's i386 __builtin_va_list is char* too - the one-slot-per-arg walk
 * applies unchanged. */
typedef __builtin_va_list wn_ms_va;
#define WN_VA_START(ap, last) __builtin_va_start(ap, last)
#define WN_VA_END(ap)         __builtin_va_end(ap)
#endif
