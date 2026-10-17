/* wn_stub.h — executable trampolines for unimplemented imports.
 *
 * Missing imports must never crash the loader silently: they get a stub that
 * logs dll!api + call site on first use (and throttled afterwards) and
 * returns 0/NULL with last error 120.
 */
#ifndef WN_STUB_H
#define WN_STUB_H

#include <stdint.h>

/* Returns an executable stub address for dll!name. Stable per (dll,name):
 * the same missing import always gets the same stub. Never returns NULL. */
void *wn_stub_for(const char *dll, const char *name);

/* Total number of distinct stubs created (for stats). */
unsigned wn_stub_count(void);

#endif /* WN_STUB_H */
