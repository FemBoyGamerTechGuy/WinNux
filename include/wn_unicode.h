/* wn_unicode.h — BMP Unicode support for locale APIs.
 *
 * Backed by generated tables (src/common/unicode.c, see
 * scripts/dev/gen_unicode.py). Used by GetStringTypeW, LCMapStringW,
 * CompareString, lstrcmpi*.
 */
#ifndef WN_UNICODE_H
#define WN_UNICODE_H

#include <stdint.h>

/* Simple case mapping (identity when no mapping exists; astral -> identity). */
uint32_t wn_uni_to_upper(uint32_t cp);
uint32_t wn_uni_to_lower(uint32_t cp);

/* Windows character classes (values, not masks, per Windows docs):
 *  ctype1 -> CT_CTYPE1 flags (C1_UPPER..C1_ALPHA)
 *  ctype2 -> CT_CTYPE2 directionality values (C2_LEFTTORIGHT = 1, ...)
 *  ctype3 -> CT_CTYPE3 flags (C3_NONSPACING..C3_IDEOGRAPH)
 * Unassigned/astral codepoints return 0. */
uint32_t wn_uni_ctype1(uint32_t cp);
uint32_t wn_uni_ctype2(uint32_t cp);
uint32_t wn_uni_ctype3(uint32_t cp);

#endif /* WN_UNICODE_H */
