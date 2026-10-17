/* wn_util.h — small shared helpers: allocation, UTF conversion, strings.
 * All allocation aborts the process on OOM (documented, intentional: there is
 * no sane recovery path for the host itself running out of memory).
 */
#ifndef WN_UTIL_H
#define WN_UTIL_H

#include <stddef.h>
#include <stdint.h>

/* x-malloc family: dies loudly on OOM (see header comment). */
void  *wn_xmalloc(size_t n);
void  *wn_xcalloc(size_t n, size_t sz);
void  *wn_xrealloc(void *p, size_t n);
char  *wn_xstrdup(const char *s);

/* Case-insensitive ASCII compare (Windows path/name matching semantics). */
int    wn_strcaseeq(const char *a, const char *b);
/* Case-insensitive prefix compare: does s start with prefix? */
int    wn_strcaseprefix(const char *s, const char *prefix);
/* Lowercase into caller buffer (ASCII fold; non-ASCII bytes untouched). */
void   wn_strlower(char *dst, size_t cap, const char *src);

/* UTF-16LE <-> UTF-8. Return allocated strings (xmalloc), or NULL on
 * invalid input (caller decides policy). Surrogate pairs handled. */
uint16_t *wn_utf8_to_utf16(const char *utf8, size_t *out_len16);
/* Like above but for a fixed byte length (no NUL requirement). */
uint16_t *wn_utf8_to_utf16_n(const char *utf8, size_t nbytes);
char     *wn_utf16_to_utf8(const uint16_t *w, size_t len16);

/* Split a path into directory + file component. Modifies nothing; returns
 * pointer to basename within path, sets *dir_len (may be 0). */
const char *wn_path_basename(const char *path, size_t *dir_len);

/* Simple growable byte buffer. */
typedef struct {
    uint8_t *data;
    size_t   len;
    size_t   cap;
} wn_buf;

void wn_buf_init(wn_buf *b);
void wn_buf_free(wn_buf *b);
/* Append n bytes; returns 0 on success, -1 on OOM abort (never returns). */
void wn_buf_append(wn_buf *b, const void *data, size_t n);
void wn_buf_append_str(wn_buf *b, const char *s);

/* Monotonic nanoseconds. */
uint64_t wn_monotonic_ns(void);

#endif /* WN_UTIL_H */
