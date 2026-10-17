/* wn_path.h — Windows path <-> host path translation and the prefix.
 *
 * "C:\foo\bar.txt"  ->  <prefix>/drive_c/foo/bar.txt
 * "Z:\etc\passwd"   ->  /etc/passwd          (Z: is a window onto the host)
 * Relative paths resolve against the Windows current directory, which is
 * tracked per process and synced with the host cwd.
 *
 * Windows is case-insensitive: lookups resolve each component against
 * readdir when the exact-case path is missing.
 */
#ifndef WN_PATH_H
#define WN_PATH_H

#include <stddef.h>

/* Create the prefix skeleton (drive_c/windows/{system32,temp}, registry file).
 * Returns 0 on success. */
int  wn_path_prefix_init(const char *prefix);

/* Windows path -> host path. Returns 0 and fills out (or a pointer into
 * win when no copy needed... always copies for safety). Returns -1 with a
 * loud log for unrepresentable paths (UNC etc.). */
int  wn_path_win_to_host(const char *win, char *out, size_t cap);

/* Host path -> Windows path (reverse mapping; outside prefix -> Z:\...). */
void wn_path_host_to_win(const char *host, char *out, size_t cap);

/* Resolve a Windows-style path to an exact-case existing host path.
 * Component-wise case-insensitive fallback. Returns 0 and fills out with
 * the resolved host path if the file exists, -1 otherwise (ENOENT-ish). */
int  wn_path_resolve_ci(const char *win, char *out, size_t cap);

/* Current directory (Windows form, e.g. "C:\work"). */
void wn_path_get_cwd_win(char *out, size_t cap);
/* Set both host cwd and Windows cwd; returns 0 on success. */
int  wn_path_set_cwd_win(const char *windir);
/* Initialize CWD mapping from the host cwd (startup). */
void wn_path_init_cwd_from_host(void);

/* The prefix directory (host form). */
const char *wn_path_prefix(void);

/* Case-insensitive lookup of `name` inside host dir `dir`. Returns 1 and
 * fills out (size cap) with "<dir>/<actual-name>" on hit, 0 on miss. */
int  wn_path_lookup_ci(const char *dir, const char *name, char *out, size_t cap);

/* True when the Windows path names a directory-style device we do not
 * support (CON, NUL, ...): returns such device names for the caller to log. */
const char *wn_path_is_device(const char *win);

#endif /* WN_PATH_H */
