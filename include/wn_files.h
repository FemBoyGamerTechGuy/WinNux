/* wn_files.h — file object layer under kernel32's file APIs.
 */
#ifndef WN_FILES_H
#define WN_FILES_H

#include "wn_types.h"

typedef struct wn_file {
    int      fd;          /* -1 for pseudo console/std handles */
    int      std_fd;     /* 0/1/2 for stdin/stdout/stderr, else -1 */
    int      is_console;
    int      is_dir;
    int      append;
    int      delete_on_close;
    char     win_path[1024];
} wn_file;

/* Translate Windows creation/access/disposition to open() flags; opens the
 * file. Returns 0 and fills f; on failure returns 0 with last error set
 * (like CreateFile: check wn_last_error_get()). */
int  wn_file_open(const char *winpath, uint32_t access, uint32_t disposition,
                  uint32_t share, wn_file *f);

/* Console/std handles: allocate the three std handles at startup. */
void wn_files_std_init(void);

/* Read/Write with OVERLAPPED-less semantics. Return bytes or -1 (last err). */
int  wn_file_read(wn_file *f, void *buf, uint32_t n);
int  wn_file_write(wn_file *f, const void *buf, uint32_t n);

/* FindFirstFile support. */
typedef struct wn_find {
    void   *dir;           /* DIR* */
    char    pattern[256];  /* file part, wildcards */
    char    dir_host[4200];
    int     dot_state;     /* 0 start, 1 emitted "." 2 emitted ".." */
} wn_find;

int  wn_find_open(const char *winpattern, wn_find *out);
int  wn_find_next(wn_find *f, char *name_out, size_t cap, uint32_t *attrs,
                  uint64_t *size_out);
void wn_find_close(wn_find *f);

/* Wildcard match (Windows semantics: * and ?, case-insensitive). */
int  wn_glob_match(const char *pat, const char *name);

#endif /* WN_FILES_H */
