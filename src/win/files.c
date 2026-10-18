/* files.c — file objects, open/read/write, FindFirstFile, globbing. */
#include "wn_files.h"
#include "wn_path.h"
#include "wn_log.h"
#include "wn_util.h"
#include "wn_process.h"

#include <ctype.h>
#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

/* Map Windows access + disposition onto open(2). */
int wn_file_open(const char *winpath, uint32_t access, uint32_t disposition,
                 uint32_t share, wn_file *f)
{
    (void)share;  /* mandatory locking unsupported; documented */
    memset(f, 0, sizeof *f);
    f->fd = -1;
    f->std_fd = -1;

    const char *dev = wn_path_is_device(winpath);
    if (dev) {
        if (!strcmp(dev, "NUL")) {
            f->fd = open("/dev/null", O_RDWR | O_CLOEXEC);
            if (f->fd < 0)
                goto oserr;
            snprintf(f->win_path, sizeof f->win_path, "%s", winpath);
            return 1;
        }
        wn_log(WN_LOG_WARN, "files: device '%s' unsupported", dev);
        wn_last_error_set(WN_ERR_INVALID_PARAMETER);
        return 0;
    }

    char host[4200];
    if (wn_path_resolve_ci(winpath, host, sizeof host) != 0) {
        /* Not found (possibly creatable). Translate through the full path
         * (this applies the CWD for relative paths), then CI-resolve only
         * the parent directory and append the literal file name. */
        char fullhost[4200];
        if (wn_path_win_to_host(winpath, fullhost, sizeof fullhost) != 0) {
            wn_last_error_set(WN_ERR_INVALID_NAME);
            return 0;
        }
        size_t dl;
        const char *base = wn_path_basename(fullhost, &dl);
        char dirpart[4100];
        if (dl >= sizeof dirpart) {
            wn_last_error_set(WN_ERR_INVALID_NAME);
            return 0;
        }
        memcpy(dirpart, fullhost, dl);
        dirpart[dl] = '\0';
        if (!dl)
            snprintf(dirpart, sizeof dirpart, ".");
        struct stat dst;
        if (dl && stat(dirpart, &dst) != 0) {
            wn_last_error_set(WN_ERR_PATH_NOT_FOUND);
            return 0;
        }
        snprintf(host, sizeof host, "%s/%s", dl ? dirpart : ".", base);
    }

    int flags = O_CLOEXEC;
    int rw = (access & 0xC0000000) >> 30;   /* GENERIC_READ/WRITE bits */
    if (rw == 1)      flags |= O_WRONLY;
    else if (rw == 3) flags |= O_RDWR;
    else              flags |= O_RDONLY;

    int created = 0;
    switch (disposition) {
    case 1: /* CREATE_NEW */          flags |= O_CREAT | O_EXCL; break;
    case 2: /* CREATE_ALWAYS */        flags |= O_CREAT | O_TRUNC; break;
    case 3: /* OPEN_EXISTING */        break;
    case 4: /* OPEN_ALWAYS */          flags |= O_CREAT; break;
    case 5: /* TRUNCATE_EXISTING */    flags |= O_TRUNC; break;
    default:
        wn_log(WN_LOG_WARN, "files: disposition %u unknown", disposition);
        wn_last_error_set(WN_ERR_INVALID_PARAMETER);
        return 0;
    }

    struct stat st;
    if (disposition == 3 && stat(host, &st) != 0) {
        wn_last_error_set(errno == ENOENT ? WN_ERR_FILE_NOT_FOUND
                                          : WN_ERR_PATH_NOT_FOUND);
        return 0;
    }
    if (disposition == 5 && stat(host, &st) != 0) {
        wn_last_error_set(WN_ERR_FILE_NOT_FOUND);
        return 0;
    }

    int fd = open(host, flags, 0666);
    if (fd < 0)
        goto oserr;
    created = (flags & O_CREAT) != 0 && (disposition != 3 || stat(host, &st) == 0);

    fstat(fd, &st);
    f->fd = fd;
    f->is_dir = S_ISDIR(st.st_mode);
    snprintf(f->win_path, sizeof f->win_path, "%s", winpath);

    if (created && disposition != 2)
        wn_log(WN_LOG_DEBUG, "files: created %s", host);
    return 1;

oserr:
    wn_log(WN_LOG_DEBUG, "files: open %s: %s", host, strerror(errno));
    switch (errno) {
    case ENOENT:  wn_last_error_set(WN_ERR_FILE_NOT_FOUND); break;
    case EACCES:  wn_last_error_set(WN_ERR_ACCESS_DENIED); break;
    case EISDIR:  wn_last_error_set(WN_ERR_ACCESS_DENIED); break;
    case ENOTDIR: wn_last_error_set(WN_ERR_PATH_NOT_FOUND); break;
    case EEXIST:  wn_last_error_set(WN_ERR_FILE_EXISTS); break;
    default:      wn_last_error_set(WN_ERR_GEN_FAILURE); break;
    }
    return 0;
}

int wn_file_read(wn_file *f, void *buf, uint32_t n)
{
    ssize_t r = read(f->fd, buf, n);
    if (r < 0) {
        wn_last_error_set(errno == EBADF ? WN_ERR_INVALID_HANDLE : WN_ERR_READ_FAULT);
        return -1;
    }
    return (int)r;
}

int wn_file_write(wn_file *f, const void *buf, uint32_t n)
{
    ssize_t r = write(f->fd, buf, n);
    if (r < 0) {
        wn_last_error_set(errno == EBADF ? WN_ERR_INVALID_HANDLE : WN_ERR_WRITE_FAULT);
        return -1;
    }
    return (int)r;
}

/* --- wildcard matching ------------------------------------------------------ */

int wn_glob_match(const char *pat, const char *name)
{
    /* Treat "*.*" as "*" (Windows quirk). */
    if (!strcmp(pat, "*.*"))
        pat = "*";
    /* Case-insensitive recursive matcher with * and ?. */
    if (!*pat)
        return !*name;
    if (*pat == '*') {
        for (const char *n = name; ; n++) {
            if (wn_glob_match(pat + 1, n))
                return 1;
            if (!*n)
                return 0;
        }
    }
    if (!*name)
        return 0;
    if (*pat == '?' || tolower((unsigned char)*pat) == tolower((unsigned char)*name))
        return wn_glob_match(pat + 1, name + 1);
    return 0;
}

/* --- FindFirstFile ----------------------------------------------------------- */

int wn_find_open(const char *winpattern, wn_find *out)
{
    memset(out, 0, sizeof *out);
    char clean[1024];
    size_t dl;
    snprintf(clean, sizeof clean, "%s", winpattern);
    /* Normalize separators to '/' so host-side splitting works. */
    for (char *q = clean; *q; q++)
        if (*q == '\\')
            *q = '/';
    const char *base = wn_path_basename(clean, &dl);
    char dirpart[1024];
    if (dl >= sizeof dirpart)
        return 0;
    memcpy(dirpart, clean, dl);
    dirpart[dl] = '\0';

    /* Translate the directory part through the full path machinery so
     * relative patterns enumerate the CWD (not the prefix root). */
    char dirwin[1024], dirhost[4200];
    if (!dl) {
        char cwdwin[1024];
        wn_path_get_cwd_win(cwdwin, sizeof cwdwin);
        snprintf(dirhost, sizeof dirhost, "%s", cwdwin);
        /* dirhost currently holds the Windows form; convert: */
        if (wn_path_win_to_host(dirhost, dirhost, sizeof dirhost) != 0)
            return 0;
    } else {
        snprintf(dirwin, sizeof dirwin, "%s", dirpart);
        if (wn_path_win_to_host(dirwin, dirhost, sizeof dirhost) != 0)
            return 0;
    }
    /* dirhost is a host path; make sure it exists (case may differ). */
    struct stat dst;
    if (stat(dirhost, &dst) != 0) {
        char resolved[4200];
        if (wn_path_resolve_ci(dl ? dirpart : ".", resolved, sizeof resolved) == 0)
            snprintf(dirhost, sizeof dirhost, "%s", resolved);
        else
            return 0;
    }

    snprintf(out->pattern, sizeof out->pattern, "%s", base);
    snprintf(out->dir_host, sizeof out->dir_host, "%s", dirhost);
    out->dir = opendir(dirhost);
    if (!out->dir)
        return 0;
    out->dot_state = 0;
    return 1;
}

int wn_find_next(wn_find *f, char *name_out, size_t cap, uint32_t *attrs,
                 uint64_t *size_out)
{
    DIR *d = (DIR *)f->dir;
    if (!d)
        return 0;
    int has_wild = strchr(f->pattern, '*') || strchr(f->pattern, '?');
    if (has_wild && f->dot_state < 2) {
        const char *sel = f->dot_state == 0 ? "." : "..";
        f->dot_state++;
        snprintf(name_out, cap, "%s", sel);
        if (attrs) *attrs = WN_FILE_ATTRIBUTE_DIRECTORY;
        if (size_out) *size_out = 0;
        return 1;
    }
    struct dirent64 *e;   /* readdir64: 32-bit readdir fails with
                            * EOVERFLOW on 64-bit-inode filesystems
                            * (overlayfs containers, btrfs). */
    while ((e = readdir64(d))) {
        if (has_wild ? wn_glob_match(f->pattern, e->d_name)
                     : wn_strcaseeq(e->d_name, f->pattern)) {
            snprintf(name_out, cap, "%s", e->d_name);
            struct stat st;
            char full[4600];
            snprintf(full, sizeof full, "%s/%s", f->dir_host, e->d_name);
            uint32_t a = 0;
            uint64_t sz = 0;
            if (stat(full, &st) == 0) {
                if (S_ISDIR(st.st_mode)) a |= WN_FILE_ATTRIBUTE_DIRECTORY;
                if (!(st.st_mode & S_IWUSR)) a |= WN_FILE_ATTRIBUTE_READONLY;
                if (e->d_name[0] == '.') a |= WN_FILE_ATTRIBUTE_HIDDEN;
                if (!a) a = WN_FILE_ATTRIBUTE_NORMAL;
                sz = (uint64_t)st.st_size;
            }
            if (attrs) *attrs = a;
            if (size_out) *size_out = sz;
            return 1;
        }
    }
    return 0;
}

void wn_find_close(wn_find *f)
{
    if (f->dir)
        closedir((DIR *)f->dir);
    f->dir = NULL;
}
