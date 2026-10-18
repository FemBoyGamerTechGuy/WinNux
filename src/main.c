/* main.c — winnux CLI: `winnux run app.exe [args...]`, `winnux bench`,
 * `winnux --version`.
 *
 * Startup order (see docs/ARCHITECTURE.md):
 *   log init -> process create (PEB/TEB/env) -> prefix -> registry ->
 *   builtin modules -> exe load (map/reloc/imports/TLS/protect) -> LDR ->
 *   cmdline -> guest main thread (TLS callbacks -> PE entry) -> wait exit.
 */
#include "wn_log.h"
#include "wn_module.h"
#include "wn_process.h"
#include "wn_path.h"
#include "wn_registry.h"
#include "wn_dll.h"
#include "wn_pe.h"
#include "wn_util.h"
#include "wn_vulkan_loader.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>

#define WINNUX_VERSION "0.1.0"

extern void wn_ms_set_args(int argc, char **argv);
extern int  wn_cmd_imports(int argc, char **argv);

static struct {
    const char *prefix;
    const char *backend;
} g_cli;

/* --- guest entry ------------------------------------------------------------ */

/* Run the exe's TLS callbacks (if any), then its entry point. */
static WN_API uint64_t guest_entry_shim(uint64_t unused)
{
    (void)unused;
    wn_module *exe = g_proc.exe;

    /* TLS callbacks: NULL-terminated array of VAs (8-byte elements on PE32+,
     * 4-byte on PE32 — width MUST match or we read garbage pointers). */
    if (exe->kind == WN_MOD_PE) {
        const wn_image_data_directory *dirs = wn_pe_dirs(&exe->pe);
        const wn_image_data_directory *dir = &dirs[WN_IMAGE_DIR_TLS];
        int cb_width = exe->pe.is_64 ? 8 : 4;
        uint64_t cbva = 0;
        if (dir->virtual_address &&
            dir->size >= (exe->pe.is_64 ? sizeof(wn_image_tls_directory64)
                                        : sizeof(wn_image_tls_directory32))) {
            if (exe->pe.is_64) {
                const wn_image_tls_directory64 *tls =
                    wn_pe_rva(&exe->pe, dir->virtual_address, sizeof *tls);
                if (tls)
                    cbva = tls->address_of_callbacks;
            } else {
                const wn_image_tls_directory32 *tls =
                    wn_pe_rva(&exe->pe, dir->virtual_address, sizeof *tls);
                if (tls)
                    cbva = tls->address_of_callbacks;
            }
        }
        if (cbva) {
            if (cbva >= exe->pe.preferred_base &&
                cbva < exe->pe.preferred_base + exe->pe.size_of_image)
                cbva = (uint64_t)(uintptr_t)exe->pe.base
                     + (cbva - exe->pe.preferred_base);
            uint8_t *cbs = (uint8_t *)(uintptr_t)cbva;
            typedef WN_API void (*tls_cb)(void *, uint32_t, void *);
            for (uint32_t i = 0; i < 64; i++) {
                uint64_t fnva;
                if (cb_width == 8)
                    memcpy(&fnva, cbs + (size_t)i * 8, 8);
                else {
                    uint32_t v;
                    memcpy(&v, cbs + (size_t)i * 4, 4);
                    fnva = v;
                }
                if (!fnva)
                    break;
                wn_log(WN_LOG_DEBUG, "loader: TLS callback[%u] = 0x%llx", i,
                       (unsigned long long)fnva);
                ((tls_cb)(uintptr_t)fnva)(exe->base, 1 /*DLL_PROCESS_ATTACH*/, NULL);
            }
        }
    }

    typedef WN_API uint32_t (*entry_fn)(void *, uint32_t, void *);
    entry_fn entry = (entry_fn)(void *)(exe->base + exe->pe.entry_rva);
    wn_log(WN_LOG_INFO, "loader: calling entry point at %s+0x%x",
           exe->name, exe->pe.entry_rva);
    uint32_t rv = entry ? entry((void *)(uintptr_t)g_proc.peb, 1, 0) : 0;
    /* EXE entry returned without ExitProcess: treat retval as exit code. */
    wn_process_exit((int)(int32_t)rv);
    return rv;
}

/* --- run command --------------------------------------------------------------- */

static int file_exists(const char *p)
{
    struct stat st;
    return stat(p, &st) == 0;
}

/* Resolve the user-supplied app argument to a host path:
 *   - absolute host path        (/home/z/putty.exe)
 *   - relative host path        (./putty.exe, putty.exe)
 *   - Windows drive path        (C:\apps\putty.exe, Z:\home\z\putty.exe)
 *   - bare name                 (putty -> PATH search + .exe/.EXE probing)
 * Requires g_proc.prefix to be decided (done in wn_process_create). */
static char *resolve_app_path(const char *arg)
{
    size_t l = strlen(arg);
    /* Windows drive letter? (Accept 'C:/...' too.) */
    if (l >= 2 && arg[1] == ':' &&
        ((arg[0] >= 'A' && arg[0] <= 'Z') || (arg[0] >= 'a' && arg[0] <= 'z'))) {
        char host[2100];
        if (wn_path_resolve_ci(arg, host, sizeof host) == 0 && file_exists(host))
            return wn_xstrdup(host);
        return NULL;
    }
    /* Host-style: absolute or relative. */
    if (file_exists(arg))
        return wn_xstrdup(arg);
    if (arg[0] != '/' && arg[0] != '.' && !strchr(arg, '/')) {
        /* Bare name: probe PATH (and cwd) with .exe/.EXE suffixes. */
        static const char *exts[] = { "", ".exe", ".EXE", ".Exe", NULL };
        char *found = NULL;
        char dirbuf[8192];
        const char *path_env = getenv("PATH");
        snprintf(dirbuf, sizeof dirbuf, "%s", path_env ? path_env : "");
        char *save = NULL;
        for (char *d = strtok_r(dirbuf, ":", &save); d && !found;
             d = strtok_r(NULL, ":", &save)) {
            for (int e = 0; exts[e] && !found; e++) {
                char cand[8600];
                snprintf(cand, sizeof cand, "%s/%s%s", d, arg, exts[e]);
                if (file_exists(cand))
                    found = wn_xstrdup(cand);
            }
        }
        /* cwd probes (strtok loop above only sees PATH dirs). */
        for (int e = 0; exts[e] && !found; e++) {
            char cand[4200];
            snprintf(cand, sizeof cand, "%s%s", arg, exts[e]);
            if (file_exists(cand))
                found = wn_xstrdup(cand);
        }
        return found;
    }
    return NULL;
}

/* Peek at the PE machine type without loading (0 on error). */
static uint16_t pe_peek_machine(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return 0;
    wn_image_dos_header dos;
    if (fread(&dos, 1, sizeof dos, f) != sizeof dos || dos.e_magic != 0x5A4D ||
        dos.e_lfanew <= 0 || fseek(f, dos.e_lfanew + 4, SEEK_SET) != 0) {
        fclose(f);
        return 0;
    }
    wn_image_file_header fh;
    if (fread(&fh, 1, sizeof fh, f) != sizeof fh) {
        fclose(f);
        return 0;
    }
    fclose(f);
    return fh.machine;
}

/* 32-bit EXE on a 64-bit build: re-exec the 32-bit loader (Wine's wine64 /
 * wine split, inverted). bin/winnux32 lives next to /proc/self/exe. */
__attribute__((unused)) static int reexec_w32(int argc, char **argv)
{
    char self[300];
    ssize_t n = readlink("/proc/self/exe", self, sizeof self - 1);
    if (n <= 0)
        return 0;
    self[n] = 0;
    char *slash = strrchr(self, '/');
    if (!slash)
        return 0;
    snprintf(slash + 1, sizeof self - (size_t)(slash + 1 - self), "winnux32");
    struct stat st;
    if (stat(self, &st) != 0 || !S_ISREG(st.st_mode))
        return 0;
    /* Build the new argv: winnux32 <original run args...> */
    char **nargv = wn_xmalloc(((size_t)argc + 2) * sizeof(char *));
    nargv[0] = (char *)"winnux32";
    nargv[1] = (char *)"run";
    for (int i = 0; i < argc; i++)
        nargv[i + 2] = argv[i];
    nargv[argc + 2] = NULL;
    wn_log(WN_LOG_INFO, "winnux: 32-bit image -> re-exec %s", self);
    execv(self, nargv);
    /* exec failed */
    wn_log(WN_LOG_ERR, "winnux: exec of %s failed: %s", self, strerror(errno));
    free(nargv);
    return 0;
}

static int cmd_run(int argc, char **argv)
{
    /* Options before the exe path. */
    int i = 0;
    while (i < argc && argv[i][0] == '-') {
        if (!strcmp(argv[i], "--prefix") && i + 1 < argc) {
            g_cli.prefix = argv[++i];
            i++;
        } else if (!strcmp(argv[i], "--backend") && i + 1 < argc) {
            g_cli.backend = argv[++i];
            setenv("WINNUX_BACKEND", g_cli.backend, 1);
            i++;
        } else if (!strcmp(argv[i], "--log") && i + 1 < argc) {
            setenv("WINNUX_LOG", argv[++i], 1);
            i++;
        } else if (!strcmp(argv[i], "--trace")) {
            setenv("WINNUX_TRACE", "1", 1);
            i++;
        } else {
            fprintf(stderr, "winnux: unknown option '%s'\n", argv[i]);
            return 2;
        }
    }
    if (i >= argc) {
        fprintf(stderr, "usage: winnux run [--prefix DIR] [--backend x11|wayland] "
                "[--log LEVEL] app.exe [args...]\n");
        return 2;
    }
    const char *exe_arg = argv[i];

    wn_log_init();
    if (wn_process_create(g_cli.prefix, exe_arg) != 0)
        return 1;
    if (wn_path_prefix_init(g_proc.prefix) != 0)
        return 1;
    wn_path_init_cwd_from_host();
    wn_registry_init();
    wn_module_init();
    wn_dll_sync_placeholders();

    /* Resolve the app path (host / windows / bare name + PATH). */
    char *exe_path = resolve_app_path(exe_arg);
    if (!exe_path) {
        fprintf(stderr, "winnux: cannot find '%s' (looked in cwd, PATH, and "
                "as a C:/Z: windows path)\n", exe_arg);
        return 127;
    }
    /* 32-bit EXE: hand off to the 32-bit loader build (bin/winnux32). */
    if (pe_peek_machine(exe_path) == WN_IMAGE_FILE_MACHINE_I386) {
#if defined(__x86_64__)
        if (reexec_w32(argc - i, argv + i))
            return 0;     /* never reached on success (execv) */
        fprintf(stderr, "winnux: this is a 32-bit (i386) executable and the "
                "32-bit loader 'winnux32' was not found next to winnux.\n"
                "                build it with: make winnux32\n");
        free(exe_path);
        return 1;
#else
        /* already the 32-bit build: fall through */
#endif
    }
    /* Make it absolute: the guest sees argv[0] as a Windows path, and the
     * working directory can legitimately change during startup. */
    char abs_exe[4096];
    if (realpath(exe_path, abs_exe))
        snprintf(abs_exe, sizeof abs_exe, "%s", exe_path);   /* realpath failed: keep as-is */
    free(exe_path);
    exe_path = wn_xstrdup(abs_exe[0] ? abs_exe : exe_arg);

    wn_module *exe = wn_module_load_exe(exe_path);
    if (!exe) {
        free(exe_path);
        return 1;
    }
    wn_process_note_exe(exe);
    wn_module_build_ldr();

    /* Command line with a Windows-style argv[0]. */
    char argv0[1100];
    wn_path_host_to_win(exe_path, argv0, sizeof argv0);
    int g_argc = argc - i;
    char **g_argv = wn_xmalloc((g_argc + 1) * sizeof(char *));
    g_argv[0] = argv0;
    for (int j = 1; j < g_argc; j++)
        g_argv[j] = argv[i + j];
    g_argv[g_argc] = NULL;
    wn_process_set_cmdline(g_argc, g_argv);
    wn_ms_set_args(g_argc, g_argv);

    /* Guest main thread. */
    wn_thread *th;
    if (!wn_thread_create(exe->pe.stack_reserve, guest_entry_shim, 0, 0, &th, NULL))
        return 1;
    pthread_join(th->pthread, NULL);
    int rv = g_proc.exe ? 0 : 0;
    free(exe_path);   /* exit-time leak flagged by LeakSanitizer */
    wn_process_exit(rv);
    return 0;
}

/* --- i386 note ------------------------------------------------------------------
 * guest_entry_shim's TLS-callback walk and entry call above are written in
 * the x64 shapes; on an i386 build the callback array elements are 4 bytes
 * and the entry takes 3 pointer-sized args (the typedefs already scale
 * through uintptr_t). The 32-bit TLS directory variant is handled in
 * wn_pe_tls_setup via wn_pe_dirs(). */

/* --- bench command ---------------------------------------------------------------- */

static int cmd_bench(void)
{
    printf("WinNux %s bench (%s, %d cpus visible)\n", WINNUX_VERSION,
           "x86_64-linux", (int)sysconf(_SC_NPROCESSORS_ONLN));

    /* Loader throughput: map+reloc a real Windows PE repeatedly. */
    const char *seed = NULL;
    struct stat st;
    static const char *cands[] = { "tests/bin/t01_hello_write.exe",
                                   "tests/bin/t02_hello_printf.exe", NULL };
    for (int i = 0; cands[i] && !seed; i++)
        if (stat(cands[i], &st) == 0)
            seed = cands[i];
    if (seed && st.st_size > 0x400) {
        FILE *f = fopen(seed, "rb");
        if (f) {
            uint8_t *data = wn_xmalloc((size_t)st.st_size);
            size_t got = fread(data, 1, (size_t)st.st_size, f);
            fclose(f);
            if (got > sizeof(wn_image_dos_header) &&
                ((wn_image_dos_header *)data)->e_magic == 0x5A4D) {
                const int N = 50;
                uint64_t t0 = wn_monotonic_ns();
                for (int i = 0; i < N; i++) {
                    wn_pe_image img;
                    if (wn_pe_map(data, got, seed, &img) == 0) {
                        wn_pe_apply_relocations(&img);
                        wn_pe_unmap(&img);
                    }
                }
                uint64_t t1 = wn_monotonic_ns();
                printf("  pe-map:      %d map+reloc in %.2f ms (%.2f us/image, "
                       "%.1f MB/s)\n", N, (t1 - t0) / 1e6, (t1 - t0) / 1e3 / N,
                       (double)got * N / ((t1 - t0) / 1e9) / 1e6);
            } else {
                printf("  pe-map:      seed invalid\n");
            }
            free(data);
        }
    } else {
        printf("  pe-map:      no PE seed (run make test first)\n");
    }

    /* futex ping-pong cost. */
    {
        uint32_t word = 0;
        const int N = 10000;
        uint64_t t0 = wn_monotonic_ns();
        for (int i = 0; i < N; i++)
            wn_futex_wake(&word, 0);
        uint64_t t1 = wn_monotonic_ns();
        printf("  futex-wake:  %d no-op wakes in %.2f ms\n", N, (t1 - t0) / 1e6);
    }

    /* Software fill throughput (GDI path) — checksummed so it cannot be
     * optimized away. */
    {
        size_t bytes = 64u << 20;
        uint8_t *b = malloc(bytes);
        if (b) {
            uint64_t t0 = wn_monotonic_ns();
            memset(b, 0x5A, bytes);
            uint64_t t1 = wn_monotonic_ns();
            volatile uint64_t sink = 0;
            for (size_t i = 0; i < bytes; i += 4096)
                sink += b[i];
            printf("  memset:      %.2f GB/s (checksum %llu)\n",
                   (double)bytes / ((t1 - t0) / 1e9) / 1e9,
                   (unsigned long long)sink);
            free(b);
        }
    }

    wn_vk_report();
    return 0;
}

/* --- main -------------------------------------------------------------------------- */

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr,
                "WinNux %s — Windows compatibility layer in raw C\n"
                "usage: winnux <command> [args]\n"
                "  run app.exe [args...]   run a Windows PE32+ executable\n"
                "  imports app.exe         list imports: implemented/stubbed/missing\n"
                "  bench                   performance measurements\n"
                "  --version               print version\n",
                WINNUX_VERSION);
        return 2;
    }
    if (!strcmp(argv[1], "--version") || !strcmp(argv[1], "-v")) {
        printf("WinNux %s (x86_64 linux, C11)\n", WINNUX_VERSION);
        return 0;
    }
    if (!strcmp(argv[1], "run"))
        return cmd_run(argc - 2, argv + 2);
    if (!strcmp(argv[1], "imports"))
        return wn_cmd_imports(argc - 2, argv + 2);
    if (!strcmp(argv[1], "bench"))
        return cmd_bench();
    fprintf(stderr, "winnux: unknown command '%s'\n", argv[1]);
    return 2;
}
