/* fuzz_pe.c — mutation fuzzer for the PE loader core.
 *
 * Forks per iteration: the child runs wn_pe_map + relocations + export
 * resolve + unmap on a mutated seed; any child death (signal, ASan abort)
 * is a loader bug and the input is saved to tests/fuzz/crashes/.
 * Clean rejections (nonzero error return) are correct behavior.
 *
 * Build & run through tests/fuzz/fuzz.sh (uses the ASan debug objects).
 */
#include "wn_pe.h"
#include "wn_log.h"
#include "wn_util.h"

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static uint64_t rdt = 0x9E3779B97F4A7C15ULL;
static uint64_t rnd(void)
{
    rdt ^= rdt << 13;
    rdt ^= rdt >> 7;
    rdt ^= rdt << 17;
    return rdt;
}

static void mutate(uint8_t *buf, size_t len)
{
    int mode = (int)(rnd() % 4);
    switch (mode) {
    case 0: {   /* random bit flips */
        int n = 1 + (int)(rnd() % 16);
        for (int i = 0; i < n && len > 0; i++) {
            size_t p = (size_t)(rnd() % len);
            buf[p] ^= (uint8_t)(1u << (rnd() % 8));
        }
        break;
    }
    case 1: {   /* smash 8 bytes somewhere */
        if (len > 8) {
            size_t p = (size_t)(rnd() % (len - 8));
            uint64_t v = rnd();
            memcpy(buf + p, &v, 8);
        }
        break;
    }
    case 2: {   /* header field fuzz: lfanew / section table area */
        if (len > 0x400) {
            size_t p = 0x40 + (size_t)(rnd() % 0x380);
            buf[p] = (uint8_t)rnd();
        }
        break;
    }
    default: {  /* zero a run */
        if (len > 16) {
            size_t p = (size_t)(rnd() % (len - 16));
            memset(buf + p, 0, 1 + (size_t)(rnd() % 16));
        }
        break;
    }
    }
}

static int run_child(const uint8_t *buf, size_t len)
{
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        /* Child: exercise the loader. Any crash = bug. */
        wn_pe_image img;
        uint32_t rc = wn_pe_map(buf, len, "fuzz-input", &img);
        if (rc == 0) {
            wn_pe_apply_relocations(&img);
            wn_pe_resolve_export(&img, "SomeExportName", 0, 0, 0);
            wn_pe_resolve_export(&img, NULL, 1, 1, 0);
            wn_pe_unmap(&img);
        }
        _exit(rc == 0 ? 0 : 1);
    }
    int st = 0;
    waitpid(pid, &st, 0);
    if (WIFSIGNALED(st))
        return WTERMSIG(st);
    if (WIFEXITED(st) && WEXITSTATUS(st) != 0 && WEXITSTATUS(st) != 1)
        return WEXITSTATUS(st);   /* ASan aborts with specific codes */
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <seed.pe> <iterations> [crash-dir]\n", argv[0]);
        return 2;
    }
    const char *seed_path = argv[1];
    long iterations = strtol(argv[2], NULL, 10);
    const char *crash_dir = argc > 3 ? argv[3] : NULL;

    FILE *f = fopen(seed_path, "rb");
    if (!f) {
        perror("seed");
        return 2;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *seed = wn_xmalloc((size_t)sz);
    if (fread(seed, 1, (size_t)sz, f) != (size_t)sz) {
        perror("seed read");
        return 2;
    }
    fclose(f);

    if (crash_dir)
        mkdir(crash_dir, 0777);

    rdt ^= (uint64_t)time(NULL) ^ (uint64_t)getpid();
    long crashes = 0, accepted = 0;
    for (long it = 0; it < iterations; it++) {
        size_t len = (size_t)sz;
        /* Occasionally truncate. */
        if (rnd() % 8 == 0 && len > 64)
            len = 64 + (size_t)(rnd() % (len - 64));
        uint8_t *buf = wn_xmalloc(len);
        memcpy(buf, seed, len);
        int rounds = 1 + (int)(rnd() % 4);
        for (int r = 0; r < rounds; r++)
            mutate(buf, len);

        int res = run_child(buf, len);
        if (res != 0) {
            crashes++;
            fprintf(stderr, "CRASH it=%ld sig/code=%d len=%zu\n", it, res, len);
            if (crash_dir) {
                char path[512];
                snprintf(path, sizeof path, "%s/crash-%ld-%d.bin",
                         crash_dir, it, res);
                FILE *o = fopen(path, "wb");
                if (o) {
                    fwrite(buf, 1, len, o);
                    fclose(o);
                }
            }
        } else {
            accepted++;
        }
        free(buf);
    }
    printf("fuzz: %ld iterations, %ld crashes, %ld clean runs\n",
           iterations, crashes, accepted);
    return crashes ? 1 : 0;
}
