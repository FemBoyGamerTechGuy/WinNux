/* wn_process.h — guest-visible process state: TEB, PEB, LDR, parameters.
 *
 * Offsets match Windows x64 layouts exactly for every field guest code is
 * known to read (gs:0x30 self, gs:0x58 TLS array, gs:0x60 PEB, gs:0x68 last
 * error, PEB image base/Ldr/ProcessParameters/ProcessHeap/NumberOfProcessors).
 */
#ifndef WN_PROCESS_H
#define WN_PROCESS_H

#include "wn_types.h"
#include <pthread.h>

/* --- TEB (offsets are the ABI) ------------------------------------------- */
typedef struct wn_teb {
    uint64_t exception_list;        /* 0x00 (x64: mostly unused)        */
    uint64_t stack_base;            /* 0x08                             */
    uint64_t stack_limit;           /* 0x10                             */
    uint64_t subsystem_tib;         /* 0x18                             */
    uint64_t fiber_data_version;    /* 0x20                             */
    uint64_t arbitrary_user_pointer;/* 0x28                             */
    uint64_t self;                  /* 0x30 == address of this TEB      */
    uint64_t environment_pointer;   /* 0x38                             */
    uint64_t client_id_process;     /* 0x40                             */
    uint64_t client_id_thread;      /* 0x48 (Linux gettid)              */
    uint64_t active_rpc_handle;     /* 0x50                             */
    uint64_t *tls_array;            /* 0x58 ThreadLocalStoragePointer   */
    struct wn_peb *peb;             /* 0x60                             */
    uint32_t last_error;            /* 0x68                             */
    uint32_t count_owned_critsects; /* 0x6c                             */
    uint64_t csr_thread;            /* 0x70                             */
    uint64_t win32_thread_info;     /* 0x78 (user32 later)              */
    uint64_t reserved_80[12];       /* 0x80..0xdf                       */
    uint64_t wn_thread;             /* 0xE0: WN-internal wn_thread*     */
    uint64_t reserved_e8[88];       /* pad to 0x400                     */
} wn_teb;

/* --- PEB (offsets are the ABI; asserted below) ------------------------------ */
typedef struct wn_peb_ldr_data {
    uint32_t length;                /* 0x00                             */
    uint32_t initialized;           /* 0x04                             */
    uint64_t ss_handle;             /* 0x08                             */
    uint64_t in_load_order[2];      /* 0x10 LIST_ENTRY head             */
    uint64_t in_memory_order[2];    /* 0x20 LIST_ENTRY head             */
    uint64_t in_init_order[2];      /* 0x30 LIST_ENTRY head             */
    uint64_t pad[4];
} wn_peb_ldr_data;

typedef struct wn_peb {
    uint8_t  inherited_address_space;     /* 0x00 */
    uint8_t  read_image_file_exec_options;/* 0x01 */
    uint8_t  being_debugged;              /* 0x02 */
    uint8_t  bitfield;                    /* 0x03 */
    uint32_t pad04;
    uint64_t mutant;                      /* 0x08 */
    uint64_t image_base_address;          /* 0x10 */
    wn_peb_ldr_data *ldr;                 /* 0x18 */
    struct wn_rtl_user_process_parameters *process_parameters; /* 0x20 */
    uint64_t subsystem_data;              /* 0x28 */
    uint64_t process_heap;                /* 0x30 */
    void    *fast_peb_lock;               /* 0x38 */
    uint8_t  pad_40[0x24];                /* 0x40..0x63 */
    uint32_t number_of_processors;        /* 0x64 */
    uint8_t  pad_68[0x54];                /* 0x68..0xBB */
    uint32_t nt_global_flag;              /* 0xBC */
    uint8_t  pad_c0[0x100 - 0xC0];
} wn_peb;

_Static_assert(offsetof(wn_peb, mutant) == 0x08, "PEB ABI");
_Static_assert(offsetof(wn_peb, image_base_address) == 0x10, "PEB ABI");
_Static_assert(offsetof(wn_peb, ldr) == 0x18, "PEB ABI");
_Static_assert(offsetof(wn_peb, process_parameters) == 0x20, "PEB ABI");
_Static_assert(offsetof(wn_peb, process_heap) == 0x30, "PEB ABI");
_Static_assert(offsetof(wn_peb, fast_peb_lock) == 0x38, "PEB ABI");
_Static_assert(offsetof(wn_peb, number_of_processors) == 0x64, "PEB ABI");
_Static_assert(offsetof(wn_peb, nt_global_flag) == 0xBC, "PEB ABI");
_Static_assert(offsetof(wn_teb, last_error) == 0x68, "TEB ABI");
_Static_assert(offsetof(wn_teb, self) == 0x30, "TEB ABI");
_Static_assert(offsetof(wn_teb, tls_array) == 0x58, "TEB ABI");
_Static_assert(offsetof(wn_teb, peb) == 0x60, "TEB ABI");
_Static_assert(offsetof(wn_teb, wn_thread) == 0xE0, "TEB ABI");

typedef struct wn_rtl_user_process_parameters {
    uint32_t maximum_length;          /* 0x00 */
    uint32_t length;                  /* 0x04 */
    uint32_t flags;                   /* 0x08 */
    uint32_t debug_flags;             /* 0x0c */
    uint64_t console_handle;          /* 0x10 */
    uint64_t console_flags;           /* 0x18 */
    uint64_t standard_input;          /* 0x20 */
    uint64_t standard_output;         /* 0x28 */
    uint64_t standard_error;          /* 0x30 */
    wn_unicode_string current_directory;   /* 0x38 */
    uint64_t current_directory_handle;     /* 0x48 */
    wn_unicode_string dll_path;            /* 0x50 */
    wn_unicode_string image_path_name;     /* 0x60 */
    wn_unicode_string command_line;        /* 0x70 */
    uint16_t *environment;                 /* 0x80 */
    uint64_t remainder[24];
} wn_rtl_user_process_parameters;

/* LDR_DATA_TABLE_ENTRY, guest-visible. */
typedef struct wn_ldr_entry {
    uint64_t in_load_order[2];        /* 0x00 Flink/Blink */
    uint64_t in_memory_order[2];      /* 0x10 */
    uint64_t in_init_order[2];        /* 0x20 */
    uint64_t dll_base;                /* 0x30 */
    uint64_t entry_point;             /* 0x38 */
    uint32_t size_of_image;           /* 0x40 */
    uint32_t pad44;
    wn_unicode_string full_dll_name;  /* 0x48 */
    wn_unicode_string base_dll_name;  /* 0x58 */
    uint64_t remainder[8];
} wn_ldr_entry;

/* RTL_CRITICAL_SECTION layout (guest in-place object). */
typedef struct wn_critsect {
    uint64_t debug_info;              /* 0x00 */
    int32_t lock_count;               /* 0x08: -1 free */
    int32_t recursion_count;          /* 0x0c */
    uint64_t owning_thread;           /* 0x10 (tid) */
    uint64_t lock_semaphore;          /* 0x18 unused */
    uint32_t spin_count;              /* 0x20 */
    uint32_t pad24;
} wn_critsect;

/* --- threads --------------------------------------------------------------- */
typedef struct wn_thread {
    pthread_t pthread;
    uint32_t  tid;
    wn_teb   *teb;
    uint64_t  stack_low, stack_high;
    uint32_t  exit_code;
    int       exited;
    int       suspended;              /* suspend count */
    void     *altstack;
} wn_thread;

/* --- global process state (documented global: one per process) ------------- */
typedef struct wn_process {
    char     prefix[1024];            /* host prefix dir */
    struct wn_module *exe;            /* main exe module */
    char    *cmdline_utf8;            /* Windows-style: "app.exe" arg1 arg2 */
    uint16_t *cmdline_utf16;
    uint16_t *env_utf16;              /* double-NUL terminated */
    char   **env_utf8;                /* NULL-terminated "K=V" list */
    wn_peb *peb;
    wn_rtl_user_process_parameters *params;
    wn_peb_ldr_data *ldr;
    wn_critsect *peb_lock;            /* fast peb lock object */
    uint32_t pid;
    int      exit_code;
    uint32_t next_tid;
    uint64_t start_time_ft;           /* FILETIME at process start */
    /* Heap used for HeapAlloc default (process heap). */
    void    *process_heap;
    /* Global wait channel for WaitForMultipleObjects (see sync.c). */
    uint32_t global_wake;
    /* Registered atexit-style process detach callbacks (msvcrt). */
    void   (*atexit_fns[64])(void);
    int      atexit_count;
} wn_process;

extern wn_process g_proc;

/* Default prefix location: $WINNUX_HOME/default, else ~/.WinNux/default.
 * Mirrors the documented environment layout (README/ARCHITECTURE). */
void wn_prefix_default(char *out, size_t cap);

/* Run FLS destructors for the current thread (called from thread exit). */
void wn_fls_run_callbacks(void);

/* Initialize process-wide state: prefix, env, PEB skeleton. Returns 0. */
uint32_t wn_process_create(const char *prefix, const char *exe_display_name);

/* Build command line (utf8+utf16) and environment block from argv/envp. */
void wn_process_set_cmdline(int argc, char **argv);

/* Allocate a TEB (+ TLS array) and set this thread's GS base to it.
 * Every thread that runs guest code must run this. Returns the TEB. */
wn_teb *wn_teb_attach(void);

/* Current TEB via gs:0x30 (fast path; requires wn_teb_attach earlier). */
wn_teb *wn_teb_current(void);

/* Thread creation. start is ms_abi; it will be called with param. */
uint32_t wn_thread_create(uint64_t stack_reserve, WN_API uint64_t (*start)(uint64_t),
                          uint64_t param, int create_suspended,
                          wn_thread **out, wn_handle *out_handle);

/* Current wn_thread* (NULL on threads without guest context). */
wn_thread *wn_thread_current(void);

/* Suspend/resume via SIGUSR1 (documented race caveats in thread.c).
 * Return previous suspend count, 0xFFFFFFFF on failure. */
uint32_t wn_thread_suspend(wn_thread *th);
uint32_t wn_thread_resume(wn_thread *th);

/* Thread exit (called from ExitThread or when thread start returns). */
void wn_thread_exit(uint32_t code) __attribute__((noreturn));

/* Process shutdown: LDR detach, registry save, exit(code). */
void wn_process_exit(int code) __attribute__((noreturn));

/* Last error accessors (TEB 0x68). */
uint32_t wn_last_error_get(void);
void     wn_last_error_set(uint32_t e);

/* Allocate a thread id (uses gettid when on a thread, counter otherwise). */
uint32_t wn_alloc_tid(void);

/* Note the exe module once loaded (fills PEB->ImageBaseAddress). */
void wn_process_note_exe(struct wn_module *m);

/* Register an msvcrt-style atexit callback (max 64). */
int  wn_process_atexit(void (*fn)(void));

/* Static TLS: register a module's TLS block factory. Called by loader when a
 * module with a TLS directory loads; new threads copy the template. */
void     wn_tls_register_module(struct wn_module *m);
void     wn_tls_thread_init(wn_teb *teb);

/* futex helper shared by sync + suspend. */
int      wn_futex_wait(uint32_t *addr, uint32_t expected, const struct timespec *abs_ts);
int      wn_futex_wake(uint32_t *addr, int n);

#endif /* WN_PROCESS_H */
