/* wn_types.h — Windows base types used across WinNux.
 *
 * Everything the guest world touches flows through these. Keep them exact:
 * layout-compatible with real Windows x64 definitions where guest code can
 * see them.
 */
#ifndef WN_TYPES_H
#define WN_TYPES_H

#include <stdint.h>
#include <stddef.h>

typedef uint8_t  wn_byte;
typedef uint16_t wn_word;
typedef uint32_t wn_dword;
typedef uint64_t wn_qword;
typedef int32_t  wn_long;      /* Windows LONG is 32 bits */
typedef intptr_t wn_intptr;
typedef uintptr_t wn_uintptr;
typedef long long wn_longlong;

typedef void          *wn_handle;      /* opaque HANDLE */
typedef void          *wn_lpparam_void;
typedef const char    *wn_pcstr;
typedef char          *wn_lpstr;
typedef uint16_t      *wn_pwstr;      /* UTF-16LE */
typedef const uint16_t *wn_pcwstr;

typedef wn_dword wn_colorref;

/* Windows API calling convention: on x86_64 there is exactly one convention
 * and it is the Microsoft x64 ABI. GCC/Clang expose it via ms_abi so builtin
 * functions can be called directly by guest code with zero thunks.
 *
 * i386 (WoW64 groundwork, IN PROGRESS — see STATUS.md): Win32 APIs are
 * stdcall (callee cleans) and msvcrt varargs are cdecl, so the i386 dispatch
 * layer needs per-export convention metadata before any 32-bit guest can
 * run. Until that lands, WN_API maps to PLAIN cdecl on i386: `make
 * check32` compiles the whole tree with -m32 to keep the source 32-bit
 * clean (pointer-size assumptions, struct layouts) without claiming a
 * working convention. */
#if defined(__x86_64__)
#define WN_API __attribute__((ms_abi))
#elif defined(__i386__)
#define WN_API                   /* cdecl; stdcall metadata TBD (STATUS.md) */
#else
#error "WinNux targets x86 (32/64) only; aarch64 is planned"
#endif

/* Export-table signature for builtin DLLs: ms_abi functions whose address is
 * handed to guest code through the IAT / GetProcAddress. */
typedef WN_API void (*wn_fnptr_void)(void);
typedef WN_API uintptr_t (*wn_fnptr_generic)(uintptr_t, uintptr_t, uintptr_t,
                                             uintptr_t);

/* Booleans and status codes as Windows sees them. */
typedef int32_t wn_bool32;            /* BOOL */
#define WN_TRUE  1
#define WN_FALSE 0

typedef uint32_t wn_ntstatus;
#define WN_STATUS_SUCCESS            0x00000000u
#define WN_STATUS_INVALID_PARAMETER  0xC000000Du
#define WN_STATUS_UNHANDLED_EXCEPTION 0xC000026Bu

/* Common Win32 error codes (GetLastError space). */
#define WN_ERR_SUCCESS               0
#define WN_ERR_FILE_NOT_FOUND        2
#define WN_ERR_PATH_NOT_FOUND        3
#define WN_ERR_ACCESS_DENIED         5
#define WN_ERR_INVALID_HANDLE        6
#define WN_ERR_NOT_ENOUGH_MEMORY     8
#define WN_ERR_BAD_ENVIRONMENT       10
#define WN_ERR_INVALID_ACCESS        12
#define WN_ERR_NO_MORE_FILES         18
#define WN_ERR_BAD_FORMAT            11
#define WN_ERR_WRITE_FAULT           29
#define WN_ERR_READ_FAULT            30
#define WN_ERR_GEN_FAILURE           31
#define WN_ERR_SHARING_VIOLATION     32
#define WN_ERR_HANDLE_EOF            38
#define WN_ERR_NOT_SUPPORTED         50
#define WN_ERR_DISK_FULL             112
#define WN_ERR_INVALID_PARAMETER     87
#define WN_ERR_BROKEN_PIPE           109
#define WN_ERR_CALL_NOT_IMPLEMENTED  120
#define WN_ERR_INSUFFICIENT_BUFFER   122
#define WN_ERR_ALREADY_EXISTS        183
#define WN_ERR_FILE_EXISTS           80
#define WN_ERR_INVALID_NAME          123
#define WN_ERR_MOD_NOT_FOUND         126
#define WN_ERR_PROC_NOT_FOUND        127
#define WN_ERR_DIR_NOT_EMPTY         145
#define WN_ERR_MORE_DATA             234
#define WN_ERR_NO_MORE_ITEMS         259
#define WN_ERR_NOT_OWNER             288
#define WN_ERR_ENVVAR_NOT_FOUND      203

/* File attributes. */
#define WN_FILE_ATTRIBUTE_READONLY   0x00000001
#define WN_FILE_ATTRIBUTE_HIDDEN     0x00000002
#define WN_FILE_ATTRIBUTE_DIRECTORY  0x00000010
#define WN_FILE_ATTRIBUTE_NORMAL     0x00000080
#define WN_FILE_ATTRIBUTE_TEMPORARY  0x00000100

/* Generic handle values guests pass around. */
#define WN_INVALID_HANDLE_VALUE      ((wn_handle)(intptr_t)-1)
#define WN_CURRENT_PROCESS           ((wn_handle)(intptr_t)-1)
#define WN_CURRENT_THREAD            ((wn_handle)(intptr_t)-2)

/* Representation of a UTF-16 string in guest-readable memory. */
typedef struct {
    wn_word length;            /* bytes, not chars */
    wn_word maximum_length;    /* bytes */
    wn_pwstr buffer;
} wn_unicode_string;

/* FILETIME: 100ns intervals since 1601-01-01 UTC. */
typedef struct { wn_dword lo; wn_dword hi; } wn_filetime;

/* 1601->1970 offset in 100ns units. */
#define WN_FILETIME_UNIX_OFFSET 116444736000000000ULL

#endif /* WN_TYPES_H */
