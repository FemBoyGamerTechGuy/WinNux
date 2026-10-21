# WinNux — build
# Raw C11, no build systems other than this Makefile and POSIX sh.
# Link-time dependencies: libc, libm, libpthread, libdl only (see DEPENDENCIES.md).

CC      ?= cc
CSTD    := -std=c11
WARN    := -Wall -Wextra -Wshadow -Wpointer-arith -Wundef -Werror
DEFS    := -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L
OPT     ?= -O2 -g
INC     := -Iinclude

CFLAGS  := $(CSTD) $(WARN) $(DEFS) $(INC) $(OPT) \
           -fstack-protector-strong -MMD -MP
LDLIBS  := -lpthread -ldl -lm

BIN     := bin
OBJ     := obj
TARGET  := $(BIN)/winnux

SRCS    := $(sort $(wildcard src/*.c src/common/*.c src/pe/*.c src/loader/*.c \
            src/win/*.c src/dlls/*.c src/backends/*.c src/gfx/*.c src/tools/*.c))
OBJS    := $(patsubst src/%.c,$(OBJ)/%.o,$(SRCS)) $(OBJ)/win/wow64_gates.o

# Cross toolchain used to build Windows test binaries (tests only, never linked
# into the product). Discovered via MXGCC env or PATH.
MXGCC   ?= x86_64-w64-mingw32-gcc

# Install: put `winnux` on the user's PATH. Default is ~/.local/bin (no
# root needed; on most distro default PATHs). Override: make install PREFIX=/usr/local
INSTALL_PREFIX ?= $(HOME)/.local

.PHONY: all clean debug check test fuzz install uninstall

all: $(TARGET)

$(TARGET): $(OBJS) | $(BIN)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDLIBS)

$(OBJ)/%.o: src/%.c | $(OBJ)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<


$(OBJ)/win/wow64_gates.o: src/win/wow64_gates.S | $(OBJ)
	@mkdir -p $(dir $@)
	$(CC) -c -o $@ $<

-include $(OBJ)/*.d $(OBJ)/*/*.d obj32/*.d obj32/*/*.d


# Signal-context code runs with the GUEST %fs state (base 0 in compat mode);
# a stack-canary prologue (fs:0x28 read) would fault before the wow64 hook
# can restore the host FS base. Found via core-dump forensics (d69a017-era).
$(OBJ)/win/wow64.o $(OBJ)/win/seh.o $(DBGOBJ)/win/wow64.o $(DBGOBJ)/win/seh.o: CFLAGS += -fno-stack-protector
# Same rationale on the i386 build (signal-context code under guest %fs).
obj32/win/wow64.o obj32/win/seh.o: CFLAGS += -fno-stack-protector

$(BIN) $(OBJ):
	mkdir -p $@

# Debug build with sanitizers (kept in separate dirs so both can coexist).
DBGOBJ  := obj-dbg
DBGTGT  := $(BIN)/winnux-dbg
DBGOBJS := $(patsubst src/%.c,$(DBGOBJ)/%.o,$(SRCS)) $(DBGOBJ)/win/wow64_gates.o


$(DBGOBJ)/win/wow64_gates.o: src/win/wow64_gates.S | $(DBGOBJ)
	@mkdir -p $(dir $@)
	$(CC) -c -o $@ $<


# Signal-context files: no stack protector in ANY build (canary fs:0x28
# reads fault when handlers are entered from compat mode, FS base 0).
$(DBGOBJ)/win/wow64.o: src/win/wow64.c
	@mkdir -p $(dir $@)
	$(CC) $(CSTD) $(WARN) $(DEFS) $(INC) -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -fno-stack-protector -c -o $@ $<

$(DBGOBJ)/win/seh.o: src/win/seh.c
	@mkdir -p $(dir $@)
	$(CC) $(CSTD) $(WARN) $(DEFS) $(INC) -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -fno-stack-protector -c -o $@ $<

debug: $(DBGTGT)

$(DBGTGT): $(DBGOBJS) | $(BIN)
	$(CC) $(CSTD) $(WARN) $(DEFS) $(INC) -O1 -g -fsanitize=address,undefined \
		-fno-omit-frame-pointer -o $@ $(DBGOBJS) $(LDLIBS)

$(DBGOBJ)/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CSTD) $(WARN) $(DEFS) $(INC) -O1 -g -fsanitize=address,undefined \
		-fno-omit-frame-pointer -c -o $@ $<

# Test suite: builds test .exe files with the mingw cross compiler when
# available, runs them under bin/winnux and records pass/fail.
test check: $(TARGET)
	sh tests/run_tests.sh

# PE-loader fuzzing (uses the sanitized debug build).
fuzz: $(DBGTGT)
	sh tests/fuzz/fuzz.sh

install: $(TARGET)
	mkdir -p $(INSTALL_PREFIX)/bin
	install -m 755 $(TARGET) $(INSTALL_PREFIX)/bin/winnux
	@echo "installed: $(INSTALL_PREFIX)/bin/winnux"
	@case ":$$PATH:" in *":$(INSTALL_PREFIX)/bin:"*) \
		echo "on PATH: yes";; \
		*) echo "NOTE: $(INSTALL_PREFIX)/bin is not on your PATH - add it:"; \
		echo "  export PATH=\"$$PATH:$(INSTALL_PREFIX)/bin\"  # in ~/.bashrc";; \
	esac

uninstall:
	rm -f $(INSTALL_PREFIX)/bin/winnux

clean:
	rm -rf $(BIN) $(OBJ) $(DBGOBJ)

# --- 32-bit groundwork (compile-only probe) -------------------------------------
# Compiles every translation unit with -m32 (i386) WITHOUT linking: keeps the
# source 32-bit clean (pointer sizes, struct overlays, static asserts). Full
# WoW64 needs per-export stdcall/cdecl dispatch metadata + i386 TEB/PEB
# layouts — see STATUS.md "32-bit".
HAVE_M32 := $(shell echo 'int winnux_probe;' | $(CC) -m32 -x c - -o /dev/null >/dev/null 2>&1 && echo yes || echo no)


# --- 32-bit (i386) loader build --------------------------------------------
# winnux32 is the i386 build of the same runtime: `winnux run app.exe` re-execs
# it for PE32 (i386) images (Wine's wine/wine64 split, inverted).
# Toolchain discovery: native -m32 first (Arch/Debian with gcc-multilib);
# else a local glibc32 sysroot (WINNUX_M32_SYSROOT, e.g. our dev box's
# toolchain/root32) with patched ld scripts + lib32gcc-14-dev crt files.
M32_SYSROOT ?= /home/z/my-project/toolchain/root32
OBJ32   := obj32
TARGET32 := $(BIN)/winnux32

define m32_probe
$(shell printf 'int main(){return 0;}' > /tmp/w32p.c; \
  if $(CC) -m32 -no-pie -static-libgcc /tmp/w32p.c -o /tmp/w32p 2>/dev/null; then \
    echo native; \
  elif [ -d "$(M32_SYSROOT)/usr/lib32" ]; then \
    echo sysroot; \
  else echo none; fi)
endef

# Guest->host stack alignment contract (LuaForWindows GUI crash, 2026-10-20):
# i386 WinNux builtins are stdcall C functions wired DIRECTLY into the guest
# IAT, so they are entered from guest code with only the Win32 4-byte ESP
# alignment (Delphi/Inno and other i386 compilers do NOT keep ESP 16-byte
# aligned). Host libs built by any modern distro (libX11, libc, ...) assume
# GCC's -mpreferred-stack-boundary=4 chain: the first `movaps` on a stack
# slot (e.g. libX11 _XSend) takes a #GP when our wrapper passes the guest's
# misaligned ESP through -> SIGSEGV si_addr=NULL (no CR2 for #GP).
#
# LESSON (verified on gcc-14 -m32): `-mstackrealign` alone is NOT enough.
# It only inserts `and $-16,%esp` in functions that THEMSELVES have 16-byte
# aligned stack objects/SSE spills (12 of ~1700 in this tree). A plain chain
# (u32_CreateWindowExA -> x11_win_create -> XSetWMProtocols -> _XSend) has
# no such function, so the guest's 4-byte ESP propagated into libX11 and the
# exact same crash survived the earlier "fix".
#
# `-mincoming-stack-boundary=2` is the real mechanism: every function then
# ASSUMES only 4-byte incoming alignment, and every function that makes an
# outgoing call (i.e. every link of any guest->...->host-lib chain) realigns
# its own frame at entry. The first host builtin the guest touches realigns,
# and everything below it - our code AND libX11/libc - runs 16-byte aligned.
# Verified: varargs + 16-aligned struct copies correct under qemu-i386;
# export prologues checked in bin/winnux32 (u32_CreateWindowExA et al.).
# -msse2 pins SSE codegen on conservative toolchains too (Debian -m32 =
# i586 baseline) so this bug class can't silently diverge by build host;
# every x86-64 CPU has SSE2 and qemu-i386 emulates it.
M32_MODE := $(strip $(m32_probe))
M32ALIGN := -msse2 -mstackrealign -mpreferred-stack-boundary=4 -mincoming-stack-boundary=2
ifeq ($(M32_MODE),native)
M32FLAGS := -m32 -no-pie -fno-pic -static-libgcc $(M32ALIGN)
M32POST  :=
else ifeq ($(M32_MODE),sysroot)
# With -m32, gcc swaps the multiarch include dir (/usr/include/x86_64-linux-gnu
# -> /usr/include/i386-linux-gnu), but glibc's bi-arch bits/ headers live in the
# amd64 dir (wordsize.h dispatches on __x86_64__), so re-add it to the chain.
# GCC32DIR auto-detects the gcc version dir holding 32/crtbegin.o.
GCC32DIR := $(patsubst %/32/,%,$(dir $(firstword $(wildcard $(M32_SYSROOT)/usr/lib/gcc/x86_64-linux-gnu/*/32/crtbegin.o))))
M32FLAGS := -m32 --sysroot=$(M32_SYSROOT) -no-pie -fno-pic -static-libgcc $(M32ALIGN) \
  -isystem $(M32_SYSROOT)/usr/include \
  -isystem $(M32_SYSROOT)/usr/include/i386-linux-gnu \
  -isystem /usr/include/x86_64-linux-gnu \
  -B$(M32_SYSROOT)/usr/lib32/ \
  -B$(GCC32DIR)/ \
  -L$(M32_SYSROOT)/usr/lib32
M32POST  :=
else
M32FLAGS :=
endif

# obj32 dir rule: without it, make rejects the obj32/%.o pattern entirely
# ("No rule to make target 'obj32/...'", order-only prereq unsatisfiable).
$(OBJ32):
	mkdir -p $@

OBJS32  := $(patsubst src/%.c,$(OBJ32)/%.o,$(SRCS))

# REAL server-side input (XTEST) regression suite: needs Xvfb + the mingw
# cross toolchain + python-xlib (scripts/dev/xinject.py header explains).
e2e: $(TARGET32)
	@if command -v Xvfb >/dev/null 2>&1 && \
	   [ -x /home/z/my-project/toolchain/root/usr/bin/x86_64-w64-mingw32-gcc-posix ]; then \
		sh tests/e2e/run_e2e.sh; \
	else echo "SKIP e2e (no Xvfb or cross toolchain)"; fi

.PHONY: winnux32 check32 e2e

winnux32: $(TARGET32)

# The 32-bit binary's ELF interpreter: hosts WITHOUT the multilib
# runtime (no /lib/ld-linux.so.2 — e.g. a rootless build box) can still
# run winnux32 by embedding the SYSROOT's own loader + an rpath to its
# libc. Hosts that have the system loader keep the standard PT_INTERP.
M32_LOADER_HOST := /lib/ld-linux.so.2
M32_LOADER_SYS  := $(M32_SYSROOT)/usr/lib32/ld-linux.so.2
ifeq ($(M32_MODE),sysroot)
  ifneq ($(wildcard $(M32_LOADER_HOST)),)
    M32LDFLAGS :=
  else ifneq ($(wildcard $(M32_LOADER_SYS)),)
    M32LDFLAGS := -Wl,-dynamic-linker,$(M32_LOADER_SYS) \
                  -Wl,-rpath,$(M32_SYSROOT)/usr/lib32
  else
    M32LDFLAGS :=
  endif
else
  M32LDFLAGS :=
endif

$(TARGET32): $(OBJS32) | $(BIN)
ifneq ($(M32_MODE),none)
	$(CC) $(CSTD) $(WARN) $(DEFS) $(INC) $(OPT) $(M32FLAGS) \
	      -fstack-protector-strong $(M32LDFLAGS) -o $@ $(OBJS32) $(LDLIBS)
	@echo "built $(TARGET32) ($(M32_MODE) toolchain, embedded-loader fallback armed)"
else
	@echo "winnux32: SKIP - no -m32 toolchain (native or $(M32_SYSROOT))"
	@echo "  Arch:   enable [multilib] in /etc/pacman.conf, then: pacman -S gcc-multilib lib32-gcc-libs"
	@echo "  Debian: apt install gcc-multilib (as root)"
endif

$(OBJ32)/%.o: src/%.c | $(OBJ32)
ifneq ($(M32_MODE),none)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(M32FLAGS) -c -o $@ $<
endif
check32:
ifeq ($(M32_MODE),none)
	@echo "check32: SKIP - no -m32 toolchain (native or $(M32_SYSROOT))"
else
	@echo "== i386 compile check (mode: $(M32_MODE)) =="
	@rc=0; for src in $(SRCS); do \
		obj="$(OBJ32)/$$(echo $$src | sed 's|^src/||; s|\.c$$|.o|')"; \
		if ! $(CC) $(CSTD) $(WARN) $(DEFS) $(INC) -O1 $(M32FLAGS) -c -o $$obj $$src 2>/tmp/check32.err; then \
			echo "FAIL: $$src"; head -20 /tmp/check32.err; rc=1; \
		fi; \
	done; \
	if [ $$rc = 0 ]; then echo "check32: all sources compile under -m32"; \
	else echo "check32: FAILURES above"; fi; exit $$rc
endif
