# WinNux — build
# Raw C11, no build systems other than this Makefile and POSIX sh.
# Link-time dependencies: libc, libm, libpthread, libdl only (see DEPENDENCIES.md).

CC      ?= cc
CSTD    := -std=c11
WARN    := -Wall -Wextra -Wshadow -Wpointer-arith -Wundef -Werror
DEFS    := -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L
OPT     ?= -O2 -g
INC     := -Iinclude

CFLAGS  := $(CSTD) $(WARN) $(DEFS) $(INC) $(OPT) -fno-pic -no-pie -MMD -MP
LDLIBS  := -lpthread -ldl -lm

BIN     := bin
OBJ     := obj
TARGET  := $(BIN)/winnux

SRCS    := $(sort $(wildcard src/*.c src/common/*.c src/pe/*.c src/loader/*.c \
            src/win/*.c src/dlls/*.c src/backends/*.c src/gfx/*.c src/tools/*.c))
OBJS    := $(patsubst src/%.c,$(OBJ)/%.o,$(SRCS))

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

-include $(OBJ)/*.d $(OBJ)/*/*.d

$(BIN) $(OBJ):
	mkdir -p $@

# Debug build with sanitizers (kept in separate dirs so both can coexist).
DBGOBJ  := obj-dbg
DBGTGT  := $(BIN)/winnux-dbg
DBGOBJS := $(patsubst src/%.c,$(DBGOBJ)/%.o,$(SRCS))

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

M32_MODE := $(strip $(m32_probe))
ifeq ($(M32_MODE),native)
M32FLAGS := -m32 -no-pie -fno-pic -static-libgcc
M32POST  :=
else ifeq ($(M32_MODE),sysroot)
# With -m32, gcc swaps the multiarch include dir (/usr/include/x86_64-linux-gnu
# -> /usr/include/i386-linux-gnu), but glibc's bi-arch bits/ headers live in the
# amd64 dir (wordsize.h dispatches on __x86_64__), so re-add it to the chain.
# GCC32DIR auto-detects the gcc version dir holding 32/crtbegin.o.
GCC32DIR := $(patsubst %/32/,%,$(dir $(firstword $(wildcard $(M32_SYSROOT)/usr/lib/gcc/x86_64-linux-gnu/*/32/crtbegin.o))))
M32FLAGS := -m32 -no-pie -fno-pic -static-libgcc \
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

.PHONY: winnux32 check32

winnux32: $(TARGET32)

$(TARGET32): $(OBJS32) | $(BIN)
ifneq ($(M32_MODE),none)
	$(CC) $(CSTD) $(WARN) $(DEFS) $(INC) $(OPT) $(M32FLAGS) -o $@ $(OBJS32) $(LDLIBS)
	@echo "built $(TARGET32) ($(M32_MODE) toolchain)"
else
	@echo "winnux32: SKIP - no -m32 toolchain (native or $(M32_SYSROOT))"
	@echo "  Arch:   enable [multilib] in /etc/pacman.conf, then: pacman -S gcc-multilib lib32-gcc-libs"
	@echo "  Debian: apt install gcc-multilib (as root)"
endif

$(OBJ32)/%.o: src/%.c | $(OBJ32)
ifneq ($(M32_MODE),none)
	@mkdir -p $(dir $@)
	$(CC) $(CSTD) $(WARN) $(DEFS) $(INC) $(OPT) $(M32FLAGS) -c -o $@ $<
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
