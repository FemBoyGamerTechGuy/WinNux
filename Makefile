# WinNux — build
# Raw C11, no build systems other than this Makefile and POSIX sh.
# Link-time dependencies: libc, libm, libpthread, libdl only (see DEPENDENCIES.md).

CC      ?= cc
CSTD    := -std=c11
WARN    := -Wall -Wextra -Wshadow -Wpointer-arith -Wundef -Werror
DEFS    := -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L
OPT     ?= -O2 -g
INC     := -Iinclude

CFLAGS  := $(CSTD) $(WARN) $(DEFS) $(INC) $(OPT) -MMD -MP
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

check32:
	@mkdir -p obj32
ifeq ($(HAVE_M32),no)
	@echo "check32: SKIP - no working -m32 toolchain on this box"
	@echo "  Debian/Ubuntu: apt install gcc-multilib (as root)"
	@echo "  Arch:          pacman -S gcc-multilib lib32-gcc-libs"
else
	@echo "== i386 compile check (no link; dispatch metadata is future work) =="
	@rc=0; for src in $(SRCS); do \
		obj="obj32/$$(echo $$src | sed 's|^src/||; s|\.c$$|.o|; s|/|_|g')"; \
		if ! $(CC) $(CFLAGS) -m32 -c -o $$obj $$src 2>/tmp/check32.err; then \
			echo "FAIL: $$src"; head -12 /tmp/check32.err; rc=1; \
		fi; \
	done; \
	if [ $$rc = 0 ]; then echo "check32: all sources compile under -m32"; \
	else echo "check32: FAILURES above"; fi; exit $$rc
endif
