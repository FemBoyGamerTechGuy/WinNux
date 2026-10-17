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
            src/win/*.c src/dlls/*.c src/backends/*.c src/gfx/*.c))
OBJS    := $(patsubst src/%.c,$(OBJ)/%.o,$(SRCS))

# Cross toolchain used to build Windows test binaries (tests only, never linked
# into the product). Discovered via MXGCC env or PATH.
MXGCC   ?= x86_64-w64-mingw32-gcc

.PHONY: all clean debug check test fuzz

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

clean:
	rm -rf $(BIN) $(OBJ) $(DBGOBJ)
