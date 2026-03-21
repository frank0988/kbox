# kbox - Linux kernel as a library, rootless chroot via seccomp-unotify
# Build: make [BUILD=release]
# Test:  make check

CC       ?= gcc
CFLAGS   ?=
LDFLAGS  ?=
BUILD    ?= debug

ARCH ?= $(shell uname -m)

CFLAGS  += -std=gnu11 -D_GNU_SOURCE -Wall -Wextra -Wpedantic -Wshadow
CFLAGS  += -Wno-unused-parameter
CFLAGS  += -Iinclude -Isrc

ifeq ($(BUILD),release)
  CFLAGS  += -O2 -DNDEBUG
else
  CFLAGS  += -O0 -g3 -fsanitize=address,undefined -fno-omit-frame-pointer
  LDFLAGS += -fsanitize=address,undefined
endif

# LKL library
LKL_DIR  ?= lkl-$(ARCH)
LKL_LIB   = $(LKL_DIR)/liblkl.a

LDFLAGS += -L$(LKL_DIR) -L$(LKL_DIR)/lib
LDLIBS   = -llkl -lpthread -ldl -lm -lrt

# Optional: SLIRP networking (set KBOX_HAS_SLIRP=1 to enable)
ifdef KBOX_HAS_SLIRP
  SLIRP_DIR  = externals/minislirp
  SLIRP_HDR  = $(SLIRP_DIR)/src/libslirp.h
  CFLAGS    += -DKBOX_HAS_SLIRP -I$(SLIRP_DIR)/src
  SLIRP_SRCS = $(wildcard $(SLIRP_DIR)/src/*.c)
  SLIRP_OBJS = $(SLIRP_SRCS:.c=.o)
endif

# Optional: Web observatory (set KBOX_HAS_WEB=1 to enable)
ifdef KBOX_HAS_WEB
  CFLAGS    += -DKBOX_HAS_WEB
  WEB_ASSET_SRC = $(SRC_DIR)/web-assets.c
endif

# Source files
SRC_DIR  = src
SRCS     = $(SRC_DIR)/main.c \
           $(SRC_DIR)/cli.c \
           $(SRC_DIR)/syscall-nr.c \
           $(SRC_DIR)/lkl-wrap.c \
           $(SRC_DIR)/fd-table.c \
           $(SRC_DIR)/procmem.c \
           $(SRC_DIR)/path.c \
           $(SRC_DIR)/identity.c \
           $(SRC_DIR)/elf.c \
           $(SRC_DIR)/mount.c \
           $(SRC_DIR)/probe.c \
           $(SRC_DIR)/image.c \
           $(SRC_DIR)/seccomp-bpf.c \
           $(SRC_DIR)/seccomp-notify.c \
           $(SRC_DIR)/shadow-fd.c \
           $(SRC_DIR)/seccomp-dispatch.c \
           $(SRC_DIR)/seccomp-supervisor.c \
           $(SRC_DIR)/net-slirp.c \
           $(SRC_DIR)/web-telemetry.c \
           $(SRC_DIR)/web-events.c \
           $(SRC_DIR)/web-server.c

ifdef KBOX_HAS_WEB
  SRCS    += $(WEB_ASSET_SRC)
endif

ifdef KBOX_HAS_SLIRP
  SRCS    += $(SLIRP_SRCS)
endif

OBJS     = $(SRCS:.c=.o)
TARGET   = kbox

# Unit test files (no LKL dependency)
TEST_DIR   = tests/unit
TEST_SRCS  = $(TEST_DIR)/test-runner.c \
             $(TEST_DIR)/test-fd-table.c \
             $(TEST_DIR)/test-path.c \
             $(TEST_DIR)/test-identity.c \
             $(TEST_DIR)/test-syscall-nr.c \
             $(TEST_DIR)/test-elf.c

# Unit tests link only the pure-computation sources (no LKL)
TEST_SUPPORT_SRCS = $(SRC_DIR)/fd-table.c \
                    $(SRC_DIR)/path.c \
                    $(SRC_DIR)/identity.c \
                    $(SRC_DIR)/syscall-nr.c \
                    $(SRC_DIR)/elf.c

TEST_OBJS    = $(TEST_SRCS:.c=.o) $(TEST_SUPPORT_SRCS:.c=.o)
TEST_TARGET  = tests/unit/test-runner

# Guest test programs (compiled statically, run inside kbox)
GUEST_DIR    = tests/guest
GUEST_SRCS   = $(wildcard $(GUEST_DIR)/*-test.c)
GUEST_BINS   = $(GUEST_SRCS:.c=)

# Stress test programs (compiled statically, run inside kbox)
STRESS_DIR   = tests/stress
STRESS_SRCS  = $(wildcard $(STRESS_DIR)/*.c)
STRESS_BINS  = $(STRESS_SRCS:.c=)

# Rootfs image
ROOTFS       = alpine.ext4

# ---- Top-level targets ----

.PHONY: all clean check check-unit check-integration check-stress guest-bins stress-bins rootfs fetch-lkl fetch-minislirp install-hooks web-assets indent

all: $(TARGET)
ifneq ($(wildcard .git),)
all: | .git/hooks/pre-commit
endif

$(TARGET): $(OBJS) | $(LKL_LIB)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Auto-install git hooks on first build (skipped in worktrees where .git is a file).
.git/hooks/pre-commit: scripts/pre-commit.hook
	@if [ -d .git/hooks ]; then $(MAKE) -s install-hooks; fi

# Auto-fetch LKL if missing
$(LKL_LIB):
	@echo "LKL library not found at $(LKL_DIR). Fetching..."
	./scripts/fetch-lkl.sh $(ARCH)

# Auto-fetch minislirp if missing (shallow clone, no submodule).
# $(wildcard) evaluates at parse time, so if minislirp has not been
# fetched yet SLIRP_SRCS is empty.  Guard: fetch and re-exec make so
# the wildcard picks up the newly-cloned sources.
ifdef KBOX_HAS_SLIRP
# Auto-fetch minislirp if the header is missing and a build target
# was requested (skip for clean/fetch-only goals).
ifneq ($(filter clean,$(MAKECMDGOALS)),clean)
ifeq ($(wildcard $(SLIRP_HDR)),)
$(shell ./scripts/fetch-minislirp.sh >&2)
SLIRP_SRCS = $(wildcard $(SLIRP_DIR)/src/*.c)
SLIRP_OBJS = $(SLIRP_SRCS:.c=.o)
endif
endif

fetch-minislirp:
	./scripts/fetch-minislirp.sh
endif

# ---- Test targets ----

check: check-unit check-integration check-stress

check-unit: $(TEST_TARGET)
	./$(TEST_TARGET)

# Unit tests are built WITHOUT linking LKL.
# We define LKL stubs for functions referenced by test support code.
$(TEST_TARGET): $(TEST_SRCS) $(TEST_SUPPORT_SRCS)
	$(CC) $(CFLAGS) -DKBOX_UNIT_TEST -o $@ $^ $(LDFLAGS)

check-integration: $(TARGET) guest-bins stress-bins $(ROOTFS)
	./scripts/run-tests.sh ./$(TARGET) $(ROOTFS)

check-stress: $(TARGET) stress-bins $(ROOTFS)
	./scripts/run-stress.sh ./$(TARGET) $(ROOTFS) || \
	  echo "(stress test failures are non-blocking -- see TODO.md)"

# ---- Guest / stress binaries (static, no ASAN) ----
# These are cross-compiled on Linux and placed into the rootfs.
# They must be statically linked and cannot use sanitizers.

guest-bins: $(GUEST_BINS)

$(GUEST_DIR)/%-test: $(GUEST_DIR)/%-test.c
	$(CC) -std=gnu11 -Wall -Wextra -O2 -static -o $@ $<

stress-bins: $(STRESS_BINS)

$(STRESS_DIR)/%: $(STRESS_DIR)/%.c
	$(CC) -std=gnu11 -Wall -Wextra -O2 -static -pthread -o $@ $<

# ---- Rootfs ----

rootfs: $(ROOTFS)

$(ROOTFS): scripts/mkrootfs.sh scripts/alpine-sha256.txt $(GUEST_BINS) $(STRESS_BINS)
	ALPINE_ARCH=$(ARCH) ./scripts/mkrootfs.sh

# ---- Utilities ----

# Fetch LKL from nightly release if not cached locally.
# To force re-download: rm -rf lkl-x86_64 && make fetch-lkl
fetch-lkl:
	./scripts/fetch-lkl.sh $(ARCH)

# Install git hooks from scripts/*.hook into .git/hooks/.
# Skips hooks that already exist (preserves user customizations).
install-hooks:
	@for hook in scripts/*.hook; do \
	    name=$$(basename "$$hook" .hook); \
	    if [ ! -e .git/hooks/"$$name" ] && [ ! -L .git/hooks/"$$name" ]; then \
	        ln -s ../../"$$hook" .git/hooks/"$$name"; \
	        echo "Installed $$name hook"; \
	    fi; \
	done

# Generate compiled-in web assets from web/ directory.
# Re-run when any web/ file changes.
ifdef KBOX_HAS_WEB
WEB_SRCS_ALL = $(shell find web -type f \( -name '*.html' -o -name '*.css' -o -name '*.js' -o -name '*.svg' \) 2>/dev/null)
$(WEB_ASSET_SRC): $(WEB_SRCS_ALL) scripts/gen-web-assets.sh
	./scripts/gen-web-assets.sh
web-assets: $(WEB_ASSET_SRC)
endif

# ---- Formatting ----

CLANG_FORMAT := $(shell command -v clang-format-20 2>/dev/null || \
                        command -v clang-format 2>/dev/null)
SHFMT        := shfmt
BLACK        := black

C_SRCS_FMT  := $(wildcard src/*.c src/*.h include/kbox/*.h \
                tests/unit/*.c tests/unit/*.h \
                tests/guest/*.c tests/stress/*.c)
SH_SRCS_FMT := $(wildcard scripts/*.sh)
PY_SRCS_FMT := $(wildcard scripts/gdb/*.py)

indent:
ifeq ($(CLANG_FORMAT),)
	$(error clang-format not found; install clang-format or clang-format-20)
endif
	@$(CLANG_FORMAT) --version | grep -q 'version 20' || \
	  { echo "error: clang-format version 20 required"; exit 1; }
	$(CLANG_FORMAT) -i $(C_SRCS_FMT)
	$(SHFMT) -i 4 -fn -ci -sr -bn -w $(SH_SRCS_FMT)
	$(BLACK) -q $(PY_SRCS_FMT)

clean:
	rm -f $(OBJS) $(TARGET) $(TEST_TARGET) $(TEST_DIR)/*.o
	rm -f src/*.o src/web-assets.c
	rm -f $(GUEST_BINS) $(STRESS_BINS)

# ---- Dependencies ----
# Auto-generate with gcc -MM if needed; keep it simple for now.
$(SRC_DIR)/main.o: include/kbox/cli.h include/kbox/image.h
$(SRC_DIR)/cli.o: include/kbox/cli.h
$(SRC_DIR)/probe.o: include/kbox/probe.h src/seccomp-defs.h
$(SRC_DIR)/image.o: include/kbox/image.h include/kbox/mount.h include/kbox/identity.h include/kbox/probe.h src/lkl-wrap.h src/net.h src/seccomp.h src/shadow-fd.h
$(SRC_DIR)/shadow-fd.o: src/shadow-fd.h src/lkl-wrap.h src/syscall-nr.h
$(SRC_DIR)/seccomp-dispatch.o: src/seccomp.h src/seccomp-defs.h src/fd-table.h src/lkl-wrap.h src/procmem.h include/kbox/path.h include/kbox/identity.h src/shadow-fd.h src/net.h
$(SRC_DIR)/seccomp-supervisor.o: src/seccomp.h src/seccomp-defs.h src/syscall-nr.h
$(SRC_DIR)/seccomp-bpf.o: src/seccomp.h src/seccomp-defs.h src/syscall-nr.h
$(SRC_DIR)/seccomp-notify.o: src/seccomp.h src/seccomp-defs.h
$(SRC_DIR)/net-slirp.o: src/net.h src/lkl-wrap.h src/syscall-nr.h
$(SRC_DIR)/web-telemetry.o: src/web.h src/lkl-wrap.h src/syscall-nr.h
$(SRC_DIR)/web-events.o: src/web.h
$(SRC_DIR)/web-server.o: src/web.h src/fd-table.h src/lkl-wrap.h src/syscall-nr.h
