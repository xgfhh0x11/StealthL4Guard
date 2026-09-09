# StealthL4Guard — eBPF build glue.
#
# Two build modes:
#
#   make                 — legacy: compile against /lib/modules/$(uname -r)/build.
#                          Produces a non-portable .o that may fail to load on
#                          kernels other than the build host. Default for now.
#
#   make USE_CORE=1      — CO-RE-ready: compile against a generated vmlinux.h
#                          extracted from /sys/kernel/btf/vmlinux. Produces a
#                          .o that is theoretically loadable on any modern
#                          kernel with BTF. Requires bpftool to be installed.
#                          See CORE_MIGRATION.md for the per-program porting
#                          checklist.
#
# Output: two .o files (xdp_l4_guard.o, tc_l4_guard.o) loadable via
# `ip link set ... xdp obj ...` and `tc filter add ... bpf obj ...`.

CLANG       ?= clang
BPFTOOL     ?= bpftool
ARCH        := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
KDIR        ?= /lib/modules/$(shell uname -r)/build

# Legacy include set — kernel headers of the current host.
LEGACY_INCLUDES := \
    -I$(KDIR)/include \
    -I$(KDIR)/include/uapi \
    -I$(KDIR)/arch/$(ARCH)/include \
    -I$(KDIR)/arch/$(ARCH)/include/uapi \
    -I/usr/include

# CO-RE include set — vmlinux.h supplies kernel types via BTF, no
# /lib/modules dependency.
CORE_INCLUDES := \
    -I. \
    -I/usr/include

ifeq ($(USE_CORE),1)
    INCLUDES := $(CORE_INCLUDES)
    EXTRA_DEFS := -DUSE_CORE=1
    DEPS := vmlinux.h
else
    INCLUDES := $(LEGACY_INCLUDES)
    EXTRA_DEFS :=
    DEPS :=
endif

CFLAGS := \
    -O2 -g -Wall -Wextra \
    -target bpf \
    -D__TARGET_ARCH_$(ARCH) \
    $(EXTRA_DEFS) \
    -fno-stack-protector \
    -fno-asynchronous-unwind-tables \
    $(INCLUDES)

PROGS := xdp_l4_guard.o tc_l4_guard.o

.PHONY: all clean check vmlinux

all: $(PROGS)

# vmlinux.h generation — required for CO-RE builds. Falls back to a
# helpful error if /sys/kernel/btf/vmlinux is not present (the host
# kernel was built without CONFIG_DEBUG_INFO_BTF).
vmlinux.h:
	@if [ ! -r /sys/kernel/btf/vmlinux ]; then \
	    echo "ERROR: /sys/kernel/btf/vmlinux not readable."; \
	    echo "       The running kernel must be built with CONFIG_DEBUG_INFO_BTF=y"; \
	    echo "       and the BTF blob mounted at /sys/kernel/btf/vmlinux."; \
	    exit 1; \
	fi
	@command -v $(BPFTOOL) >/dev/null 2>&1 || \
	    (echo "ERROR: bpftool not in PATH. apt install linux-tools-common."; exit 1)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# Convenience alias to regenerate vmlinux.h.
vmlinux: vmlinux.h

%.o: %.c $(DEPS)
	$(CLANG) $(CFLAGS) -c $< -o $@

# `check` does not load the program — just confirms it compiles and
# the verifier-relevant inline checks survive optimization.
check: $(PROGS)
	@for p in $(PROGS); do \
	    echo "==> $$p"; \
	    file $$p; \
	    test -s $$p || (echo "EMPTY: $$p" && exit 1); \
	done

clean:
	rm -f $(PROGS) *.ll vmlinux.h
