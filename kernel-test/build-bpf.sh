#!/usr/bin/env bash
# kernel-test/build-bpf.sh
#
# Builds bpf/xdp_l4_guard.o and bpf/tc_l4_guard.o from the sources in bpf/.
# No root required. No network interfaces are touched.
#
# Strategy: try the repo's own bpf/Makefile first (as it is the canonical
# build path). If that fails — which it will on a bare WSL2 install, see
# NOTES below — fall back to a direct clang invocation with include paths
# and flags that are known to work on Ubuntu 22.04 / WSL2 (verified against
# clang 14.0.0, libbpf-dev 0.5.0, kernel 6.18 microsoft-standard-WSL2).
#
# NOTES (found while building this harness, all confirmed on this host):
#   1. bpf/Makefile's default (legacy) mode compiles against
#      /lib/modules/$(uname -r)/build, which does not exist under WSL2
#      (no matching linux-headers package for the WSL2 kernel) and, even
#      on a host where it does exist, shadows the plain UAPI headers with
#      kernel-internal ones that -target bpf cannot compile (upstream repo
#      review calls this out as bug B17). We do not patch the Makefile;
#      we just fail over to a direct clang call instead.
#   2. The plain `-I/usr/include` include set additionally needs
#      `-I/usr/include/<multiarch-triplet>` for <asm/types.h>, or
#      <linux/bpf.h> fails to resolve <linux/types.h>.
#   3. account_v4()/tc_l4_guard.c use __sync_fetch_and_add() and read its
#      return value (the per-CPU race fix referenced in the review). LLVM's
#      BPF backend only supports atomic-fetch-with-return ("XADD-with-
#      return") on BPF ISA v3+; without `-mcpu=v3` clang 14 crashes with
#      "Invalid usage of the XADD return value" while compiling
#      xdp_l4_guard.c. `-mcpu=v3` fixes it. (v3 requires a 5.1+ kernel to
#      *run*, which WSL2 6.18 and any current distro satisfy.)
#   4. bpf/tc_l4_guard.c uses IPPROTO_TCP/IPPROTO_UDP but does not include
#      <linux/in.h> (unlike xdp_l4_guard.c, which does). On this system's
#      header set that leaves the macros undefined and the file fails to
#      compile. We do not edit the reviewed source file; we force the
#      header in via `-include linux/in.h` on the compiler command line
#      instead. This is a real repo bug worth fixing upstream — flagged
#      here, not silently patched.
#
# All four points above were hit and resolved while validating this script;
# the resulting objects were built and inspected (`llvm-objdump -h/-t`) on
# this host before this file was committed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BPF_DIR="$REPO_ROOT/bpf"

APT_LINE="sudo apt-get update && sudo apt-get install -y clang llvm libbpf-dev linux-libc-dev linux-tools-common linux-tools-generic iproute2"

need() { command -v "$1" >/dev/null 2>&1; }

missing=0
for tool in clang llvm-objdump; do
    if ! need "$tool"; then
        echo "MISSING TOOL: $tool" >&2
        missing=1
    fi
done

if [ "$missing" -ne 0 ]; then
    echo "" >&2
    echo "Required build tools are missing. Install them with:" >&2
    echo "  $APT_LINE" >&2
    exit 1
fi

if ! need bpftool; then
    echo "WARNING: bpftool not found in PATH." >&2
    echo "         Build will proceed, but kernel-test/verify.sh needs it." >&2
    echo "         Install with: $APT_LINE" >&2
fi

if [ ! -d "$BPF_DIR" ]; then
    echo "ERROR: expected $BPF_DIR to exist (repo layout changed?)" >&2
    exit 1
fi

MULTIARCH="$(gcc -dumpmachine 2>/dev/null || echo x86_64-linux-gnu)"
ARCH="$(uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')"

build_direct() {
    local src="$1" obj="$2"
    clang -O2 -g -Wall -Wextra \
        -target bpf -mcpu=v3 \
        -D__TARGET_ARCH_"${ARCH}" \
        -include linux/in.h \
        -I/usr/include -I/usr/include/"${MULTIARCH}" \
        -fno-stack-protector -fno-asynchronous-unwind-tables \
        -c "$src" -o "$obj"
}

cd "$BPF_DIR"

echo "== [1/2] trying repo Makefile (bpf/Makefile) =="
MAKE_LOG="$(mktemp)"
if make -C "$BPF_DIR" clean >/dev/null 2>&1 && make -C "$BPF_DIR" all >"$MAKE_LOG" 2>&1; then
    echo "Makefile build succeeded."
    rm -f "$MAKE_LOG"
else
    echo "Repo Makefile build failed (expected on a bare WSL2 host — see NOTES"
    echo "at the top of this script). Last output:"
    sed 's/^/    /' "$MAKE_LOG" | tail -20
    rm -f "$MAKE_LOG"
    echo
    echo "== [2/2] falling back to direct clang build =="
    build_direct xdp_l4_guard.c xdp_l4_guard.o
    build_direct tc_l4_guard.c tc_l4_guard.o
fi

fail=0
for f in xdp_l4_guard.o tc_l4_guard.o; do
    if [ ! -s "$BPF_DIR/$f" ]; then
        echo "BUILD FAILED: $BPF_DIR/$f was not produced (or is empty)." >&2
        fail=1
    fi
done
[ "$fail" -eq 0 ] || exit 1

echo
echo "Built objects:"
ls -la "$BPF_DIR/xdp_l4_guard.o" "$BPF_DIR/tc_l4_guard.o"

echo
echo "== xdp_l4_guard.o: expected section 'xdp_guard', maps, license (global symbols) =="
llvm-objdump -t "$BPF_DIR/xdp_l4_guard.o" | grep -E '^[0-9a-f]+ g ' || true

echo
echo "== tc_l4_guard.o: expected section 'tc_ingress', maps, license (global symbols) =="
llvm-objdump -t "$BPF_DIR/tc_l4_guard.o" | grep -E '^[0-9a-f]+ g ' || true

echo
echo "Build OK. Next: kernel-test/netns-up.sh, then kernel-test/load.sh (dry-run by default)."
