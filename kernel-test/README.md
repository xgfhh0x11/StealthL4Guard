# kernel-test/ — dynamic BPF test harness for StealthL4Guard

This directory runs the repo's two eBPF programs (`bpf/xdp_l4_guard.c`,
`bpf/tc_l4_guard.c`) against real packets, inside an **isolated network
namespace**, on WSL2 (Ubuntu-22.04, kernel 6.18 `microsoft-standard-WSL2`,
BTF present at `/sys/kernel/btf/vmlinux`).

Per the repo review (`review_StealthL4Guard.md`, finding G3): as of this
writing **nothing has ever executed a BPF instruction from this repo**.
Everything downstream (`nftables.conf`, `haproxy.cfg`) is out of scope
here — this harness only builds and exercises the two BPF programs.

## SAFETY — read this before running anything

- **Every script in this directory defaults to touching only a private
  veth pair inside a dedicated network namespace (`l4guard_test`), never
  a real interface.** `load.sh` additionally **defaults to dry-run** —
  it only prints the commands it would run.
- **Never attach these programs to a real NIC or management interface.**
  `xdp_l4_guard.c`'s header comment is explicit about its design: *"No
  feedback. No RST. No ICMP. The attacker sees packet loss."* — the same
  is true of a *misconfigured or over-tight* attach on the wrong
  interface: it fails silently, from the outside indistinguishable from
  a hung box or a dead link. If you attach this to the interface you're
  using to SSH into the host, you can lock yourself out with no error
  message.
- `load.sh` requires `--arm` to attach anything for real, and refuses
  any interface other than the isolated test veth (`veth-l4g-ns`) unless
  you pass `--host-iface <name>` explicitly. If that name isn't one of
  this harness's own veths, it additionally requires
  `I_UNDERSTAND_THIS_MAY_BREAK_HOST_NETWORKING=yes` in the environment.
  There is no supported reason to use `--host-iface` on this project —
  it exists only as a documented, deliberately-noisy escape hatch.
- Always run `kernel-test/teardown.sh` when you're done, or before
  re-running `netns-up.sh`/`load.sh` after an interrupted session.
- Known correctness issue relevant to testing (review finding B5):
  `tc_l4_guard.c`'s `compute_mark()` permanently marks a flow KILL once
  it exceeds 5000 packets, with no time-window decay. A long-lived test
  flow (e.g. a big `nc` transfer, or a loop of many pings) **will**
  eventually get marked, by design of the current code, not because of
  a bug in this harness. Keep test traffic bursts modest, or expect and
  note the eventual mark.

## Invoking from Windows

All scripts are bash and must run under WSL2, from the repo root (paths
inside the scripts are self-locating, but invoke them from anywhere and
they'll resolve `kernel-test/..` correctly regardless):

```powershell
wsl -d Ubuntu-22.04 -- bash kernel-test/build-bpf.sh
wsl -d Ubuntu-22.04 -- bash kernel-test/netns-up.sh
wsl -d Ubuntu-22.04 -- bash kernel-test/load.sh              # dry-run, prints commands only
wsl -d Ubuntu-22.04 -- bash kernel-test/load.sh --arm         # actually attaches, to the test veth only
wsl -d Ubuntu-22.04 -- bash kernel-test/verify.sh
wsl -d Ubuntu-22.04 -- bash kernel-test/teardown.sh
```

`netns-up.sh`, `load.sh --arm`, `verify.sh`, and `teardown.sh` all need
root for network namespace / `tc` / `ip link xdp` operations and will
call `sudo` internally — run them from an **interactive** WSL shell
(`wsl -d Ubuntu-22.04`, then `bash kernel-test/...`) the first time so
you can enter your password; `sudo -n` (passwordless) was not enabled on
this host as of writing.

## Toolchain prerequisites

Confirmed present on this host already (Ubuntu 22.04.5 LTS under WSL2):
`clang` 14.0.0, `gcc`, `llvm-strip`/`llvm-objdump`, `libbpf-dev` 1:0.5.0,
`bpftool` (via `linux-tools-common`), `ip`/`tc` (iproute2 5.15.0), `nc`
(netcat-openbsd), `ping` (iputils). If any of these are missing on a
fresh box, install with:

```bash
sudo apt-get update
sudo apt-get install -y \
    clang llvm libbpf-dev linux-libc-dev \
    linux-tools-common linux-tools-generic \
    iproute2 nftables netcat-openbsd iputils-ping
```

`build-bpf.sh` detects a missing `clang`/`llvm-objdump` itself and
prints this exact line before exiting non-zero, rather than failing
obscurely mid-build. A missing `bpftool` degrades gracefully (build
still works; `verify.sh` needs it and will say so).

`linux-tools-generic`'s `bpftool` prints a `WARNING: bpftool not found
for kernel <ver>-microsoft` banner on WSL2 because there's no
kernel-version-matched package for Microsoft's custom kernel build —
this is cosmetic; the generic bpftool binary still works fine for
`prog show`/`map dump` (confirmed on this host).

## Build reality (found and fixed while writing `build-bpf.sh`)

`bpf/Makefile`'s default target does **not** build on a bare WSL2 host
(confirmed: `/lib/modules/<kernel>/build` doesn't exist here, and even
where it does, the review's finding B17 applies — kernel-internal
headers shadow the UAPI ones clang needs for `-target bpf`).
`build-bpf.sh` tries the Makefile first, then falls back automatically
to a direct `clang` invocation, which was tested end-to-end on this
host and successfully produced both objects with three fixes beyond
what the Makefile does:

1. `-I/usr/include/$(gcc -dumpmachine)` in addition to `-I/usr/include`,
   for `<asm/types.h>`.
2. `-mcpu=v3` — `tc_l4_guard.c`'s (and, transitively via the same
   helper, `xdp_l4_guard.c`'s) use of `__sync_fetch_and_add()`'s return
   value needs BPF ISA v3; without it clang 14's BPF backend crashes
   compiling `xdp_l4_guard.c` with `Invalid usage of the XADD return
   value`. This is the atomic per-CPU-race fix mentioned in the task
   brief and the repo review (B8).
3. `-include linux/in.h` when compiling `tc_l4_guard.c` — that file uses
   `IPPROTO_TCP`/`IPPROTO_UDP` but (unlike `xdp_l4_guard.c`) does not
   include `<linux/in.h>` itself, so on this header set those macros are
   undefined. This is a genuine bug in the repo source, not fixed here
   (the `.c` files are left untouched) — worked around only at the
   compiler-invocation level, and called out again below.

None of these are hidden: `build-bpf.sh` prints its reasoning inline,
and this README documents it so a maintainer can decide whether to fix
`bpf/Makefile` / add `#include <linux/in.h>` to `tc_l4_guard.c` upstream.

## Object / section / map names wired into these scripts

| Source | Object | `SEC()` name | Maps |
|---|---|---|---|
| `bpf/xdp_l4_guard.c` | `bpf/xdp_l4_guard.o` | `xdp_guard` (func `xdp_l4_guard`) | `blocked_prefixes_v4` (LPM_TRIE), `ipv4_rates` (LRU_HASH), `ipv6_rates` (LRU_HASH) |
| `bpf/tc_l4_guard.c` | `bpf/tc_l4_guard.o` | `tc_ingress` (func `tc_l4_guard`) | `flow_table` (LRU_HASH) |

These are the legacy-style section names the repo review (B14) flags as
incompatible with libbpf's type-inference in `bpftool prog load` /
skeletons — but `ip link set ... xdp[generic] object ... section ...`
and `tc filter ... bpf ... obj ... sec ...` (what `load.sh` uses) set the
program type explicitly and work fine with them, confirmed against the
built objects on this host.

## Order of operations

1. `build-bpf.sh` — compiles `bpf/xdp_l4_guard.o` / `bpf/tc_l4_guard.o`.
   No root, touches nothing but files under `bpf/`.
2. `netns-up.sh` — creates netns `l4guard_test` with veth pair
   `veth-l4g-h` (host side, `10.200.1.1/24`) / `veth-l4g-ns` (namespace
   side, `10.200.1.2/24`). Idempotent.
3. `load.sh` — dry-run by default; `--arm` to actually attach XDP
   (`xdpgeneric`, veth doesn't reliably support native XDP offload) and
   TC (`clsact` + `bpf da`) on `veth-l4g-ns`, inside the namespace.
4. `verify.sh` — `bpftool prog show` / `bpftool map dump` on all four
   maps, generates ICMP/TCP/UDP test traffic into the namespace with
   `ping`/`nc`, and re-dumps the maps so you can see counters move.
   **There is no `bpf_printk` or stats map in this codebase (review
   G5)** — map deltas and observed packet loss are the only signal
   available; `verify.sh` says this again inline before you read its
   output.
5. `teardown.sh` — detaches everything and deletes the netns/veth pair.
   Idempotent; safe after a partial/interrupted run.

## What this harness does *not* do

- It does not touch `config/nftables.conf` or `config/haproxy.cfg` — the
  task scope here is the two BPF programs only.
- It does not fix any of the correctness issues found in review (probes,
  IPv6 extension headers, IP-options evasion in TC, the permanent-KILL
  flow aging gap, etc.) — it only builds and exercises the code as it
  stands, safely, so those issues can be *observed* under real traffic
  rather than fixed blind.
- It does not attempt SYN-flood / XMAS / fragment-evasion traffic
  generation (scapy/trafgen) — `verify.sh` is a smoke test (does the
  program load and touch real packets at all), not the fuller adversarial
  test harness described in the review's §5 ("kernel-test readiness").
  That is a reasonable next step once this smoke test is green.
