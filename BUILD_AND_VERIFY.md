# StealthL4Guard — Build & Verification

> *Quality gate for the HBO NL portfolio. This file answers:
> "Is this project buildable, runnable, and behaving as documented?"*

> *Last updated: 2026-05-14 — post P0–P3 fix pass. CO-RE infrastructure ready; per-file port still pending.*

## 1. Build

### 1.1 Primary build path

- **Platform**: Linux only (eBPF requires kernel >= 5.10 with `CONFIG_BPF=y`,
  `CONFIG_BPF_SYSCALL=y`, `CONFIG_XDP_SOCKETS=y`, `CONFIG_NET_CLS_BPF=y`,
  `CONFIG_NF_TABLES=y`). Stock Ubuntu 22.04 / Debian 12 / Fedora 38+ kernels
  ship this configuration.
- **Toolchain**: `clang` >= 11 with the BPF target enabled,
  `llvm`, `libbpf-dev`, kernel headers matching `uname -r`,
  `iproute2` (`ip`, `tc`), `nftables` >= 0.9, `haproxy` >= 2.4.
- **Command** (from repo root):

  ```sh
  cd bpf && make
  ```

  The eBPF Makefile auto-detects architecture (`uname -m`, normalized to
  `x86` / `arm64`) and pulls headers from
  `/lib/modules/$(uname -r)/build` via `KDIR`. Override either with
  environment variables, e.g.:

  ```sh
  make CLANG=clang-15 KDIR=/path/to/kernel/source
  ```

- **Output**:
  - `bpf/xdp_l4_guard.o` — XDP program (section `xdp_guard`), loaded with
    `ip link set dev <iface> xdp obj bpf/xdp_l4_guard.o sec xdp_guard`.
  - `bpf/tc_l4_guard.o` — TC ingress classifier (section `tc_ingress`),
    loaded with `tc filter add dev <iface> ingress bpf da obj bpf/tc_l4_guard.o sec tc_ingress`.
  - `config/nftables.conf` — declarative ruleset, applied with `nft -f`.
  - `config/haproxy.cfg` — TCP-mode L4 frontend, validated with
    `haproxy -c -f`.

### 1.2 Alternative build paths

- **CI build (GitHub Actions, Ubuntu)** — `.github/workflows/build.yml`
  compiles the eBPF objects, runs `make check` (smoke-checks the `.o`
  files are non-empty ELF), then dry-runs `nft -c -f config/nftables.conf`
  and `haproxy -c -f config/haproxy.cfg`. This is the closest thing to
  a reproducible end-to-end build verification the repo currently has,
  and it is the path most HBO graders will exercise.
- **Per-target compile** — `make xdp_l4_guard.o` or
  `make tc_l4_guard.o` to build a single program when iterating.
- **Clean** — `make clean` removes `*.o` and `*.ll`.
- **Cross-arch build** — set `ARCH=arm64` and point `KDIR` at matching
  headers; otherwise the build follows the host's architecture.
- **No top-level Makefile** — there is intentionally no root `Makefile`.
  The eBPF programs build under `bpf/`; the `config/` artefacts are
  hand-authored text files validated at deploy time, not compiled.

### 1.3 Dependencies

- **Required**:
  - Linux kernel >= 5.10 with BPF, XDP, TC-clsact, and nftables enabled.
  - `clang` >= 11 with `-target bpf` support (Ubuntu: `clang`, `llvm`).
  - `libbpf-dev` — provides `<bpf/bpf_helpers.h>` and `<bpf/bpf_endian.h>`.
  - Kernel headers for the running kernel — `linux-headers-$(uname -r)`
    on Debian/Ubuntu, `kernel-devel` on Fedora/RHEL. The Makefile reads
    `/lib/modules/$(uname -r)/build`; if this path is missing the build
    fails with header-not-found errors.
  - `linux-libc-dev` (or distro equivalent) for `<linux/bpf.h>`,
    `<linux/if_ether.h>`, `<linux/ip.h>`, `<linux/ipv6.h>`, `<linux/tcp.h>`,
    `<linux/udp.h>`, `<linux/pkt_cls.h>`.
  - `iproute2` (provides `ip` and `tc`) for loading the programs.
  - `nftables` >= 0.9 for the `rawguard` table.
  - `haproxy` >= 2.4 for the L4 frontend with stick-tables.
- **Optional**:
  - `bpftool` (`linux-tools-common`) — for `bpftool prog tracelog`,
    `bpftool map dump`, and verifier inspection. Strongly recommended
    for any debugging session.
  - `gcc-multilib` — pulled in by CI to satisfy header search paths
    on Ubuntu runners.
  - `socat` — required for the documented HAProxy stick-table inspection
    command (`echo "show table fe_http" | socat stdio /var/run/haproxy.sock`).
  - `perf`, `nstat`, `ethtool` — for the operator observability path
    documented in README.

## 2. Expected behavior

### 2.1 What this project does

StealthL4Guard is a four-layer Linux-native L4 DDoS defense pipeline.
Packets traverse, in order:

1. **XDP** (`bpf/xdp_l4_guard.c`, section `xdp_guard`) — line-rate
   header validation, anomalous TCP-flag rejection (XMAS/NULL/lone-FIN),
   IPv4 fragment drop, LPM-trie prefix blocklist (`blocked_prefixes_v4`),
   per-source-IP LRU rate counters (`ipv4_rates`, `ipv6_rates`) with
   1-second windows, and *probabilistic* drops at multiple severity tiers
   (~30%, ~60%, ~85%) — never 100%, so the attacker has no clean boundary
   to fingerprint.
2. **TC/eBPF ingress** (`bpf/tc_l4_guard.c`, section `tc_ingress`) —
   IPv4 TCP/UDP 5-tuple LRU flow table (1M entries), per-flow
   pkt/syn/ack/udp counters, behavioral `compute_mark()` returning
   `MARK_NONE` (0x0) / `MARK_GREY` (0x1) / `MARK_KILL` (0x2). Writes
   `skb->mark`; never drops.
3. **nftables/raw** (`config/nftables.conf`, table `inet rawguard`) —
   `prerouting` hook at priority `-300` (pre-conntrack). Hard-drops
   `mark 0x02`, probabilistically drops `mark 0x01` at ~30%,
   probabilistically drops `bad_sources` set members at ~80%, and
   silently drops everything that isn't TCP/UDP/ICMP(v6). No RST,
   no ICMP unreachable.
4. **HAProxy** (`config/haproxy.cfg`) — TCP-mode frontends `fe_http`
   (port 80) and `fe_https` (port 443) with per-IP `stick-table`
   `conn_rate(10s)` / `conn_cur`, rejecting overly fast (>100/s on HTTP,
   >80/s on HTTPS) or overly concurrent (>50 / >40) clients. Backends
   `be_web` / `be_web_tls` are placeholders pointing at `10.0.0.11`
   and `10.0.0.12`.

The whole pipeline is *silent*: no layer emits feedback packets to
the source.

### 2.2 Acceptance criteria

- [ ] `cd bpf && make` produces `xdp_l4_guard.o` and `tc_l4_guard.o`
      with zero errors and verifier-relevant warnings only.
- [ ] `cd bpf && make check` reports both `.o` files as non-empty ELF.
- [ ] `file bpf/xdp_l4_guard.o` reports `ELF 64-bit LSB relocatable,
      eBPF`.
- [ ] `file bpf/tc_l4_guard.o` reports `ELF 64-bit LSB relocatable,
      eBPF`.
- [ ] XDP program loads via
      `sudo ip link set dev <iface> xdp obj bpf/xdp_l4_guard.o sec xdp_guard`.
- [ ] TC clsact qdisc attaches: `sudo tc qdisc add dev <iface> clsact`
      and then
      `sudo tc filter add dev <iface> ingress bpf da obj bpf/tc_l4_guard.o sec tc_ingress`
      succeeds.
- [ ] nftables ruleset compiles: `sudo nft -c -f config/nftables.conf`
      exits 0.
- [ ] nftables ruleset applies: `sudo nft -f config/nftables.conf`
      installs table `inet rawguard` with the `prerouting` chain at
      priority `-300`.
- [ ] HAProxy config loads: `sudo haproxy -c -f config/haproxy.cfg`
      reports `Configuration file is valid`.
- [ ] CI workflow `eBPF build` is green on `main` / `master`.
- [ ] Repository layout matches README "Repository layout" section
      (`bpf/`, `config/`, `docs/`, `.github/workflows/`).

### 2.3 Manual verification

On a clean Ubuntu 22.04 / Debian 12 VM with kernel >= 5.15:

```sh
# 1. Install toolchain.
sudo apt-get update
sudo apt-get install -y \
    clang llvm libbpf-dev \
    linux-headers-$(uname -r) linux-libc-dev gcc-multilib \
    iproute2 nftables haproxy bpftool

# 2. Build eBPF objects.
cd bpf
make
make check
file xdp_l4_guard.o tc_l4_guard.o     # expect ELF 64-bit LSB, eBPF

# 3. Dry-run the config artefacts.
cd ..
sudo nft -c -f config/nftables.conf
sudo haproxy -c -f config/haproxy.cfg

# 4. Load the data plane on a test NIC (e.g. veth pair, NEVER a
#    production interface during verification).
sudo ip link add veth0 type veth peer name veth1
sudo ip link set dev veth0 up
sudo ip link set dev veth0 xdp obj bpf/xdp_l4_guard.o sec xdp_guard
sudo tc qdisc add dev veth0 clsact
sudo tc filter add dev veth0 ingress bpf da obj bpf/tc_l4_guard.o sec tc_ingress
sudo nft -f config/nftables.conf

# 5. Confirm everything is attached.
ip link show dev veth0 | grep -i xdp
sudo tc filter show dev veth0 ingress
sudo nft list table inet rawguard

# 6. Tear down.
sudo ip link set dev veth0 xdp off
sudo tc qdisc del dev veth0 clsact
sudo nft delete table inet rawguard
sudo ip link del veth0
```

If any step fails, the verifier output is usually in
`dmesg` (`sudo dmesg | tail -50`) or `bpftool prog tracelog`.

### 2.4 Automated verification

- **GitHub Actions** — `.github/workflows/build.yml` runs on every push
  and pull request to `main` / `master`. It performs the canonical
  build chain end-to-end on `ubuntu-latest`:
  1. `apt-get install clang llvm libbpf-dev linux-headers-$(uname -r)
     linux-libc-dev gcc-multilib`.
  2. `cd bpf && make all`.
  3. `cd bpf && make check`.
  4. `sudo nft -c -f config/nftables.conf`.
  5. `sudo haproxy -c -f config/haproxy.cfg`.
- ~~**No unit tests.** This is a data-plane project; the eBPF programs
  are exercised functionally by the kernel verifier at load time, which
  the manual-verification path above triggers. There is no `make test`
  target and no userland test harness.~~ **PARTIALLY RESOLVED
  2026-06-10** — a static `pytest` suite (`tests/`) now runs in CI and
  locally with no kernel/libbpf: `test_structure.py` checks the
  documented repository layout, and `test_mark_protocol.py` pins the
  one-byte `skb->mark` contract (MARK_GREY/MARK_KILL in `tc_l4_guard.c`
  must match the `meta mark … drop` rules in `nftables.conf`, KILL
  unconditional vs GREY probabilistic) — a cross-layer drift the kernel
  verifier cannot catch. CI also adds a `clang -fsyntax-only -target bpf`
  check. Full functional load-time testing still needs a privileged
  kernel (the manual path above / a future scapy harness).

## 3. Alternatives & improvements

### 3.1 Known fragilities

- **Kernel header coupling**. The Makefile pulls headers from
  `/lib/modules/$(uname -r)/build`. On a system where this symlink is
  missing (some container images, custom kernels), the build fails
  with `linux/bpf.h: No such file or directory`. Fix: install
  `linux-headers-$(uname -r)` or set `KDIR` explicitly.
- **CO-RE: infrastructure ready, per-file port pending**. The Makefile
  now ships a dual-mode build (`make` = legacy, `make USE_CORE=1` =
  CO-RE-ready) with a `vmlinux.h` generation target wired in, and
  `bpf/CORE_MIGRATION.md` documents the full porting plan with a
  per-program checklist (`vmlinux.h` includes, `BPF_CORE_READ` field
  rewrites for `iphdr`/`ipv6hdr`/`tcphdr`/`udphdr` layout-fragility
  points, `BPF_CORE_READ_BITFIELD` for TCP flags, validation matrix
  across kernel versions). **The actual `.c` programs are still
  legacy-include**, so until the per-file port lands a `.o` built on
  kernel 6.5 may still fail to load on 5.15. The status table in
  `CORE_MIGRATION.md` tracks `xdp_l4_guard.c` and `tc_l4_guard.c`
  as not-yet-ported. README §Limitations point 5 still applies in
  practice; the runway to fix it is now short.
- **Verifier sensitivity**. The TC program performs `++` on map values
  for an `LRU_HASH` (`tc_l4_guard.c:162-175`). The Linux verifier
  currently accepts this pattern, but verifier semantics have tightened
  across kernel releases; a kernel update can in principle reject the
  program with no source change. The README documents this (§Limitations
  point 3).
- **`compute_mark()` has no time window**. Counters accumulate
  monotonically over a flow's lifetime in the LRU hash. A long-lived
  legitimate connection will eventually cross the `MARK_KILL` threshold
  (`pkt_count > 5000`). The README documents this as the
  highest-priority limitation (§Limitations point 1).
- **IPv6 is half-implemented**. XDP handles IPv6 rate-counting; TC
  drops out to `TC_ACT_OK` on any non-IPv4 EtherType
  (`tc_l4_guard.c:99-100`). Flow-level behavioral analysis is
  IPv4-only.
- **No top-level Makefile**. Newcomers running `make` at the repo
  root see "No targets specified and no makefile found". The README
  is unambiguous about `cd bpf && make`, but the lack of a root entry
  point is a usability fragility.
- **Loopback / non-Ethernet NICs**. The XDP program assumes an
  Ethernet header and `XDP_DROP`s anything shorter than `sizeof(ethhdr)`.
  Loading it on `lo` or a tunnel interface that does not present an
  Ethernet header will discard legitimate traffic. Always load against
  the externally-facing NIC.
- **Probabilistic-drop math**. `DROP_PROB_HIGH` etc. are computed at
  preprocessor time as `0xFFFFFFFFU / 100 * 30`, which is
  `(2^32 - 1) / 100 * 30 = 1288490157 ≈ 30%`. The integer rounding is
  conservative (slightly under 30/60/85%) but stable across compilers.
- **`bad_sources` set is unmanaged**. The nftables ruleset declares
  `set bad_sources` with `flags timeout` but populates it only at
  runtime via an out-of-scope user-space daemon. A bare deployment
  has an empty set; the slow-ban rule is a no-op until something
  populates it.
- **HAProxy backends are placeholders**. `10.0.0.11` / `10.0.0.12` will
  fail `tcp-check` on most networks. HAProxy will still start, but the
  frontends will reject every connection once both servers are marked
  down.

### 3.2 Fallbacks

- **If `clang -target bpf` is unavailable** — install a newer LLVM
  toolchain (`apt-get install clang-15 llvm-15`) and invoke
  `make CLANG=clang-15`.
- **If kernel headers are missing** — point `KDIR` at any matching
  kernel source tree, or install `linux-source-$(uname -r | cut -d- -f1)`.
- **If the XDP program is rejected by the verifier on a newer kernel**
   — rebuild on a host running the target kernel, or disable the
  offending check by editing `xdp_l4_guard.c` (the bounded-loop and
  pointer-arithmetic sites are explicitly bounds-checked already,
  so most regressions will be in map-helper signatures).
- **If `nft` reports `Error: Could not process rule: Operation not supported`**
  on `priority -300` — the kernel lacks the `raw` family for `inet`
  at that priority. Drop the priority to `-150` (post-conntrack); the
  silent-drop property weakens but the pipeline still functions.
- **If HAProxy 2.4 syntax is unavailable** — the stick-table syntax
  used here has been stable since 1.8; older HAProxy versions usually
  parse the config but the `bytes_in_rate(10s)` counter may need to be
  removed for very old releases.
- **If running on a kernel without `clsact`** — fall back to
  `ingress` qdisc: `tc qdisc add dev <iface> ingress`. Loses the egress
  hook (unused here) but works on 4.x kernels.

### 3.3 Roadmap

- **Short-term (<= 1 day)**:
  - **Port `xdp_l4_guard.c` and `tc_l4_guard.c` to CO-RE per
    `bpf/CORE_MIGRATION.md`** (~2-3 hours per file). The Makefile
    toggle (`make USE_CORE=1`), `vmlinux.h` generation rule, and
    per-program checklist are already in place; this is now a
    mechanical rewrite of header includes and field accesses, followed
    by validation on the matrix in `CORE_MIGRATION.md`. Closes README
    §Limitations 5.
  - Add a top-level `Makefile` that delegates `all`, `check`, `clean`
    to `bpf/`, and that runs `nft -c -f` and `haproxy -c -f` as part of
    a `make verify` target — eliminates the repo-root usability gap.
  - Add `bpftool gen skeleton` invocation to `bpf/Makefile` to emit
    `.skel.h` files for a future user-space loader.
  - Add a `verifier-check` target that uses `bpftool prog load` to
    exercise the kernel verifier offline (without attaching).
  - Document the exact kernel `.config` flags required, not just
    "5.10+".
- **Medium-term (<= 1 week)**:
  - Add the IPv6 5-tuple path in `tc_l4_guard.c` (closes §Limitations 2).
  - Add atomic counter updates via `__sync_fetch_and_add` or
    `BPF_F_LOCK` for production hardening (closes §Limitations 3).
  - Write a minimal user-space brain (Go or Rust) that pins maps under
    `/sys/fs/bpf/`, reads them at 1 Hz, and exports Prometheus metrics.
  - Add an integration test harness (network namespaces + `scapy`) that
    sends crafted XMAS / NULL / SYN-flood traffic and asserts XDP drops
    and TC marks.
- **Long-term**:
  - Add a sliding-window aging mechanism in `compute_mark()`
    (closes §Limitations 1).
  - Per-tenant threshold calibration in a sidecar daemon
    (closes §Limitations 4).
  - Optional smart-NIC offload path with a feature-detection fallback
    to the kernel XDP driver mode.
  - Full HAProxy backend templating and an example end-to-end deployment
    with Nginx behind the pipeline.

## 4. Sanity check

| Check                                | Status | Notes                                                                                                                                                                       |
|--------------------------------------|--------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| README documents build               | PASS   | README §Build lists requirements, command (`cd bpf && make`), and outputs (`xdp_l4_guard.o`, `tc_l4_guard.o`).                                                              |
| Build files present                  | PASS   | `bpf/Makefile`, `bpf/xdp_l4_guard.c`, `bpf/tc_l4_guard.c`, `config/nftables.conf`, `config/haproxy.cfg`, `.github/workflows/build.yml` all present and non-empty.            |
| Build files internally consistent    | PASS   | Makefile `PROGS` list matches the two `.c` sources; CI workflow invokes `make all` and `make check`; section names in `.c` (`xdp_guard`, `tc_ingress`) match README's load commands. Makefile now offers dual modes (default legacy = current CI path, `USE_CORE=1` = CO-RE-ready with `vmlinux.h` auto-generation); both modes share the same `PROGS` and `check` targets, so CI behavior is unchanged. `bpf/CORE_MIGRATION.md` cross-references the `USE_CORE=1` toggle. |
| Source structure matches README      | PASS   | README "Repository layout" lists exactly the files present: `bpf/{xdp_l4_guard.c, tc_l4_guard.c, Makefile}`, `config/{nftables.conf, haproxy.cfg}`, `docs/architecture-deep-dive.md`, `.github/workflows/build.yml`. |
| Tests exist                          | PASS (static) | `tests/` (pytest): `test_structure.py` (repo layout) + `test_mark_protocol.py` (one-byte `skb->mark` contract consistency across `tc_l4_guard.c` ↔ `nftables.conf`). 11 passed locally. CI also runs `clang -fsyntax-only -target bpf`. Full functional/load-time testing still needs a privileged kernel. |
| Test invocation documented           | PASS   | `python -m pytest tests/ -v`, run in CI (`build.yml`) after the eBPF compile + config dry-runs. Deployment/observability commands remain in the README for the privileged path. |
| Output artifacts named in build files| PASS   | `bpf/Makefile` declares `PROGS := xdp_l4_guard.o tc_l4_guard.o`; README §Build "Output" names the same two files; CI consumes them via `make check`.                        |
