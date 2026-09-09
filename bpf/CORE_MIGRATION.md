# StealthL4Guard — CO-RE Migration Plan

## Why migrate

The current `xdp_l4_guard.c` and `tc_l4_guard.c` are compiled
against the running kernel's headers in
`/lib/modules/$(uname -r)/build`. The resulting `.o` files are
*kernel-build-locked*: a `.o` built on a 6.5 host may fail to load
on a 6.1 host because a `struct iphdr` field offset or a
helper-argument shape moved.

CO-RE (Compile-Once-Run-Everywhere) solves this by replacing the
kernel-header includes with a single generated `vmlinux.h` (the
kernel's type universe, dumped from the BTF blob in
`/sys/kernel/btf/vmlinux`) and rewriting field accesses to use
relocation-aware helpers (`BPF_CORE_READ`, `bpf_core_field_offset`).
The resulting `.o` carries BTF metadata that libbpf rewrites at
load time to match the running kernel.

This document is the porting checklist. Use it alongside the
Makefile's `USE_CORE=1` switch, which is wired and waiting.

## Status

| File                   | Status              |
|------------------------|---------------------|
| `Makefile`             | ✅ CO-RE-ready (toggle via `make USE_CORE=1`) |
| `vmlinux.h`            | ✅ Generation rule present (auto-extracted from BTF) |
| `xdp_l4_guard.c`       | ⬜ Not yet ported    |
| `tc_l4_guard.c`        | ⬜ Not yet ported    |

## Build (when ported)

```sh
make USE_CORE=1
```

The Makefile runs `bpftool btf dump file /sys/kernel/btf/vmlinux
format c > vmlinux.h` (one-time on a fresh checkout), then
compiles each `.c` with the CO-RE include set instead of the
legacy `/lib/modules/...` headers.

## Per-program porting checklist

For each of `xdp_l4_guard.c` and `tc_l4_guard.c`:

### 1. Replace kernel-header includes

**Before:**
```c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
```

**After:**
```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
```

`vmlinux.h` supplies every kernel type the program touches —
`struct __sk_buff`, `struct xdp_md`, `struct ethhdr`, `struct iphdr`,
`struct ipv6hdr`, `struct tcphdr`, `struct udphdr`, the in-protocol
constants — so the `<linux/*.h>` set becomes redundant.

### 2. Rewrite field reads for layout-fragility

Direct field reads keep working in many cases (the program-side
struct layout matches the kernel's at compile time). Where the
field shape *might* shift across kernels, use the CO-RE read
helpers so libbpf rewrites the offset at load:

```c
/* Before: direct read, locked to the build host's iphdr layout */
__u32 saddr = iph->saddr;

/* After: relocated at load to match the running kernel */
__u32 saddr = BPF_CORE_READ(iph, saddr);
```

The high-risk fields for L4 work are:
- `struct iphdr::{saddr, daddr, protocol, ihl, tot_len}`
- `struct ipv6hdr::{saddr, daddr, nexthdr, hop_limit, payload_len}`
- `struct tcphdr::{source, dest, syn, ack, fin, rst}` (bitfield
  layout is BPF_CORE_READ_BITFIELD territory)
- `struct udphdr::{source, dest, len}`

Wrap each of these in `BPF_CORE_READ(...)` (or
`BPF_CORE_READ_BITFIELD(...)` for the TCP flags).

### 3. Rewrite map definitions

Modern CO-RE programs use BTF-aware map declarations:

```c
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_v4_key);
    __type(value, __u8);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} blocked_prefixes_v4 SEC(".maps");
```

The current programs already use this form; no work needed here.

### 4. Verify with the legacy path before merging

Until both programs are ported and verified on at least two
kernels, the legacy `make` (no `USE_CORE=1`) is the supported
build. Do *not* delete the legacy include set from the Makefile
until both programs pass `make USE_CORE=1 check` on the target
kernels.

## Reference

- Andrii Nakryiko. *BPF CO-RE (Compile Once – Run Everywhere).*
  https://nakryiko.com/posts/bpf-core-reference-guide/
- Linux kernel documentation. *BPF Type Format (BTF).*
  `Documentation/bpf/btf.rst`.
- libbpf-tools project — comprehensive example corpus of
  CO-RE-ported eBPF tools.
- `bpftool btf dump file ... format c` — the canonical recipe
  for generating `vmlinux.h`.

## Validation matrix (target end-state)

| Source kernel | Target kernel | Expected outcome     |
|--------------|---------------|----------------------|
| 6.1 build host | 6.1 load host | load OK              |
| 6.1 build host | 6.5 load host | load OK (CO-RE wins) |
| 6.5 build host | 5.15 load host| load OK (within BTF support) |
| 6.5 build host | 4.19 load host| load fails (pre-BTF) — documented limit |

Until the migration is complete, the validation matrix is
"build host == load host", which is the current `BUILD_AND_VERIFY.md`
position.
