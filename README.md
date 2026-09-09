# StealthL4Guard — A Silent L4 DDoS Defense Pipeline

A multi-layer L4 DDoS-defense pipeline for Linux that runs entirely
below the application: **XDP → TC/eBPF → nftables/raw → HAProxy**.
The pipeline is designed so that, from an attacker's vantage, the
target appears only to experience packet loss or elevated latency —
no `RST`, no `ICMP unreachable`, no fingerprintable signature. The
defense is silent by construction.

This repository ships the data-plane components — two eBPF
programs, an nftables configuration, an HAProxy configuration, and
build glue — plus the architectural documentation that explains why
each layer exists where it does.

This is research / educational infrastructure. It is not a turnkey
production deployment. See [Threat model and scope](#threat-model-and-scope)
and [Limitations](#limitations) below for what this code does and
does not claim.

---

## Why this exists

Application-layer DDoS defense is a saturated market. *L4* DDoS
defense, in contrast, is dominated by closed appliances (Arbor,
F5, Cloudflare Magic Transit) and a handful of public reference
implementations. The open implementations tend either to be
*loud* — they send `RST` or `ICMP unreachable` packets, advertise
their presence in `nmap`, or expose tell-tale Linux netfilter
fingerprints — or *coarse* — they drop large prefixes wholesale and
fail under any sophisticated mixed-traffic attack.

StealthL4Guard targets the gap between these two: a Linux-native L4
pipeline that combines line-rate filtering, behavioral flow
analysis, and silent kill decisions, without ever exposing the
defense surface to an attacker who is merely reading the network's
response. The pipeline is composed of four cooperating layers, each
responsible for exactly one decision class, and each communicating
with the next *only* through a one-byte `skb->mark`.

---

## Architecture

The five-stage data flow:

```
┌─────────┐
│   NIC   │  packets land here via DMA + IRQ/NAPI
└────┬────┘
     ▼
┌──────────────┐
│     XDP      │  earliest, fastest filter
│ xdp_l4_guard │    • Ethernet / IPv4 / IPv6 / TCP / UDP validation
└────┬─────────┘    • bad-prefix LPM trie  (blocked_prefixes_v4)
     │              • per-IP LRU rate maps (ipv4_rates / ipv6_rates)
     │              • probabilistic drop (no hard wall = no fingerprint)
     ▼
┌──────────────┐
│  TC / eBPF   │  flow-level behavioral classifier
│ tc_l4_guard  │    • 5-tuple flow_table (LRU hash, 1 M entries)
└────┬─────────┘    • per-flow counters: pkt / syn / ack / udp
     │              • compute_mark(): MARK_NONE / MARK_GREY / MARK_KILL
     │              • does NOT drop — only writes skb->mark
     ▼
┌──────────────┐
│ nftables/raw │  silent kill-zone, runs *before* conntrack
│  rawguard    │    • priority -300  (pre-conntrack)
└────┬─────────┘    • meta mark 0x02 → drop
     │              • meta mark 0x01 → probabilistic drop (random < 30 %)
     │              • non-{tcp,udp,icmp} → drop
     │              • no RST / ICMP feedback (silent)
     ▼
┌──────────────┐
│  conntrack   │  state tracking — only sees the cleaned residue
└────┬─────────┘
     ▼
┌──────────────┐
│   HAProxy    │  L4 TCP load balancer + last-mile sweeper
│   fe_http /  │    • TCP mode
│   fe_https   │    • stick-table conn_rate(10s) / conn_cur
└────┬─────────┘    • acl too_fast → reject
     ▼
   Backend pool (Nginx / Node / PHP / …)
```

### Layer responsibilities (one sentence each)

| Layer            | Role                                                                                   |
|------------------|----------------------------------------------------------------------------------------|
| **XDP**          | Reject malformed and prefix-blocklisted traffic at NIC driver line rate.               |
| **TC / eBPF**    | Maintain per-flow state, compute a behavioral score, attach a mark to the `sk_buff`.   |
| **nftables/raw** | Translate marks into silent drops before conntrack creates state.                      |
| **HAProxy**      | Apply per-IP rate limits and distribute the post-defense survivors to backends.        |

### Design invariants

The pipeline preserves three invariants that the rest of the design
follows from:

1. **No feedback to the attacker.** No layer emits `RST`, `ICMP
   destination unreachable`, or any other observable rejection.
   From the attacker's side the target appears to be experiencing
   network loss, not active defense.
2. **Mark-only communication between layers.** XDP and TC do not
   call into each other; nftables and TC do not share memory.
   Every cross-layer signal travels through `skb->mark`. This
   means each layer can be reloaded, tuned, or replaced
   independently.
3. **Defense moves earlier as confidence grows.** XDP filters with
   the least information but the most speed; TC adds flow
   intelligence; nftables makes the final call; HAProxy handles
   what survives. By the time a packet reaches the application
   backend, every preceding layer has had a chance to drop it.

---

## Threat model and scope

StealthL4Guard is designed for the following adversary:

- a botnet sourcing high pps / cps from many ASNs;
- volumetric L4 traffic — SYN flood, UDP flood, ACK flood, XMAS
  flag, NULL flag, FIN/PSH;
- IP-fragmentation amplification, malformed-checksum amplification;
- mixed legitimate-and-malicious traffic from the same source IP.

It is **not** designed for:

- L7 attacks (Slowloris, HTTP-flood, application-logic abuse);
- amplification attacks at the L4 *source* — i.e., this is a
  *recipient*-side defense, not an outbound rate-limiter;
- attacks that originate inside the same host or the same VLAN
  trust boundary;
- adversaries with the ability to deploy code on the protected
  host (a kernel-resident attacker can disable everything in this
  repository).

It explicitly does not:

- send any feedback to the attacker;
- attempt to attribute traffic to specific actors;
- forward observed traffic to any third party;
- modify any kernel object outside its own BPF maps.

---

## Repository layout

```
bpf/
  xdp_l4_guard.c    Line-rate header validation + prefix filter + rate maps
  tc_l4_guard.c     Flow-level behavioral classifier, marks skb->mark
  Makefile          clang BPF target build glue

config/
  nftables.conf     pre-conntrack mark interpreter ("rawguard")
  haproxy.cfg       TCP-mode frontend skeleton with stick-table

docs/
  architecture-deep-dive.md   Extended per-layer technical analysis

.github/workflows/
  build.yml         CI: clang BPF compile check
```

---

## Build

Requirements:

- Linux kernel 5.10+ with BPF/XDP/TC support;
- `clang` with BPF target (clang 11+);
- `libbpf-dev`;
- kernel headers matching the running kernel;
- `nftables` ≥ 0.9;
- `haproxy` ≥ 2.4.

To build the eBPF programs:

```sh
cd bpf && make
```

Output:

```
bpf/xdp_l4_guard.o
bpf/tc_l4_guard.o
```

## Deploy

The deployment sequence loads the layers from outermost (XDP) to
innermost (HAProxy). Each step is idempotent and reversible.

Replace `eth0` with the externally-facing NIC.

**1. Load XDP:**

```sh
sudo ip link set dev eth0 xdp obj bpf/xdp_l4_guard.o sec xdp_guard
```

**2. Attach TC ingress filter:**

```sh
sudo tc qdisc add dev eth0 clsact
sudo tc filter add dev eth0 ingress bpf da obj bpf/tc_l4_guard.o sec tc_ingress
```

**3. Apply nftables ruleset:**

```sh
sudo nft -f config/nftables.conf
```

**4. Start HAProxy** (validate config first):

```sh
sudo haproxy -c -f config/haproxy.cfg     # check
sudo haproxy -f config/haproxy.cfg        # run
```

To tear down:

```sh
sudo ip link set dev eth0 xdp off
sudo tc qdisc del dev eth0 clsact
sudo nft delete table inet rawguard
sudo systemctl stop haproxy   # or `kill` the haproxy pid
```

---

## Observability

The data plane is silent to attackers. It is meant to *not* be
silent to operators, but the code as it exists today has limited
built-in instrumentation. Be aware of what each tool below actually
shows, as-is:

- `bpftool prog tracelog` — this surfaces the kernel verifier's
  load-time diagnostics and any `bpf_printk()` trace lines. **Neither
  `xdp_l4_guard.c` nor `tc_l4_guard.c` contains a single
  `bpf_printk()` call**, so at runtime this command has nothing to
  print for this pipeline; it is only useful while debugging a
  load/verifier failure.
- `bpftool map dump pinned /sys/fs/bpf/<map>` — only works for a
  pinned map. **None of the four maps
  (`blocked_prefixes_v4`, `ipv4_rates`, `ipv6_rates`, `flow_table`)
  declare `LIBBPF_PIN_BY_NAME`**, and the load commands shown above
  (`ip link set ... xdp obj ...`, `tc filter add ... obj ...`) do not
  pin them either — there is no loader in this repository. As
  deployed via those commands, the maps are anonymous: this command
  will not find them, `blocked_prefixes_v4` cannot be populated from
  user space, and the rate/flow maps cannot be read.
- `perf top` — general CPU profiling, not specific to this pipeline;
  no baseline numbers have been measured against this code (see
  [Status](#status)).
- `nstat -a`, `ethtool -S eth0` — NIC/stack-level counters; they
  reflect all traffic on the interface, not this pipeline's
  decisions specifically.
- `nft list table inet rawguard` — per-rule drop counters. This one
  is real as written: every drop rule in `config/nftables.conf`
  carries a `counter` keyword, so once the ruleset is applied these
  numbers do reflect nftables' own decisions.
- HAProxy stick-table:
  `echo "show table fe_http" | socat stdio /var/run/haproxy.sock` —
  the shipped `config/haproxy.cfg` does not configure a `stats
  socket`, so this command will fail against it unless a
  `stats socket /var/run/haproxy.sock ...` line is added to `global`
  first.

There is no stats/counter map (e.g. `BPF_MAP_TYPE_PERCPU_ARRAY`) in
either eBPF program, so no per-reason XDP/TC drop counts exist
anywhere in this code; the `nft` per-rule counters above are the only
real-time counters this pipeline currently produces.

For longitudinal observation — not implemented here, only described
as a design direction:

- Pinning the BPF maps and having a small Go or Rust daemon read
  them at 1 Hz is a reasonable follow-on design (see "Tuning the
  user-space brain" below), but it does not exist in this repository
  today.
- Exporting to Prometheus and plotting `(drop rate, latency, CPU)`
  jointly is likewise a documented idea, not shipped code or a
  measured result.

---

## Tuning the user-space brain

The eBPF programs are intentionally policy-light: they implement
the *mechanism*, not the *policy*. A small user-space daemon can:

- read the LRU rate maps and adjust `blocked_prefixes_v4` to add
  observed abusive ASNs (`AS9009`, `AS20473`, `AS8100`, …);
- update `nft set` entries with `timeout 10m` to slow-ban offenders
  while remaining recoverable;
- rotate thresholds in `compute_mark()` over time to defeat
  fingerprinting;
- emit a randomized jitter window into the probabilistic-drop
  rates to prevent attacker calibration.

The daemon is intentionally out of scope for this repository — it
is a single integration surface, not a single implementation.

---

## Limitations

This is research / educational code. Known limitations, prioritized
by what would have to change first for production deployment:

1. **`compute_mark()` has no explicit time window.** Counters
   accumulate monotonically over a flow's lifetime in the LRU
   hash; a long-lived benign connection will eventually trip the
   `KILL` threshold. The fix is to add a sliding-window timer or
   to age counters via a periodic eBPF user-space tick. The
   current PoC uses static thresholds and relies on the LRU
   eviction to bound staleness — adequate for demonstration,
   inadequate for production.

2. **IPv6 path is partially specified.** XDP handles IPv6 in the
   description but the current `tc_l4_guard.c` is IPv4-only.
   IPv6 5-tuple support is a documented next step.

3. **Race-safety of in-place LRU updates.** The TC program (and the
   XDP per-IP rate windows) update counters in place on a shared
   LRU map value rather than via a fresh `bpf_map_update_elem` per
   packet, and multiple RSS CPUs can update the same flow/IP
   concurrently. Per-field increments use `__sync_fetch_and_add`
   (not a bare `++`) so a single counter cannot silently lose an
   update. The four-field struct as a whole is still not updated as
   one atomic transaction — a reader can observe one field bumped
   slightly ahead of the others — which is acceptable for these
   statistical thresholds; a fully race-free design would need
   `BPF_F_LOCK` or `BPF_MAP_TYPE_PERCPU_HASH`. None of this has been
   exercised against a real kernel verifier — see
   [Status](#status).

4. **`compute_mark()` thresholds are static and uncalibrated.**
   Real deployment requires per-tenant calibration; the shipped
   values (`pkt_count > 5000`, `udp_count > 3000`,
   `syn_count > 1000 && ack_count < syn_count/10`) are PoC
   placeholders that are useful only as a baseline.

5. **No CO-RE.** The eBPF programs are compiled against the
   building host's headers; portability across kernel versions
   requires migrating to CO-RE / libbpf bootstrap.

6. **HAProxy config is a skeleton.** Backend pool is a
   placeholder; tune `conn_rate`, `conn_cur`, and stick-table
   size for the actual deployment.

7. **No user-space brain bundled.** As noted above, the daemon
   that closes the policy loop is left as a documented
   integration point.

---

## References

[1] Linux kernel documentation. *XDP: eXpress Data Path.*
    `Documentation/networking/af_xdp.rst`, 2024.

[2] T. Høiland-Jørgensen, J. Brouer, D. Borkmann, J. Fastabend,
    T. Herbert, D. Ahern, D. Miller. *The eXpress Data Path: Fast
    Programmable Packet Processing in the Operating System Kernel.*
    CoNEXT, 2018.

[3] B. Gregg. *BPF Performance Tools.* Addison-Wesley, 2019.

[4] M. Fleming. *A thorough introduction to eBPF.* LWN, 2017.

[5] Linux kernel documentation. *BPF and XDP Reference Guide.*
    Cilium project, 2024.

[6] Netfilter project. *nftables reference manual.*
    https://wiki.nftables.org

[7] HAProxy Technologies. *HAProxy Configuration Manual* (TCP
    mode, stick-tables). https://www.haproxy.org/

[8] D. Borkmann, et al. *eBPF and XDP for Programmable Networking.*
    Kernel summit, 2017.

[9] J. Brouer. *Network performance workshop.* Red Hat, 2018.
    (per-CPU map design rationale).

[10] Y. Yarom, K. Falkner. *FLUSH+RELOAD.* USENIX Security, 2014.
     (Cited only for the timing-fingerprint methodology motivating
     the silent-drop design.)

---

## License

MIT — see `LICENSE`.

## Status

Research / non-production, and **untested at runtime**. As of this
writing, no BPF program in this repository has ever executed a
single instruction on a kernel — nothing here has been built,
loaded, or run against real or synthetic traffic. Concretely:

- the two eBPF programs are source code that has been written and
  reviewed, not compiled in this project (no clang/libbpf/Linux
  kernel toolchain has been used against it);
- the nftables ruleset and HAProxy config have not been dry-run or
  applied;
- the `tests/` suite (see `BUILD_AND_VERIFY.md` §2.4) is static:
  file-existence checks plus regex comparisons between source files.
  It does not compile, load, or execute any BPF code, and it does
  not send or receive a packet. "11 passed" describes these static
  checks, not a functional or behavioral result.

Deployment on a production edge — or even a first real dynamic
test — requires the hardening described in
[Limitations](#limitations), an actual build/load/traffic-generation
pass on a Linux kernel, and a calibrated user-space brain.

The architectural posture — silent drop, mark-only communication,
defense-moves-earlier-as-confidence-grows — is the contribution.
The eBPF programs are reference implementations of that posture,
not a turnkey appliance.
