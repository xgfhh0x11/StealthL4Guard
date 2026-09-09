# StealthL4Guard — Architecture Deep Dive

Companion document to `README.md`. The README explains *what* each
layer does and *how* to deploy it. This document explains *why*
each layer is where it is, what alternative placements were rejected,
and what each layer's failure mode looks like in practice.

The intended reader is a defender who wants to extend, audit, or
recompose the pipeline.

---

## 0. Position-of-defense, restated

The single most important architectural commitment is this:

> *Defense moves earlier in the pipeline as confidence in the
> bad-traffic verdict grows.*

This is the inverse of most off-the-shelf L7 protections, which
push every packet up to an application layer where rich context
is available but where every packet has already cost the kernel
work to deliver. StealthL4Guard runs in the other direction:

| Layer        | Confidence required to act | Cost of acting        |
|--------------|----------------------------|-----------------------|
| XDP          | Coarse signals only        | Near-zero (driver)    |
| TC / eBPF    | Flow-level behavior        | Low (per-packet)      |
| nftables/raw | Pre-existing mark          | Low (no conntrack)    |
| HAProxy      | Survived everything above  | High (userspace)      |

Each rung up the ladder costs more but knows more. The mark-only
contract between rungs keeps the contract minimal: one byte of
information out of the kernel decides the rest of the packet's
fate.

---

## 1. NIC layer — what we don't do here

The NIC is the bottom of the pipeline, but the pipeline does **not**
rely on smart-NIC offload (TC-offload, XDP-offload). Two reasons:

1. **Portability.** Smart-NIC offload is vendor-specific
   (Mellanox/NVIDIA ConnectX, Netronome). The same eBPF source
   should compile and load on commodity NICs. Performance is left
   on the table; portability is preserved.

2. **Observability.** Offloaded XDP runs invisibly to standard
   kernel tooling. Operators auditing a deployment cannot
   `bpftool prog tracelog` a program that lives in NIC firmware.
   For a defense whose correctness depends on observability, this
   is a non-trivial cost.

If a future deployment justifies offload, the XDP source compiles
under XDP-offload mode unmodified; the only change is the
`ip link set ... xdp` invocation.

---

## 2. XDP layer — `bpf/xdp_l4_guard.c`

### 2.1 Why XDP exists in this pipeline

A 10 Gb/s NIC at small packet sizes carries up to ~14.88 Mpps
(million packets per second). A modest DDoS hits 50 Mpps; advanced
ones exceed 100 Mpps. The Linux network stack (sockets, conntrack,
nftables on the regular hooks) cannot process at this rate without
saturating CPUs.

XDP runs in the NIC driver path, before `sk_buff` allocation,
before any other Linux networking hook. It can drop a packet
without ever creating a `struct sk_buff`. The cost of dropping a
packet here is *single-digit nanoseconds*. Doing the same work in
nftables-with-conntrack costs *hundreds of nanoseconds per packet*
just for allocation, before any rule evaluation.

This is the only layer that can survive line-rate attacks
unmodified.

### 2.2 What XDP filters, in order

The XDP program (see `bpf/xdp_l4_guard.c`) evaluates each packet
against a sequence of cheap-to-expensive checks. The order is
deliberate: the cheapest filters come first because they reject the
largest volume of attack traffic.

1. **Frame validity.** `eth + 1 > data_end` → drop. Malformed
   frames waste downstream CPU.

2. **EtherType.** Only IPv4, IPv6, and (implicitly, by fall-through)
   non-IP packets reach this far. Non-IP packets fall to `XDP_PASS`
   so the kernel can handle ARP, VLAN tail, etc.

3. **IPv4 sanity.** `ihl >= 5`; `tot_len >= ihl*4`; fragment-bits
   non-set. Fragments are deliberately rejected: in 2026 the
   legitimate need for IP fragments is essentially zero, and they
   are the primary IDS-evasion vector.

4. **Prefix blocklist (LPM trie).** Source IP is looked up against
   `blocked_prefixes_v4`. Hits are dropped *probabilistically*.
   The probability is high (~85 %) but never 100 %. A 100 % drop
   is a fingerprint — an attacker probing with one packet per
   second from a "known bad" prefix would receive an unmistakably
   clean response indicating their prefix is on the list. With
   85 %, the response is statistically indistinguishable from
   ordinary network loss.

5. **Protocol filter.** Only TCP / UDP / ICMP are passed past this
   point. Other protocols (GRE, ESP, IGMP, IPIP) are dropped.

6. **TCP flag anomaly.** `XMAS` (FIN+URG+PSH), `NULL` (no flags),
   lone `FIN` — these are scanner / flood signatures that no
   legitimate client emits. Drop.

7. **Per-IP behavioral counters.** Source-IP-keyed LRU hash
   `ipv4_rates` maintains `pkt_count`, `syn_count`, `udp_count`
   over a 1 s rolling window. Above each threshold:
   - SYN flood (`syn_count > SYN_THRESHOLD`) → high-prob drop;
   - UDP flood (`udp_count > UDP_THRESHOLD`) → high-prob drop;
   - PPS flood (`pkt_count > PPS_THRESHOLD`) → mid-prob drop;
   - half-PPS → low-prob drop (degrade, don't cut off).

The thresholds and probabilities are PoC defaults. The contract
the rest of the pipeline relies on is that XDP *will* drop the
bulk of high-rate, prefix-blocked, and malformed traffic, *and*
that it does so without ever emitting a packet in reply.

### 2.3 IPv6 path

IPv6 uses a parallel structure: `ipv6_rates` LRU map keyed on the
16-byte source address. The current implementation handles only
TCP/UDP/ICMPv6 next-header values, with PPS- and UDP-flood
thresholds. SYN-flood detection on IPv6 is not yet implemented;
it requires extension-header walking which is a known complexity
trap and is deferred to a separate change.

### 2.4 Failure mode

If XDP fails entirely (program not loaded, NIC driver unsupported),
the pipeline still works — TC/eBPF and nftables continue to operate
— but the line-rate guarantee is lost. The next-cheapest filter is
TC, which runs after `sk_buff` allocation and is comparatively
expensive. A failed XDP layer is a *performance* failure, not a
*correctness* failure.

---

## 3. TC/eBPF layer — `bpf/tc_l4_guard.c`

### 3.1 What TC does that XDP cannot

XDP knows per-packet and per-source-IP facts. TC adds **per-flow**
intelligence. A flow, here, is a 5-tuple
`(src_ip, dst_ip, src_port, dst_port, proto)`. Per-flow state is
prohibitive to maintain at XDP for two reasons:

- per-flow keys are 13 bytes (vs. 4 for source IP), so the
  hash-collision behavior is worse at the same map size;
- per-flow state is most useful for TCP semantics
  (`syn_count >> ack_count` is a SYN-flood signature only at the
  flow level — at the per-IP level, a legitimate user opening
  many tabs looks the same as an attacker).

So XDP is per-IP and per-window; TC is per-flow and per-flow.

### 3.2 The `compute_mark` decision

The TC program does not drop. It writes one of three values to
`skb->mark`:

- `MARK_NONE` (0x0) — pass through;
- `MARK_GREY` (0x1) — suspicious, hand to nftables for
  probabilistic drop;
- `MARK_KILL` (0x2) — confirmed bad, hand to nftables for hard
  drop.

The signals feeding `compute_mark`:

```
pkt_count > 5000                     → MARK_KILL    (volumetric)
udp_count > 3000                     → MARK_KILL    (UDP flood)
syn_count > 1000 && ack < syn/10     → MARK_GREY    (SYN flood)
default                              → MARK_NONE
```

Three properties are worth noting:

1. **The thresholds are not time-windowed in this PoC.** Counters
   accumulate over the flow's lifetime in the LRU hash. A
   long-lived benign flow will eventually trip the `KILL`
   threshold. This is a known gap; the production fix is a
   sliding window driven either by a periodic eBPF user-space
   tick or by a `bpf_ktime_get_ns` check in the program.

2. **The decision is split from the execution.** TC says "this
   flow is bad"; nftables says "drop this packet". The split
   allows the *policy* (drop or pass, with what probability) to
   live entirely in nftables, configurable from user-space, while
   the *mechanism* (the behavioral classifier) stays in the
   compiled eBPF program.

3. **The map is in-place updated.** Counter increments on map
   values are not atomic across CPUs. Counters can lose a small
   number of updates under high core-count load. The signal is
   statistical, so the loss is tolerable; a strict counter would
   require `__sync_fetch_and_add` and is a one-line change.

### 3.3 Failure mode

If the TC program fails to load (verifier rejection on a kernel
mismatch, missing helper, etc.), the pipeline silently degrades to
"XDP + nftables/raw + HAProxy". The nftables `meta mark` rules will
never fire (mark always 0) and the GREY / KILL classes effectively
disappear. The system still drops malformed packets and rate-limits
per-IP; it loses per-flow detection of slow SYN floods. This is the
correct fail-soft behavior.

---

## 4. nftables/raw layer — `config/nftables.conf`

### 4.1 Why `raw` and not `filter`

The default nftables `filter` chain runs *after* connection
tracking. By the time a packet reaches `filter`, conntrack has
already created (or looked up) a connection entry. Under flood
conditions, this entry creation is itself a denial-of-service
amplifier — the conntrack table fills, legitimate connections are
evicted, and the system suffers a second-order failure even if no
packet ever reaches the application.

The `raw` table at priority `-300` runs *before* conntrack.
Decisions made here cost no connection-table memory and trigger no
state allocation. For a defense whose primary job is to keep the
conntrack table from filling, `raw` is the only sound position.

### 4.2 What `rawguard` does

The `rawguard` table consumes the marks from TC and adds two
additional drop rules:

- `ip saddr @bad_sources meta random lt 80 counter drop` — the
  user-space brain populates `bad_sources` at runtime; matched
  sources are dropped 80 % of the time.
- `meta mark 0x02 counter drop` — TC's `KILL` verdict, hard drop.
- `meta mark 0x01 meta random lt 30 counter drop` — TC's `GREY`
  verdict, 30 % probabilistic drop.
- Non-TCP/UDP/ICMP/ICMPv6 traffic — silent drop.

Every drop rule carries a `counter` keyword. The counters are the
only feedback the defense provides — they go to the operator, not
the attacker.

### 4.3 The silence guarantee

`drop` in nftables is *silent* by default. There is no `reject`
rule (which would send `RST` or `ICMP unreachable`). The attacker
sees only packet loss, indistinguishable from upstream congestion
or network failure.

---

## 5. HAProxy layer — `config/haproxy.cfg`

### 5.1 What HAProxy is for here

HAProxy is the only layer that participates in the application
session. Its job is *not* defense — defense is done. Its job is
threefold:

1. **Per-IP rate enforcement on cleaned traffic.** The kernel
   filters defend against floods. HAProxy enforces a slower,
   per-IP cap for clients that survived the kernel pipeline but
   are still misbehaving.

2. **L4 load balancing across the backend pool.** TCP-mode only;
   no L7 inspection, no SSL termination at this layer. L7 work
   re-introduces a fingerprintable surface and is delegated to
   downstream services.

3. **Backend health.** `option tcp-check` against backend ports
   removes dead backends from rotation.

### 5.2 stick-tables

HAProxy's stick-tables track per-source-IP `conn_rate(10s)` and
`conn_cur`. The `acl too_fast` and `acl too_many` thresholds are
deliberately tight: anything that survived the kernel pipeline and
is still hammering at >100 conn/10s is almost certainly the slow
tail of an attack and is rejected at the TCP level.

The stick-table is small (1 M entries, 10 m expiry) and cheap to
query at userspace speed.

### 5.3 Failure mode

If HAProxy stops, the kernel pipeline keeps the conntrack table
healthy and the attacker still cannot land RST/ICMP feedback. The
backend simply becomes unreachable to *legitimate* clients too.
HAProxy is not a defense single-point-of-failure; it is a service
single-point-of-failure, which is acceptable behavior for a
front-line load balancer.

---

## 6. Cross-layer invariants

Three invariants govern the interaction between layers and survive
every individual layer's failure:

| Invariant                                                            | Enforced by                                              |
|----------------------------------------------------------------------|----------------------------------------------------------|
| No layer sends RST / ICMP feedback to dropped packets.              | XDP uses `XDP_DROP`; nftables uses `drop` (not `reject`). |
| Inter-layer communication is one byte (`skb->mark`).                 | TC writes mark; nftables reads mark; no shared memory.   |
| Drop decisions are probabilistic above thresholds.                  | XDP `prob_drop()`; nftables `meta random lt N`.           |

The probabilistic-drop invariant is the most under-appreciated.
A defense that drops 100 % of bad traffic gives the attacker a
clean side-channel: they can probe with one packet per second
from candidate prefixes and immediately know which prefixes are
on the blocklist. A 75–85 % drop rate is statistically
indistinguishable from upstream congestion.

---

## 7. What this architecture cannot do

The defense is honest about its scope. It cannot:

- defeat **L7 attacks** (Slowloris, HTTP-flood, application-logic
  abuse). These require L7 inspection, which this pipeline
  deliberately avoids.
- defeat **attacks from within the trust boundary**. A
  kernel-resident attacker on the host can disable XDP, flush
  nftables, and stop HAProxy.
- **identify** attackers. The pipeline drops; it does not attribute.
- defeat **calibrated low-and-slow attacks** that stay below every
  threshold. Such attacks are within the application's policy
  domain, not the L4 defense's.
- replace **upstream capacity**. If a 1 Tbps flood arrives at a
  10 Gbps link, the kernel still has only 10 Gbps to drop in.
  Upstream capacity (BGP blackhole, scrubbing-center forwarding) is
  required for volumetric attacks above link rate.

These are not bugs; they are the boundary of what an L4 defense
*can* do. Honest scope is part of the contribution.

---

## 8. Tuning checklist

Before deploying to a real edge, audit:

- [ ] `PPS_THRESHOLD`, `SYN_THRESHOLD`, `UDP_THRESHOLD` against the
      target's baseline.
- [ ] LRU map sizes (`1024 * 1024`) against the source-IP
      cardinality you actually serve.
- [ ] `compute_mark` thresholds against your tenants' traffic
      patterns.
- [ ] `meta random lt N` probabilities — too high and legitimate
      slow tails get hurt, too low and the defense leaks.
- [ ] HAProxy `acl too_fast` / `acl too_many` against your real
      conn/sec from legitimate clients.
- [ ] User-space brain — every entry in `bad_sources` must have a
      `timeout`; otherwise the set grows monotonically and the
      defense becomes increasingly brittle.

The brain is the only piece that is intentionally *not* in this
repository; it is a single integration point with operator-specific
policy.
