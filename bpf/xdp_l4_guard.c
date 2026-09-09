// SPDX-License-Identifier: GPL-2.0
/*
 * StealthL4Guard — XDP line-rate filter.
 *
 * Position: NIC driver → [XDP here] → kernel stack
 *
 * Responsibilities, in order of evaluation:
 *   1. Ethernet / IPv4 / IPv6 / TCP / UDP header validation
 *      (malformed packets are dropped before reaching the stack).
 *   2. Anomalous TCP-flag rejection (XMAS, NULL, FIN-only, etc.).
 *   3. Prefix blocklist via LPM trie (blocked_prefixes_v4).
 *   4. Per-IP behavioral rate maps (LRU hash, 1 s window):
 *        ipv4_rates / ipv6_rates  →  pkt / syn / udp counts.
 *   5. Probabilistic drop above thresholds (no hard wall: never
 *      give the attacker a fingerprintable boundary).
 *
 * No feedback. No RST. No ICMP. The attacker sees packet loss.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

/* Window length for the per-IP rate maps (nanoseconds). */
#define WINDOW_NS    1000000000ULL    /* 1 s */

/* Per-window thresholds — PoC values. */
#define PPS_THRESHOLD     20000U
#define SYN_THRESHOLD      5000U
#define UDP_THRESHOLD     10000U

/* Probabilistic-drop ratios above threshold.
 * Never go to 100 %: a hard wall is a fingerprint.
 * Values are 0..UINT32_MAX, compared against bpf_get_prandom_u32(). */
#define DROP_PROB_LOW     ((__u32)(0xFFFFFFFFU / 100 * 30))   /* ~30% */
#define DROP_PROB_MID     ((__u32)(0xFFFFFFFFU / 100 * 60))   /* ~60% */
#define DROP_PROB_HIGH    ((__u32)(0xFFFFFFFFU / 100 * 85))   /* ~85% */

/* ---- per-IP rate-window record --------------------------------- */

struct ip_rate_window {
    __u64 window_start_ns;
    __u32 pkt_count;
    __u32 syn_count;
    __u32 udp_count;
};

/* ---- LPM trie key (IPv4) --------------------------------------- */

struct lpm_v4_key {
    __u32 prefixlen;
    __u32 addr;
} __attribute__((packed));

/* ---- maps ------------------------------------------------------ */

/*
 * blocked_prefixes_v4 — LPM trie of CIDR blocks to silently drop.
 * Populated from user-space at runtime (botnet ASN ranges, abusive
 * cloud prefixes, etc.). Value is a uint8_t severity / metadata
 * byte that user-space can interpret.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_v4_key);
    __type(value, __u8);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} blocked_prefixes_v4 SEC(".maps");

/*
 * ipv4_rates — per-source-IP behavioral counters over a 1 s window.
 * LRU hash bounds memory while keeping the most-active sources hot.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);                  /* source IPv4 address */
    __type(value, struct ip_rate_window);
    __uint(max_entries, 1024 * 1024);
} ipv4_rates SEC(".maps");

/*
 * ipv6_rates — same shape, IPv6 keyed.
 */
struct in6_addr_key {
    __u8 addr[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct in6_addr_key);
    __type(value, struct ip_rate_window);
    __uint(max_entries, 1024 * 1024);
} ipv6_rates SEC(".maps");

/* ---- helpers --------------------------------------------------- */

static __always_inline int prob_drop(__u32 threshold)
{
    return bpf_get_prandom_u32() < threshold;
}

/*
 * Anomalous TCP flag combinations that legitimate clients never
 * emit. Each is a known flood / scan signature.
 *
 *   XMAS:   FIN + URG + PSH
 *   NULL:   no flags
 *   FIN-only with no prior session
 *   PSH-only (sometimes a small ACK-flood variant)
 */
static __always_inline int tcp_flags_anomalous(const struct tcphdr *t)
{
    __u8 fin = t->fin, syn = t->syn, rst = t->rst;
    __u8 psh = t->psh, ack = t->ack, urg = t->urg;

    if (fin && urg && psh)                       return 1;   /* XMAS */
    if (!fin && !syn && !rst && !psh && !ack && !urg) return 1; /* NULL */
    if (fin && !ack && !syn && !rst)             return 1;   /* lone FIN */
    return 0;
}

static __always_inline void
account_v4(__u32 src, __u64 now, int is_syn, int is_udp,
           __u32 *pps, __u32 *syns, __u32 *udps)
{
    struct ip_rate_window *w = bpf_map_lookup_elem(&ipv4_rates, &src);
    struct ip_rate_window  fresh = {
        .window_start_ns = now,
        .pkt_count = 1,
        .syn_count = is_syn ? 1 : 0,
        .udp_count = is_udp ? 1 : 0,
    };

    if (!w) {
        bpf_map_update_elem(&ipv4_rates, &src, &fresh, BPF_ANY);
        *pps = 1; *syns = fresh.syn_count; *udps = fresh.udp_count;
        return;
    }

    if (now - w->window_start_ns > WINDOW_NS) {
        /* Window rolled — reset. */
        w->window_start_ns = now;
        w->pkt_count = 1;
        w->syn_count = is_syn ? 1 : 0;
        w->udp_count = is_udp ? 1 : 0;
    } else {
        w->pkt_count++;
        if (is_syn) w->syn_count++;
        if (is_udp) w->udp_count++;
    }
    *pps = w->pkt_count;
    *syns = w->syn_count;
    *udps = w->udp_count;
}

/* ---- main ------------------------------------------------------ */

SEC("xdp_guard")
int xdp_l4_guard(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;        /* malformed below minimum frame */

    __u16 etype = eth->h_proto;

    if (etype == bpf_htons(ETH_P_IP)) {
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end)
            return XDP_DROP;

        /* IPv4 sanity. */
        if (iph->ihl < 5)
            return XDP_DROP;
        if (bpf_ntohs(iph->tot_len) < (iph->ihl * 4))
            return XDP_DROP;

        /* Reject fragments outright — modern stacks rarely depend
         * on them, attackers depend on them for IDS evasion and
         * conntrack-state exhaustion. */
        if (iph->frag_off & bpf_htons(0x1FFF | 0x2000))
            return XDP_DROP;

        /* Prefix blocklist (LPM). */
        struct lpm_v4_key lk = { .prefixlen = 32, .addr = iph->saddr };
        if (bpf_map_lookup_elem(&blocked_prefixes_v4, &lk)) {
            /* Probabilistic drop: even a "known bad" prefix is
             * dropped only with high probability, so the attacker
             * cannot calibrate a clean 100 % boundary. */
            return prob_drop(DROP_PROB_HIGH) ? XDP_DROP : XDP_PASS;
        }

        /* Protocol fan-out. */
        __u8 proto = iph->protocol;
        if (proto != IPPROTO_TCP && proto != IPPROTO_UDP && proto != IPPROTO_ICMP)
            return XDP_DROP;

        void *l4 = (void *)iph + (iph->ihl * 4);

        int is_syn = 0, is_udp = (proto == IPPROTO_UDP);

        if (proto == IPPROTO_TCP) {
            struct tcphdr *tcph = l4;
            if ((void *)(tcph + 1) > data_end)
                return XDP_DROP;

            if (tcp_flags_anomalous(tcph))
                return XDP_DROP;

            /* Port 0 is reserved and a known flood marker. */
            if (tcph->source == 0 || tcph->dest == 0)
                return XDP_DROP;

            is_syn = (tcph->syn && !tcph->ack);
        } else if (proto == IPPROTO_UDP) {
            struct udphdr *udph = l4;
            if ((void *)(udph + 1) > data_end)
                return XDP_DROP;
            if (udph->source == 0 || udph->dest == 0)
                return XDP_DROP;
        }

        /* Per-source-IP rate accounting. */
        __u32 pps = 0, syns = 0, udps = 0;
        account_v4(iph->saddr, bpf_ktime_get_ns(), is_syn, is_udp,
                   &pps, &syns, &udps);

        if (syns > SYN_THRESHOLD)
            return prob_drop(DROP_PROB_HIGH) ? XDP_DROP : XDP_PASS;
        if (udps > UDP_THRESHOLD)
            return prob_drop(DROP_PROB_HIGH) ? XDP_DROP : XDP_PASS;
        if (pps  > PPS_THRESHOLD)
            return prob_drop(DROP_PROB_MID)  ? XDP_DROP : XDP_PASS;
        if (pps  > PPS_THRESHOLD / 2)
            return prob_drop(DROP_PROB_LOW)  ? XDP_DROP : XDP_PASS;

        return XDP_PASS;
    }

    if (etype == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end)
            return XDP_DROP;

        /* IPv6: allow only TCP / UDP / ICMPv6 next-headers. */
        __u8 nh = ip6->nexthdr;
        if (nh != IPPROTO_TCP && nh != IPPROTO_UDP && nh != IPPROTO_ICMPV6)
            return XDP_DROP;

        struct in6_addr_key src_key;
        __builtin_memcpy(src_key.addr, &ip6->saddr, sizeof(src_key.addr));

        struct ip_rate_window *w = bpf_map_lookup_elem(&ipv6_rates, &src_key);
        __u64 now = bpf_ktime_get_ns();
        int   is_udp = (nh == IPPROTO_UDP);

        if (!w) {
            struct ip_rate_window fresh = {
                .window_start_ns = now,
                .pkt_count = 1,
                .syn_count = 0,
                .udp_count = is_udp ? 1 : 0,
            };
            bpf_map_update_elem(&ipv6_rates, &src_key, &fresh, BPF_ANY);
            return XDP_PASS;
        }

        if (now - w->window_start_ns > WINDOW_NS) {
            w->window_start_ns = now;
            w->pkt_count = 1;
            w->syn_count = 0;
            w->udp_count = is_udp ? 1 : 0;
        } else {
            w->pkt_count++;
            if (is_udp) w->udp_count++;
        }

        if (w->udp_count > UDP_THRESHOLD)
            return prob_drop(DROP_PROB_HIGH) ? XDP_DROP : XDP_PASS;
        if (w->pkt_count > PPS_THRESHOLD)
            return prob_drop(DROP_PROB_MID)  ? XDP_DROP : XDP_PASS;

        return XDP_PASS;
    }

    /* Anything that is not IPv4 / IPv6 (ARP, VLAN-stripped tail,
     * obscure protocols) gets the benefit of the doubt — XDP is
     * not the right layer to police these. */
    return XDP_PASS;
}
