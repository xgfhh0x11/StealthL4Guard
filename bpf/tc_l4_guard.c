// SPDX-License-Identifier: GPL-2.0
/*
 * StealthL4Guard — TC/eBPF flow-level behavioral classifier.
 *
 * Position: NIC → XDP → [TC/eBPF here] → nftables/raw → conntrack → HAProxy
 *
 * This program does NOT drop. It maintains a 5-tuple flow table,
 * computes a behavioral mark (NONE / GREY / KILL), and writes that
 * mark to skb->mark. The actual drop decision is made downstream
 * by nftables in the `rawguard` table, before conntrack creates state.
 *
 * The split is deliberate. TC owns *analysis*; nftables owns *kill*.
 * The two layers communicate exclusively through skb->mark.
 */

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

#define MARK_NONE 0x0
#define MARK_GREY 0x1
#define MARK_KILL 0x2

struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
} __attribute__((packed));

struct flow_stats {
    __u64 pkt_count;
    __u64 syn_count;
    __u64 ack_count;
    __u64 udp_count;
};

/*
 * LRU hash: flow_key -> flow_stats.
 *
 * Sized for 1 M concurrent flows. LRU eviction bounds memory and
 * provides implicit aging — flows quiescent for long enough are
 * evicted by newer ones. See README §"Limitations" for the
 * sliding-window improvement this approximates.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct flow_key);
    __type(value, struct flow_stats);
    __uint(max_entries, 1024 * 1024);
} flow_table SEC(".maps");

/*
 * compute_mark — behavioral classifier.
 *
 * Three signals:
 *   pkt_count    high  → volumetric flood
 *   udp_count    high  → UDP flood / amplification
 *   syn ≫ ack          → SYN flood / half-open exhaustion
 *
 * Thresholds are PoC defaults. Production deployments must
 * recalibrate per-tenant; see README §"Tuning".
 */
static __always_inline __u32 compute_mark(const struct flow_stats *st)
{
    if (st->pkt_count > 5000)
        return MARK_KILL;

    if (st->udp_count > 3000)
        return MARK_KILL;

    if (st->syn_count > 1000 && st->ack_count < st->syn_count / 10)
        return MARK_GREY;

    return MARK_NONE;
}

SEC("tc_ingress")
int tc_l4_guard(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    /* This layer covers IPv4 TCP/UDP only. IPv6 is handled at the
     * XDP layer (see xdp_l4_guard.c); the IPv6 flow path is a
     * documented next step (README §"Limitations"). */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;

    if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
        return TC_ACT_OK;

    __u8  proto    = iph->protocol;
    __u32 src_ip   = iph->saddr;
    __u32 dst_ip   = iph->daddr;
    __u16 src_port = 0, dst_port = 0;

    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)(iph + 1);
        if ((void *)(tcph + 1) > data_end)
            return TC_ACT_OK;
        src_port = tcph->source;
        dst_port = tcph->dest;
    } else { /* IPPROTO_UDP */
        struct udphdr *udph = (void *)(iph + 1);
        if ((void *)(udph + 1) > data_end)
            return TC_ACT_OK;
        src_port = udph->source;
        dst_port = udph->dest;
    }

    struct flow_key key = {
        .src_ip   = src_ip,
        .dst_ip   = dst_ip,
        .src_port = src_port,
        .dst_port = dst_port,
        .proto    = proto,
    };

    struct flow_stats *st = bpf_map_lookup_elem(&flow_table, &key);
    struct flow_stats  new_st = {};

    if (!st) {
        /* New flow. */
        new_st.pkt_count = 1;

        if (proto == IPPROTO_TCP) {
            struct tcphdr *tcph = (void *)(iph + 1);
            if ((void *)(tcph + 1) > data_end)
                return TC_ACT_OK;

            if (tcph->syn && !tcph->ack)
                new_st.syn_count = 1;
            else if (tcph->ack)
                new_st.ack_count = 1;
        } else {
            new_st.udp_count = 1;
        }

        bpf_map_update_elem(&flow_table, &key, &new_st, BPF_ANY);
        st = &new_st;
    } else {
        /* Existing flow — in-place update on map value, shared
         * across RSS CPUs that can process packets from the same
         * flow concurrently. Use atomic fetch-and-add instead of a
         * plain "++" so concurrent CPUs don't clobber each other's
         * read-modify-write and silently lose increments. This does
         * not make the whole struct update a single atomic
         * transaction (a reader can still observe pkt_count bumped
         * before syn_count/ack_count/udp_count), which is acceptable
         * for these statistical thresholds; a fully race-free design
         * would use BPF_MAP_TYPE_PERCPU_HASH instead. See README. */
        __sync_fetch_and_add(&st->pkt_count, 1);

        if (proto == IPPROTO_TCP) {
            struct tcphdr *tcph = (void *)(iph + 1);
            if ((void *)(tcph + 1) > data_end)
                return TC_ACT_OK;

            if (tcph->syn && !tcph->ack)
                __sync_fetch_and_add(&st->syn_count, 1);
            else if (tcph->ack)
                __sync_fetch_and_add(&st->ack_count, 1);
        } else {
            __sync_fetch_and_add(&st->udp_count, 1);
        }
    }

    __u32 mark = compute_mark(st);
    if (mark == MARK_GREY || mark == MARK_KILL)
        skb->mark = mark;

    /* The TC layer never drops. Pass on to nftables/raw, which
     * interprets skb->mark and performs the silent kill. */
    return TC_ACT_OK;
}
