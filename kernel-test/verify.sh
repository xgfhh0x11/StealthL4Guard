#!/usr/bin/env bash
# kernel-test/verify.sh
#
# Confirms the attached programs are present and exercises them with real
# traffic into the isolated test netns, then re-reads the BPF maps to
# check for evidence the programs actually ran.
#
# IMPORTANT (per repo review): neither bpf/xdp_l4_guard.c nor
# bpf/tc_l4_guard.c contains a single bpf_printk(), and there is no
# dedicated drop/reason counter map. The only observability available is:
#   - bpftool prog show / map dump on the four maps that do exist
#     (blocked_prefixes_v4, ipv4_rates, ipv6_rates, flow_table)
#   - packet loss observed from outside (ping/nc), since a drop is silent
#     by design ("No feedback. No RST. No ICMP.")
# This script does both: it dumps the maps before/after traffic, and it
# runs traffic so you can see loss/success directly. It does NOT and
# cannot assert "packet X was dropped because of rule Y" — that
# instrumentation does not exist in this codebase (see review G5).

set -uo pipefail

NETNS="l4guard_test"
VETH_NS="veth-l4g-ns"
HOST_IP="10.200.1.1"
NS_IP="10.200.1.2"

need() { command -v "$1" >/dev/null 2>&1; }

if ! need bpftool; then
    echo "ERROR: bpftool not found. Install with:" >&2
    echo "  sudo apt-get update && sudo apt-get install -y linux-tools-common linux-tools-generic" >&2
    exit 1
fi

echo "======================================================================"
echo "== bpftool prog show (host) =="
echo "======================================================================"
sudo bpftool prog show

echo
echo "======================================================================"
echo "== bpftool prog show (inside netns $NETNS) =="
echo "======================================================================"
sudo ip netns exec "$NETNS" bpftool prog show 2>&1

echo
echo "======================================================================"
echo "== bpftool map dump — BEFORE traffic =="
echo "======================================================================"
for m in ipv4_rates ipv6_rates blocked_prefixes_v4 flow_table; do
    echo "-- map: $m --"
    sudo bpftool map dump name "$m" 2>&1
    echo
done

echo "======================================================================"
echo "== generating test traffic into $NETNS =="
echo "======================================================================"

echo "-- ICMP: host -> ns ($HOST_IP -> $NS_IP), 5 packets --"
sudo ping -c 5 -i 0.2 -W 1 "$NS_IP" || echo "  (some/all pings failed or were dropped)"

echo
echo "-- ICMP: ns -> host ($NS_IP -> $HOST_IP), 5 packets --"
sudo ip netns exec "$NETNS" ping -c 5 -i 0.2 -W 1 "$HOST_IP" || echo "  (some/all pings failed or were dropped)"

echo
echo "-- TCP: host -> ns:9000 (nc), 3s session --"
sudo ip netns exec "$NETNS" sh -c 'timeout 3 nc -l 9000 >/tmp/l4g_tcp_recv.txt 2>&1 &'
sleep 0.4
echo "hello-tcp" | sudo timeout 2 nc -w 2 "$NS_IP" 9000 || echo "  (tcp send failed or was dropped)"
sleep 0.3
echo "  received in ns: $(sudo ip netns exec "$NETNS" cat /tmp/l4g_tcp_recv.txt 2>/dev/null || echo '(nothing)')"

echo
echo "-- UDP: host -> ns:9001 (nc -u), one datagram --"
sudo ip netns exec "$NETNS" sh -c 'timeout 3 nc -u -l 9001 >/tmp/l4g_udp_recv.txt 2>&1 &'
sleep 0.4
echo "hello-udp" | sudo timeout 2 nc -u -w 1 "$NS_IP" 9001 || true
sleep 0.3
echo "  received in ns: $(sudo ip netns exec "$NETNS" cat /tmp/l4g_udp_recv.txt 2>/dev/null || echo '(nothing)')"

echo
echo "======================================================================"
echo "== bpftool map dump — AFTER traffic =="
echo "======================================================================"
for m in ipv4_rates flow_table; do
    echo "-- map: $m --"
    sudo bpftool map dump name "$m" 2>&1
    echo
done

echo "======================================================================"
echo "== interpretation =="
echo "======================================================================"
cat <<'EOF'
- If XDP is attached on veth-l4g-ns: a nonzero pkt_count entry keyed on
  10.200.1.1 (0x0A_C8_01_01 in the map's raw big/little-endian dump) in
  ipv4_rates confirms xdp_l4_guard ran account_v4() on real packets.
- If TC is attached: a nonzero entry in flow_table for the 5-tuple
  (10.200.1.1, 10.200.1.2, tcp/udp, ports 9000/9001) confirms
  tc_l4_guard ran on real packets.
- ping/nc failures above are only meaningful as "the program dropped
  this" if you already know the program's thresholds — with the
  DROP_PROB_* / SYN_THRESHOLD / PPS_THRESHOLD / pkt_count>5000 defaults
  in the source, a handful of ICMP/TCP/UDP packets in a fresh netns
  should all PASS. Persistent test flows (see review finding B5 —
  tc_l4_guard.c permanently KILLs any flow once pkt_count > 5000, with
  no decay) will eventually be blocked; that is expected, not a bug in
  this harness.
- There is no bpf_printk / dmesg trace and no drop-reason map to
  consult (review finding G5) — map deltas and observed packet
  loss are the only signal this codebase currently provides.
EOF
