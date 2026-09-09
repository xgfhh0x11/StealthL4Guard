#!/usr/bin/env bash
# kernel-test/teardown.sh
#
# Detaches the BPF programs and removes the test netns + veth pair.
# Idempotent and safe to run even if nothing was set up (or only
# partially set up) — every step ignores "already gone" errors.
# Deleting the host-side veth also removes its netns-side peer.

set -uo pipefail

NETNS="l4guard_test"
VETH_HOST="veth-l4g-h"
VETH_NS="veth-l4g-ns"

echo "== detaching TC (netns side, $VETH_NS) =="
sudo ip netns exec "$NETNS" tc filter del dev "$VETH_NS" ingress 2>/dev/null || true
sudo ip netns exec "$NETNS" tc qdisc del dev "$VETH_NS" clsact 2>/dev/null || true

echo "== detaching XDP (netns side, $VETH_NS) =="
sudo ip netns exec "$NETNS" ip link set dev "$VETH_NS" xdpgeneric off 2>/dev/null || true
sudo ip netns exec "$NETNS" ip link set dev "$VETH_NS" xdp off 2>/dev/null || true

echo "== detaching TC/XDP on host-side veth ($VETH_HOST), in case --host-iface was used =="
sudo tc filter del dev "$VETH_HOST" ingress 2>/dev/null || true
sudo tc qdisc del dev "$VETH_HOST" clsact 2>/dev/null || true
sudo ip link set dev "$VETH_HOST" xdpgeneric off 2>/dev/null || true
sudo ip link set dev "$VETH_HOST" xdp off 2>/dev/null || true

echo "== removing veth pair (also removes the netns-side peer) =="
sudo ip link del "$VETH_HOST" 2>/dev/null || true

echo "== removing netns =="
sudo ip netns del "$NETNS" 2>/dev/null || true

echo "== cleaning up verify.sh scratch files inside the (now-gone) netns' pid namespace =="
rm -f /tmp/l4g_tcp_recv.txt /tmp/l4g_udp_recv.txt 2>/dev/null || true

echo "Teardown complete: netns '$NETNS' and veths '$VETH_HOST'/'$VETH_NS' removed (if present)."
echo "Reminder: this NEVER touched any real host interface — only the test veth pair."
