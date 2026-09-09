#!/usr/bin/env bash
# kernel-test/netns-up.sh
#
# Creates an isolated network namespace + veth pair for BPF testing.
# NEVER touches a real/host interface. Idempotent: safe to re-run.
#
#   host netns                              l4guard_test netns
#   +----------------------+                +----------------------+
#   | veth-l4g-h            |<---veth pair-->| veth-l4g-ns           |
#   | 10.200.1.1/24          |                | 10.200.1.2/24          |
#   +----------------------+                +----------------------+
#
# XDP/TC programs are attached (by load.sh) to veth-l4g-ns, inside the
# namespace, never to any interface carrying real host traffic.

set -uo pipefail

NETNS="l4guard_test"
VETH_HOST="veth-l4g-h"
VETH_NS="veth-l4g-ns"
HOST_IP="10.200.1.1/24"
NS_IP="10.200.1.2/24"

if [ "$(id -u)" -ne 0 ] && ! command -v sudo >/dev/null 2>&1; then
    echo "ERROR: need root or sudo to manage network namespaces." >&2
    exit 1
fi
RUN="sudo"
[ "$(id -u)" -eq 0 ] && RUN=""

if ip netns list 2>/dev/null | grep -qw "$NETNS"; then
    echo "netns '$NETNS' already exists — reusing."
else
    echo "creating netns '$NETNS'"
    $RUN ip netns add "$NETNS"
fi

if ip link show "$VETH_HOST" >/dev/null 2>&1; then
    echo "veth '$VETH_HOST' already exists on the host — reusing."
else
    echo "creating veth pair $VETH_HOST <-> $VETH_NS"
    $RUN ip link add "$VETH_HOST" type veth peer name "$VETH_NS"
    $RUN ip link set "$VETH_NS" netns "$NETNS"
fi

# If the ns side didn't get moved for some reason (partial prior state),
# fail loudly rather than silently testing against nothing.
if ! $RUN ip netns exec "$NETNS" ip link show "$VETH_NS" >/dev/null 2>&1; then
    echo "ERROR: '$VETH_NS' is not present inside netns '$NETNS'." >&2
    echo "       Run kernel-test/teardown.sh first, then retry." >&2
    exit 1
fi

echo "assigning addresses and bringing links up"
$RUN ip addr replace "$HOST_IP" dev "$VETH_HOST"
$RUN ip link set "$VETH_HOST" up
$RUN ip netns exec "$NETNS" ip addr replace "$NS_IP" dev "$VETH_NS"
$RUN ip netns exec "$NETNS" ip link set "$VETH_NS" up
$RUN ip netns exec "$NETNS" ip link set lo up

echo
echo "Ready."
echo "  netns:        $NETNS"
echo "  host side:    $VETH_HOST  $HOST_IP"
echo "  namespace side: $VETH_NS  $NS_IP  (this is where load.sh attaches XDP/TC)"
echo
echo "Sanity check:"
$RUN ip netns exec "$NETNS" ping -c 2 -W 1 10.200.1.1 && echo "  ping OK (ns -> host)" || echo "  ping FAILED — check the above output"
