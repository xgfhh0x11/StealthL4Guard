#!/usr/bin/env bash
# kernel-test/load.sh — SAFETY-GATED attach of the BPF programs.
#
# Default behaviour is DRY-RUN: it only PRINTS the commands it would run.
# Nothing is attached unless you pass --arm.
#
# The attach target defaults to the isolated test veth created by
# netns-up.sh (veth-l4g-ns, inside netns l4guard_test) and refuses any
# other interface unless you explicitly pass --host-iface <name>.
#
#   DRY RUN (default, safe):
#     kernel-test/load.sh
#
#   Actually attach, to the test veth (safe — isolated netns):
#     kernel-test/load.sh --arm
#
#   Actually attach to some other interface (NOT recommended, requires
#   both flags and, for anything that doesn't look like a test veth, an
#   extra explicit environment-variable acknowledgement):
#     kernel-test/load.sh --arm --host-iface eth0
#
# NEVER pass --host-iface pointing at a real NIC, a management interface,
# or anything else you rely on for connectivity to this box. A broken or
# misconfigured XDP program can silently blackhole all traffic on the
# interface it is attached to, with no feedback to the sender (that is
# the program's designed behaviour — see bpf/xdp_l4_guard.c header
# comment "No feedback. No RST. No ICMP.").

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BPF_DIR="$REPO_ROOT/bpf"

NETNS="l4guard_test"
VETH_NS="veth-l4g-ns"
VETH_HOST="veth-l4g-h"

XDP_OBJ="$BPF_DIR/xdp_l4_guard.o"
XDP_SEC="xdp_guard"     # SEC() name in bpf/xdp_l4_guard.c
TC_OBJ="$BPF_DIR/tc_l4_guard.o"
TC_SEC="tc_ingress"     # SEC() name in bpf/tc_l4_guard.c

ARM=0
TARGET_IFACE="$VETH_NS"
HOST_IFACE_GIVEN=0

usage() {
    sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
    case "$1" in
        --arm) ARM=1; shift ;;
        --host-iface)
            [ $# -ge 2 ] || { echo "ERROR: --host-iface needs a value" >&2; exit 1; }
            TARGET_IFACE="$2"; HOST_IFACE_GIVEN=1; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; usage; exit 1 ;;
    esac
done

# Refuse anything but the known test veth unless the escape hatch was used.
if [ "$TARGET_IFACE" != "$VETH_NS" ] && [ "$HOST_IFACE_GIVEN" -ne 1 ]; then
    echo "Refusing to attach to '$TARGET_IFACE': not the isolated test veth ($VETH_NS)." >&2
    echo "Pass --host-iface $TARGET_IFACE explicitly if you really intend this." >&2
    exit 1
fi

# Extra guard: anything that doesn't look like one of our own veths needs an
# explicit written acknowledgement via env var, even with --host-iface.
case "$TARGET_IFACE" in
    "$VETH_NS"|"$VETH_HOST") : ;;
    *)
        if [ "${I_UNDERSTAND_THIS_MAY_BREAK_HOST_NETWORKING:-}" != "yes" ]; then
            echo "REFUSING: '$TARGET_IFACE' is not one of this harness's test veths." >&2
            echo "This looks like a real interface. If you are certain, re-run with:" >&2
            echo "  I_UNDERSTAND_THIS_MAY_BREAK_HOST_NETWORKING=yes $0 --arm --host-iface $TARGET_IFACE" >&2
            exit 1
        fi
        echo "!! Proceeding against non-test interface '$TARGET_IFACE' (acknowledged via env var). !!"
        ;;
esac

for f in "$XDP_OBJ" "$TC_OBJ"; do
    if [ ! -s "$f" ]; then
        echo "ERROR: $f not found or empty. Run kernel-test/build-bpf.sh first." >&2
        exit 1
    fi
done

# Namespace-scoped targets run via `ip netns exec`; a --host-iface target
# outside the namespace (e.g. veth-l4g-h, or an acknowledged real NIC) runs
# directly on the host.
in_netns=1
case "$TARGET_IFACE" in
    "$VETH_NS") in_netns=1 ;;
    *) in_netns=0 ;;
esac

ns_prefix=()
[ "$in_netns" -eq 1 ] && ns_prefix=(ip netns exec "$NETNS")

XDP_CMD=("${ns_prefix[@]}" ip link set dev "$TARGET_IFACE" xdpgeneric object "$XDP_OBJ" section "$XDP_SEC")
TC_QDISC_CMD=("${ns_prefix[@]}" tc qdisc add dev "$TARGET_IFACE" clsact)
TC_FILTER_CMD=("${ns_prefix[@]}" tc filter add dev "$TARGET_IFACE" ingress bpf da obj "$TC_OBJ" sec "$TC_SEC")

print_cmd() { printf '  sudo'; printf ' %q' "$@"; printf '\n'; }

echo "== load.sh =="
echo "target interface : $TARGET_IFACE"
echo "netns             : $([ "$in_netns" -eq 1 ] && echo "$NETNS" || echo "(host, no netns)")"
echo "xdp object/section: $XDP_OBJ  [$XDP_SEC]"
echo "tc object/section : $TC_OBJ  [$TC_SEC]"
echo
echo "Planned commands:"
print_cmd "${XDP_CMD[@]}"
print_cmd "${TC_QDISC_CMD[@]}"
print_cmd "${TC_FILTER_CMD[@]}"

if [ "$ARM" -ne 1 ]; then
    echo
    echo "DRY-RUN (default) — nothing was attached."
    echo "Re-run with --arm to actually load these programs."
    exit 0
fi

echo
echo "ARMED — attaching for real."
sudo "${XDP_CMD[@]}"
sudo "${TC_QDISC_CMD[@]}" || echo "  (clsact qdisc add failed/exists — continuing)"
sudo "${TC_FILTER_CMD[@]}"
echo
echo "Attached XDP[$XDP_SEC] and TC[$TC_SEC] on $TARGET_IFACE."
echo "Verify with kernel-test/verify.sh; remove with kernel-test/teardown.sh."
