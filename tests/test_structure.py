"""Structure check — asserts the repository layout the README documents:
the two eBPF programs, the build glue, the nftables + HAProxy configs,
and the design doc. Pure-Python; no toolchain required."""
import os

import pytest

EXPECTED = [
    "bpf/xdp_l4_guard.c",
    "bpf/tc_l4_guard.c",
    "bpf/Makefile",
    "config/nftables.conf",
    "config/haproxy.cfg",
    "docs/architecture-deep-dive.md",
    ".github/workflows/build.yml",
]


@pytest.mark.parametrize("rel", EXPECTED)
def test_path_present(repo_root, rel):
    assert os.path.isfile(os.path.join(repo_root, *rel.split("/"))), f"missing {rel}"
