"""Mark-protocol consistency — the whole pipeline communicates through a
single byte of skb->mark. The TC eBPF program *writes* the marks and the
nftables ruleset *interprets* them; if the two drift (e.g. someone
renumbers MARK_KILL) the kernel verifier won't catch it and traffic is
silently mishandled. This test pins the contract.

Constants: bpf/tc_l4_guard.c   #define MARK_GREY/MARK_KILL
Interpreter: config/nftables.conf  `meta mark 0x.. ... drop`
"""
import os
import re

import pytest


def _read(repo_root, *rel):
    with open(os.path.join(repo_root, *rel), "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _defined_mark(src, name):
    m = re.search(rf"#define\s+{name}\s+(0x[0-9A-Fa-f]+|\d+)", src)
    assert m, f"{name} not #defined in tc_l4_guard.c"
    return int(m.group(1), 0)


@pytest.fixture(scope="module")
def marks(repo_root):
    src = _read(repo_root, "bpf", "tc_l4_guard.c")
    return {
        "GREY": _defined_mark(src, "MARK_GREY"),
        "KILL": _defined_mark(src, "MARK_KILL"),
        "NONE": _defined_mark(src, "MARK_NONE"),
    }


def test_marks_fit_in_one_byte(marks):
    for name, val in marks.items():
        assert 0 <= val <= 0xFF, f"MARK_{name}=0x{val:x} does not fit in skb->mark's byte"


def test_marks_are_distinct(marks):
    vals = list(marks.values())
    assert len(set(vals)) == len(vals), f"mark values collide: {marks}"


def test_nftables_interprets_both_actionable_marks(repo_root, marks):
    """Every actionable mark the TC program emits (GREY, KILL) must have a
    matching `meta mark <val> ... drop` rule in the nftables ruleset."""
    nft = _read(repo_root, "config", "nftables.conf")
    dropped = {
        int(m.group(1), 16)
        for m in re.finditer(r"meta\s+mark\s+0x([0-9A-Fa-f]+)\b[^\n]*\bdrop\b", nft)
    }
    assert marks["KILL"] in dropped, (
        f"MARK_KILL=0x{marks['KILL']:x} has no drop rule in nftables.conf (dropped={[hex(d) for d in dropped]})"
    )
    assert marks["GREY"] in dropped, (
        f"MARK_GREY=0x{marks['GREY']:x} has no drop rule in nftables.conf (dropped={[hex(d) for d in dropped]})"
    )


def test_kill_is_unconditional_grey_is_probabilistic(repo_root, marks):
    """KILL = hard drop; GREY = probabilistic drop. The GREY rule must
    carry a `random` qualifier, the KILL rule must not."""
    nft = _read(repo_root, "config", "nftables.conf")
    kill_line = next((ln for ln in nft.splitlines() if re.search(rf"meta\s+mark\s+0x0*{marks['KILL']:x}\b", ln)), "")
    grey_line = next((ln for ln in nft.splitlines() if re.search(rf"meta\s+mark\s+0x0*{marks['GREY']:x}\b", ln)), "")
    assert "drop" in kill_line and "random" not in kill_line, f"KILL rule should be an unconditional drop: {kill_line!r}"
    assert "random" in grey_line and "drop" in grey_line, f"GREY rule should be a probabilistic drop: {grey_line!r}"
