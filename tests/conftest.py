"""Shared fixtures: repo root. These tests are static (no kernel, no
libbpf) so they run anywhere — they check repo structure and that the
one-byte skb->mark protocol is consistent across the data-plane layers,
which the kernel verifier (the only other check) cannot catch."""
import os

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_HERE)


@pytest.fixture(scope="session")
def repo_root():
    return _REPO_ROOT
