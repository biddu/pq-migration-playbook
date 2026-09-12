"""Acceptance tests for Labs 2.1 and 2.2. Run:  pytest labs/ch02/tests
Set PQ_LAB_IMPL=solution to test the reference solutions instead of starter files."""
import importlib
import os
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent.parent
use_solution = os.environ.get("PQ_LAB_IMPL", "starter") == "solution"
sys.path.insert(0, str(HERE / "solution" if use_solution else HERE))


def load(starter_name, solution_name):
    try:
        return importlib.import_module(solution_name if use_solution else starter_name)
    except ModuleNotFoundError:
        sys.path.insert(0, str(HERE / "solution"))
        return importlib.import_module(solution_name)


sizes = load("starter_sizes", "sizes")
hybrid = load("starter_hybrid", "hybrid")

# FIPS 203 / 204 / 205 byte sizes. Secret keys from `cryptography` are seeds (64 / 32 B);
# expanded sizes are given in the chapter's Table 2.2.
EXPECTED = {
    "X25519":      dict(pk=32,   payload=32),
    "ML-KEM-768":  dict(pk=1184, payload=1088),
    "ML-KEM-1024": dict(pk=1568, payload=1568),
    "Ed25519":     dict(pk=32,   payload=64),
    "ML-DSA-44":   dict(pk=1312, payload=2420),
    "ML-DSA-65":   dict(pk=1952, payload=3309),
    "ML-DSA-87":   dict(pk=2592, payload=4627),
}
EXPECTED_OQS = {
    "ML-KEM-512":        dict(pk=800, payload=768),
    "SLH-DSA-SHA2-128s": dict(pk=32,  payload=7856),
    "SLH-DSA-SHA2-128f": dict(pk=32,  payload=17088),
}


@pytest.fixture(scope="module")
def rows():
    return {r.alg: r for r in sizes.build_rows(include_oqs=False)}


def test_all_core_algorithms_present(rows):
    assert set(EXPECTED) <= set(rows)


@pytest.mark.parametrize("alg", list(EXPECTED))
def test_sizes_match_fips(rows, alg):
    assert rows[alg].pk == EXPECTED[alg]["pk"]
    assert rows[alg].payload == EXPECTED[alg]["payload"]


def test_seed_format_private_keys(rows):
    assert rows["ML-KEM-768"].sk == 64
    assert rows["ML-DSA-65"].sk == 32


def test_mlkem768_encaps_under_one_millisecond(rows):
    assert rows["ML-KEM-768"].op2_us < 1000


def test_markdown_table_written(tmp_path, rows):
    md = sizes.to_markdown(list(rows.values()))
    assert md.startswith("| Algorithm") and "ML-DSA-65" in md


@pytest.mark.skipif(getattr(sizes, "oqs", None) is None, reason="liboqs not installed")
def test_oqs_sizes():
    got = {r.alg: r for r in sizes.build_rows(include_oqs=True)}
    for alg, exp in EXPECTED_OQS.items():
        assert got[alg].pk == exp["pk"] and got[alg].payload == exp["payload"]


# ---------------------------------------------------------------- Lab 2.2

def test_hybrid_key_shares_have_tls_sizes():
    c = hybrid.client_keygen()
    s_share, k_s = hybrid.server_encaps(c.key_share, b"t")
    assert len(c.key_share) == 1216 and len(s_share) == 1120 and len(k_s) == 32


def test_hybrid_agrees():
    c = hybrid.client_keygen()
    s_share, k_s = hybrid.server_encaps(c.key_share, b"t")
    assert hybrid.client_decaps(c, s_share, b"t") == k_s


def test_combiner_depends_on_both_halves_and_transcript():
    a, b, t = bytes(32), bytes([1]) * 32, b"transcript"
    k = hybrid.combine(a, b, t)
    assert hybrid.combine(a, b, t) == k                              # deterministic
    assert hybrid.combine(bytes([2]) * 32, b, t) != k                # ML-KEM half matters
    assert hybrid.combine(a, bytes([2]) * 32, t) != k                # X25519 half matters
    assert hybrid.combine(a, b, b"other") != k                       # transcript binds the key


def test_transcript_mismatch_breaks_agreement():
    c = hybrid.client_keygen()
    s_share, k_s = hybrid.server_encaps(c.key_share, b"t1")
    assert hybrid.client_decaps(c, s_share, b"t2") != k_s
