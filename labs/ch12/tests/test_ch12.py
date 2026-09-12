"""Acceptance tests for Labs 12.1-12.3. Offline; the interop matrix and the full test-plan run are
exercised by their own scripts (they need OpenSSL 3.5 and Go), while these tests check the detector's
statistics, the toy targets, and the report renderers on fixed data."""
import importlib
import json
import os
import random
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
use_solution = os.environ.get("PQ_LAB_IMPL", "starter") == "solution"
sys.path.insert(0, str(HERE / "solution"))
if not use_solution:
    sys.path.insert(0, str(HERE))
try:
    timing = importlib.import_module("timing" if use_solution else "starter_timing")
except ModuleNotFoundError:
    timing = importlib.import_module("timing")
interop = importlib.import_module("interop")
testplan = importlib.import_module("testplan")


# ---------------------------------------------------------------- Lab 12.2: the detector

def test_welch_t_separates_shifted_distributions_and_not_identical_ones():
    rng = random.Random(1)
    a = [rng.gauss(100, 10) for _ in range(5000)]
    b = [rng.gauss(103, 10) for _ in range(5000)]
    c = [rng.gauss(100, 10) for _ in range(5000)]
    assert abs(timing.welch_t(a, b)) > timing.T_THRESHOLD
    assert abs(timing.welch_t(a, c)) < timing.T_THRESHOLD


def test_crop_keeps_lowest_fraction():
    xs = list(range(100))
    assert timing.crop(xs, 0.9) == list(range(90))


def test_measure_flags_a_leaky_function_and_clears_a_constant_one():
    def leaky(x):                      # work proportional to the input class
        s = 0
        for _ in range(x * 200):
            s += 1
        return s
    r = timing.measure(leaky, [1], [3], n=400, warmup=10)
    assert r["leak"] is True and abs(r["t"]) > timing.T_THRESHOLD
    r2 = timing.measure(lambda x: sum(range(300)), [1], [3], n=400, warmup=10)
    assert r2["leak"] is False


def test_toy_kem_round_trip_and_rejection_paths_give_different_keys():
    toy = timing.ToyKEM()
    k, ct = toy.encapsulate()
    assert toy.decaps_leaky(ct) == k and toy.decaps_ct(ct) == k
    bad = timing.flip(ct, 3)
    assert toy.decaps_leaky(bad) != k and toy.decaps_ct(bad) != k
    assert toy.decaps_ct(bad) == toy.decaps_ct(bad)                   # deterministic rejection key


def test_early_exit_compare_is_correct_but_leaky_by_construction():
    assert timing.leaky_compare(b"a" * 32, b"a" * 32) and not timing.leaky_compare(b"a" * 32, b"b" + b"a" * 31)


# ---------------------------------------------------------------- Lab 12.1 / 12.3: renderers

def test_interop_render_marks_negotiated_mismatch_and_unsupported():
    rows = []
    for g in interop.GROUPS:
        for s in interop.IMPLS:
            for c in interop.IMPLS:
                rows.append({"server": s, "client": c, "group": g, "status": "OK", "negotiated": g})
    rows[0]["negotiated"] = "X25519MLKEM768"                          # X25519 requested, hybrid negotiated
    rows[1]["status"] = "UNSUPPORTED"
    out = interop.render(rows)
    assert "OK(X25519MLKEM768)" in out and "n/s" in out and "X25519MLKEM768" in out


def test_testplan_render_counts_statuses():
    report = [{"section": "1", "check": "a", "status": "PASS", "detail": ""},
              {"section": "1", "check": "b", "status": "FAIL", "detail": "x"},
              {"section": "2", "check": "c", "status": "MANUAL", "detail": "attach"}]
    md = testplan.render(report)
    assert "| 1 | b | FAIL | x |" in md and "FAIL 1" in md and "PASS 1" in md and "MANUAL 1" in md


def test_lab_results_if_present_are_consistent():
    f = HERE / "results" / "timing.json"
    if f.exists():
        rows = json.loads(f.read_text())
        lib = [r for r in rows if "cryptography" in r["target"]]
        assert lib and not lib[0]["leak"]
        assert next(r for r in rows if "leaky" in r["target"])["leak"]
