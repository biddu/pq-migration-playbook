"""Acceptance tests for Labs 8.1 and 8.2.

Lab 8.2 (LMS) tests run offline against RFC 8554 Test Case 1 and against the lab's own keys.
Lab 8.1 (signbench) tests need liboqs for the SLH-DSA rows and are skipped if it is absent;
the ML-DSA and LMS rows always run.
"""
import importlib
import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent.parent
use_solution = os.environ.get("PQ_LAB_IMPL", "starter") == "solution"
sys.path.insert(0, str(HERE / "solution"))
if not use_solution:
    sys.path.insert(0, str(HERE))
try:
    lms = importlib.import_module("lms" if use_solution else "starter_lms")
except ModuleNotFoundError:
    lms = importlib.import_module("lms")


# ---------------------------------------------------------------- Lab 8.2: LMS correctness

def test_rfc8554_test_case_1_verifies():
    tv = json.loads((HERE / "fixtures" / "rfc8554_tc1.json").read_text())
    assert lms.hss_verify(bytes.fromhex(tv["public_key"]), bytes.fromhex(tv["message"]), bytes.fromhex(tv["signature"]))


def test_rfc8554_rejects_tampered_message():
    tv = json.loads((HERE / "fixtures" / "rfc8554_tc1.json").read_text())
    bad = bytes.fromhex(tv["message"])[:-1] + b"\x00"
    assert not lms.hss_verify(bytes.fromhex(tv["public_key"]), bad, bytes.fromhex(tv["signature"]))


def test_sign_verify_roundtrip_and_index_advances():
    k = lms.LmsPrivateKey(lms_type=5, ots_type=4)
    s0, s1 = k.sign(b"a"), k.sign(b"b")
    assert lms.lms_verify(k.public_key, b"a", s0) and lms.lms_verify(k.public_key, b"b", s1)
    assert int.from_bytes(s0[:4], "big") == 0 and int.from_bytes(s1[:4], "big") == 1     # q advanced
    assert not lms.lms_verify(k.public_key, b"a", s1)                                    # signatures are message-bound


def test_key_refuses_to_exhaust():
    k = lms.LmsPrivateKey(lms_type=5, ots_type=4)          # 32 signatures
    for i in range(32):
        k.sign(f"m{i}".encode())
    with pytest.raises(lms.ExhaustedKey):
        k.sign(b"one too many")


# ---------------------------------------------------------------- Lab 8.2: the failure and the fix

def test_reused_one_time_key_enables_forgery():
    key = lms.ForgetfulLmsPrivateKey(lms_type=5, ots_type=4)
    snap = key.snapshot()
    reused = []
    for v in ("1.0", "1.1", "1.2", "1.3", "1.4", "1.5"):
        key.restore(snap)
        m = f"firmware {v}".encode()
        reused.append((m, key.sign(m)))
    assert len({s[:4] for _, s in reused}) == 1                                          # all the same q
    target = b"malicious firmware"
    forged, tries, expected = lms.forge_after_reuse(key.public_key, reused, target, max_tries=2_000_000)
    assert forged is not None and lms.lms_verify(key.public_key, target, forged)         # public info alone forges


def test_single_signature_gives_no_forgery():
    key = lms.ForgetfulLmsPrivateKey(lms_type=5, ots_type=4)
    m = b"firmware 1.0"
    sig = key.sign(m)
    with pytest.raises(ValueError):
        lms.forge_after_reuse(key.public_key, [(m, sig)], b"malicious", max_tries=1000)


def test_committed_state_never_reuses_across_restart():
    with tempfile.TemporaryDirectory() as d:
        state = Path(d) / "s.json"
        k = lms.CommittedLmsPrivateKey(state, reservation=8, lms_type=5, ots_type=4)
        pub = k.public_key
        q_before = [int.from_bytes(k.sign(f"m{i}".encode())[:4], "big") for i in range(3)]
        del k
        k2 = lms.CommittedLmsPrivateKey(state)
        assert k2.public_key == pub
        q_after = [int.from_bytes(k2.sign(f"n{i}".encode())[:4], "big") for i in range(3)]
        assert min(q_after) > max(q_before)                                              # a gap, never a repeat
        assert len(set(q_before) & set(q_after)) == 0


# ---------------------------------------------------------------- Lab 8.1: sizes

def test_lms_size_formula_matches_signature():
    k = lms.LmsPrivateKey(lms_type=5, ots_type=4)
    sz = lms.sizes(5, 4)
    assert len(k.sign(b"x")) == sz["signature"] and len(k.public_key) == sz["public_key"]


def test_ml_dsa_sizes_are_fips204():
    from cryptography.hazmat.primitives.asymmetric import mldsa
    k = mldsa.MLDSA65PrivateKey.generate()
    assert len(k.public_key().public_bytes_raw()) == 1952
    assert len(k.sign(b"artefact")) == 3309


@pytest.mark.skipif(importlib.util.find_spec("oqs") is None, reason="liboqs not installed")
def test_slh_dsa_128s_signature_size():
    import oqs
    s = oqs.Signature("SLH_DSA_PURE_SHA2_128S")
    pk = s.generate_keypair()
    sig = s.sign(b"artefact")
    assert len(pk) == 32 and len(sig) == 7856
