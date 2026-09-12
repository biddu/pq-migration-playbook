"""Acceptance tests for Labs 10.1 and 10.2.

The header-parsing and mock-token tests are offline. The SoftHSM test runs if libsofthsm2.so is
installed and SOFTHSM2_CONF points at the lab's config (see README); otherwise it is skipped.
"""
import importlib
import os
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent.parent
use_solution = os.environ.get("PQ_LAB_IMPL", "starter") == "solution"
sys.path.insert(0, str(HERE / "solution"))
if not use_solution:
    sys.path.insert(0, str(HERE))
try:
    p11 = importlib.import_module("p11audit" if use_solution else "starter_p11audit")
except ModuleNotFoundError:
    p11 = importlib.import_module("p11audit")
plan = importlib.import_module("hsmplan")

SOFTHSM = "/usr/lib/softhsm/libsofthsm2.so"


# ---------------------------------------------------------------- Lab 10.1: the 3.2 header

def test_header_has_the_pq_constants():
    t = p11.parse_header()
    assert t["CKM"]["CKM_ML_KEM"] == 0x17 and t["CKM"]["CKM_ML_KEM_KEY_PAIR_GEN"] == 0x0F
    assert t["CKM"]["CKM_ML_DSA"] == 0x1D and t["CKM"]["CKM_HASH_ML_DSA_SHA512"] == 0x26
    assert t["CKM"]["CKM_SLH_DSA"] == 0x2E and t["CKM"]["CKM_HSS"] == 0x4033 and t["CKM"]["CKM_XMSS"] == 0x4036
    assert t["CKK"]["CKK_ML_KEM"] == 0x49 and t["CKK"]["CKK_ML_DSA"] == 0x4A and t["CKK"]["CKK_SLH_DSA"] == 0x4B
    assert t["CKP"]["CKP_ML_DSA_65"] == 2 and t["CKP"]["CKP_ML_KEM_768"] == 2
    assert t["CKA"]["CKA_PARAMETER_SET"] == 0x61D and t["CKA"]["CKA_SEED"] == 0x637
    assert t["CKF"]["CKF_ENCAPSULATE"] == 0x10000000 and t["CKF"]["CKF_DECAPSULATE"] == 0x20000000


def test_flag_names():
    t = p11.parse_header()
    names = p11.flag_names(t["CKF"]["CKF_ENCAPSULATE"] | t["CKF"]["CKF_DECAPSULATE"] | t["CKF"]["CKF_HW"], t["CKF"])
    assert names == ["CKF_HW", "CKF_ENCAPSULATE", "CKF_DECAPSULATE"]


# ---------------------------------------------------------------- Lab 10.1: audits

def test_mock_token_is_ready_and_requirements_line_names_the_standard():
    rep = p11.audit_mock(p11.parse_header())
    assert rep.required_missing == {} and rep.recommended_missing == {}
    assert rep.verdict.startswith("READY")
    line = p11.requirements_line(rep)
    assert "PKCS#11 v3.2" in line and "CKM_ML_KEM" in line and "FIPS 140-3" in line and "none" in line


def test_missing_flags_are_reported_not_just_missing_mechanisms():
    t = p11.parse_header()
    rep = p11.TokenReport("x", "m", "d", "1", "3.2", "t", "1")
    ckm = t["CKM"]
    rep.mechanisms = [p11.MechRow(ckm[n], n, fl) for n, fl in [
        ("CKM_ML_KEM_KEY_PAIR_GEN", ["CKF_GENERATE_KEY_PAIR"]), ("CKM_ML_KEM", ["CKF_ENCAPSULATE"]),        # no decapsulate!
        ("CKM_ML_DSA_KEY_PAIR_GEN", []), ("CKM_ML_DSA", ["CKF_SIGN", "CKF_VERIFY"]),
        ("CKM_HKDF_DERIVE", ["CKF_DERIVE"]), ("CKM_AES_KEY_WRAP_KWP", ["CKF_WRAP", "CKF_UNWRAP"])]]
    p11.finish(rep)
    assert rep.required_missing == {"CKM_ML_KEM": ["CKF_DECAPSULATE"]}
    assert rep.verdict.startswith("NOT READY")


def test_vendor_defined_mechanisms_change_the_verdict():
    t = p11.parse_header()
    rep = p11.TokenReport("x", "m", "d", "1", "2.40", "t", "1")
    rep.mechanisms = [p11.MechRow(0x80000101, "vendor-defined 0x80000101", ["CKF_SIGN"], vendor_defined=True)]
    p11.finish(rep)
    assert rep.verdict.startswith("NOT PORTABLE") and len(rep.required_missing) == len(p11.REQUIRED)


@pytest.mark.skipif(not (Path(SOFTHSM).exists() and os.environ.get("SOFTHSM2_CONF")), reason="SoftHSM not configured")
def test_softhsm_reports_no_pq_mechanisms():
    rep = p11.audit_real(SOFTHSM, None, p11.parse_header())
    assert rep.cryptoki_version.startswith("2.")
    assert "CKM_ML_DSA" in rep.required_missing and "CKM_ML_KEM" in rep.required_missing
    assert not any("ML_" in r.name for r in rep.mechanisms)


# ---------------------------------------------------------------- Lab 10.2: sizing and external mu

def test_storage_seed_form_is_much_smaller_for_lattice_keys():
    e = plan.Estate("t", {"ML-DSA-65": 1000, "ML-KEM-768": 1000})
    exp, _ = plan.storage(e, seed_form=False)
    seed, _ = plan.storage(e, seed_form=True)
    assert exp == 1000 * (1952 + 4032 + 256) + 1000 * (1184 + 2400 + 256)
    assert seed == 1000 * (1952 + 32 + 256) + 1000 * (1184 + 64 + 256)


def test_external_mu_signs_64_bytes_and_verifies_against_the_message():
    m = plan.mu_offload(b"firmware image " * 100_000)
    assert m["bytes_sent_to_hsm"] == 64 and m["signature_bytes"] == 3309 and m["verified"]


def test_throughput_rounds_up_hsm_count():
    t = plan.throughput(4000, 10_000, 1_500)
    assert t == {"ecdsa_hsms": 1, "pq_hsms": 3, "ratio": 6.7}
