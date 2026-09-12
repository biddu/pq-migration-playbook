"""Acceptance tests for Labs 7.1-7.3.

Lab 7.1 tests build real hierarchies and need OpenSSL 3.5+ (OPENSSL_BIN / LD_LIBRARY_PATH);
they are skipped otherwise. Lab 7.3's protocol tests run offline; the Pebble test runs only
if something is listening on 127.0.0.1:14000 (see pebble/run.sh).
"""
import importlib
import json
import os
import socket
import subprocess
import sys
from datetime import date
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent.parent
use_solution = os.environ.get("PQ_LAB_IMPL", "starter") == "solution"
sys.path.insert(0, str(HERE / "solution"))
if not use_solution:
    sys.path.insert(0, str(HERE))
try:
    pki = importlib.import_module("pkilab" if use_solution else "starter_pkilab")
except ModuleNotFoundError:
    pki = importlib.import_module("pkilab")
renewal = importlib.import_module("renewal")
acme = importlib.import_module("acmeclient")


def openssl_ok() -> bool:
    try:
        out = subprocess.run([pki.OPENSSL, "version"], capture_output=True, text=True, timeout=10).stdout
        ver = out.split()[1].split("(")[0]
        return tuple(int(x) for x in ver.split(".")[:2]) >= (3, 5)
    except Exception:
        return False


needs_openssl = pytest.mark.skipif(not openssl_ok(), reason="OpenSSL 3.5+ not found (set OPENSSL_BIN)")


# ---------------------------------------------------------------- Lab 7.1

def test_newkey_args_forms():
    assert pki.newkey_args("ML-DSA-65") == ["-newkey", "ML-DSA-65"]
    assert pki.newkey_args("ec:P-256") == ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256"]


@needs_openssl
def test_mldsa65_hierarchy_sizes_and_validation():
    h = pki.build("mldsa65", crl_entries=100)
    assert h.server.key_alg == "MLDSA65" and h.server.sig_alg == "ML-DSA-65"
    assert h.server.public_key_bytes == 1952 and h.server.signature_bytes == 3309          # Chapter 2's numbers, in a certificate
    assert 5500 <= h.server.der_bytes <= 5800                                              # ~5.6 KB per certificate
    assert h.chain_bytes_sent_by_server == h.server.der_bytes + h.issuing.der_bytes
    assert 11000 <= h.chain_bytes_sent_by_server <= 11600
    assert h.openssl_verify == "OK" and h.python_verify.startswith("OK")
    assert h.crl_bytes_empty > 3300 and h.crl_bytes_n > h.crl_bytes_empty + 100 * 15          # one signature, then ~20 B per entry


@needs_openssl
def test_ecdsa_baseline_is_an_order_of_magnitude_smaller():
    e = pki.build("ecdsa", crl_entries=100)
    assert e.chain_bytes_sent_by_server < 1100 and e.openssl_verify == "OK" and e.python_verify.startswith("OK")


@needs_openssl
def test_slh_dsa_root_verifies_in_openssl_and_records_python_result():
    h = pki.build("slh-root", crl_entries=10)
    assert h.openssl_verify == "OK"
    assert h.issuing.signature_bytes == 7856                                               # SLH-DSA-SHA2-128s signature on the issuing CA
    assert h.python_verify.startswith("OK") or "Forbidden" in h.python_verify or "Unsupported" in h.python_verify


@needs_openssl
def test_mixed_hierarchies_validate():
    for prof in ("pq-under-classical", "pq-ca-classical-leaf"):
        h = pki.build(prof, crl_entries=10)
        assert h.openssl_verify == "OK" and h.python_verify.startswith("OK"), prof


# ---------------------------------------------------------------- Lab 7.3: renewal arithmetic

def test_schedule_stages():
    assert renewal.stage_for(date(2026, 3, 14)) == (398, 398)
    assert renewal.stage_for(date(2026, 3, 15)) == (200, 200)
    assert renewal.stage_for(date(2027, 3, 15)) == (100, 100)
    assert renewal.stage_for(date(2029, 3, 15)) == (47, 10)


def test_renewal_point_and_repair_window():
    assert renewal.renewal_point(47) == (31, 16)
    assert renewal.renewal_point(398) == (265, 133)


# ---------------------------------------------------------------- Lab 7.3: ACME protocol pieces (offline)

def test_jws_signature_verifies_with_account_key():
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    import base64
    a = acme.Acme.__new__(acme.Acme)
    a.key = ec.generate_private_key(ec.SECP256R1()); a.kid = None; a.nonce = "abc"; a.calls = []
    jws = json.loads(a.sign("https://ca.test/new-acct", {"x": 1}))
    sig = base64.urlsafe_b64decode(jws["signature"] + "==")
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    a.key.public_key().verify(encode_dss_signature(r, s), f"{jws['protected']}.{jws['payload']}".encode(), ec.ECDSA(hashes.SHA256()))
    prot = json.loads(base64.urlsafe_b64decode(jws["protected"] + "=="))
    assert prot["alg"] == "ES256" and prot["nonce"] == "abc" and "jwk" in prot and "kid" not in prot


def test_challenge_server_serves_key_authorization():
    import urllib.request
    tokens = {"tok123": "tok123.thumb"}
    srv = acme.ChallengeServer(tokens, port=5099); srv.start()
    try:
        body = urllib.request.urlopen("http://127.0.0.1:5099/.well-known/acme-challenge/tok123", timeout=5).read()
        assert body == b"tok123.thumb"
        with pytest.raises(Exception):
            urllib.request.urlopen("http://127.0.0.1:5099/.well-known/acme-challenge/nope", timeout=5)
    finally:
        srv.stop()


def pebble_up() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", 14000), timeout=1):
            return True
    except OSError:
        return False


@pytest.mark.skipif(not pebble_up(), reason="Pebble not running on 127.0.0.1:14000")
def test_live_issue_against_pebble_and_reject_mldsa_csr():
    tokens = {}
    srv = acme.ChallengeServer(tokens); srv.start()
    try:
        a = acme.Acme(); a.new_account()
        r = acme.issue_once(a, "localhost", tokens, "P-256")
        assert r["lifetime_days"] in (46, 47) and r["chain_len"] == 2
        with pytest.raises(RuntimeError, match="badCSR|unimplemented"):
            acme.issue_once(a, "localhost", tokens, "ML-DSA-65")
    finally:
        srv.stop()
