"""Acceptance tests for Labs 9.1 and 9.2. All offline; need cryptography >= 48."""
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


def load(name):
    try:
        return importlib.import_module(name if use_solution else f"starter_{name}")
    except ModuleNotFoundError:
        return importlib.import_module(name)


xwing = load("xwing")
jws = load("jws_mldsa")
env = importlib.import_module("envelope")     # envelope.py has no starter; it imports xwing from solution/ on its own path


# ---------------------------------------------------------------- Lab 9.1: X-Wing

def test_xwing_keygen_matches_draft_test_vector():
    tv = json.loads((HERE / "fixtures" / "xwing_tv1.json").read_text())
    _, pk = xwing.generate_keypair(bytes.fromhex(tv["sk"]))
    assert pk.hex() == tv["pk"]


def test_xwing_decapsulation_matches_draft_test_vector():
    tv = json.loads((HERE / "fixtures" / "xwing_tv1.json").read_text())
    assert xwing.decapsulate(bytes.fromhex(tv["sk"]), bytes.fromhex(tv["ct"])).hex() == tv["ss"]


def test_xwing_round_trip_and_sizes():
    sk, pk = xwing.generate_keypair()
    ss, ct = xwing.encapsulate(pk)
    assert (len(sk), len(pk), len(ct), len(ss)) == (32, 1216, 1120, 32)
    assert xwing.decapsulate(sk, ct) == ss


def test_xwing_tampered_ciphertext_gives_different_secret_not_error():
    sk, pk = xwing.generate_keypair()
    ss, ct = xwing.encapsulate(pk)
    bad = bytes([ct[0] ^ 1]) + ct[1:]                          # flip a bit in the ML-KEM part
    assert xwing.decapsulate(sk, bad) != ss                    # implicit rejection: no exception, wrong key


def test_combiner_binds_both_secrets_and_transcript():
    a = xwing.combiner(b"\x01" * 32, b"\x02" * 32, b"\x03" * 32, b"\x04" * 32)
    assert a != xwing.combiner(b"\x00" * 32, b"\x02" * 32, b"\x03" * 32, b"\x04" * 32)   # ML-KEM secret matters
    assert a != xwing.combiner(b"\x01" * 32, b"\x00" * 32, b"\x03" * 32, b"\x04" * 32)   # X25519 secret matters
    assert a != xwing.combiner(b"\x01" * 32, b"\x02" * 32, b"\x00" * 32, b"\x04" * 32)   # ciphertext is bound


# ---------------------------------------------------------------- Lab 9.1: envelope and re-key

def test_rekey_rewrites_headers_only_and_objects_still_decrypt():
    with tempfile.TemporaryDirectory() as d:
        old = env.Kek.generate("rsa3072", "old"); new = env.Kek.generate("xwing", "new")
        paths = env.make_dataset(Path(d), old, n=5, size=4096)
        bodies_before = [p.with_suffix(".bin").read_bytes() for p in paths]
        r = env.rekey(paths, old, new)
        assert r["header_bytes_written"] == sum(len(p.read_bytes()) for p in paths)
        assert [p.with_suffix(".bin").read_bytes() for p in paths] == bodies_before          # bodies untouched
        plain = env.decrypt_object(new, paths[0].read_bytes(), paths[0].with_suffix(".bin").read_bytes())
        assert len(plain) == 4096
        with pytest.raises(KeyError):
            env.decrypt_object(old, paths[0].read_bytes(), paths[0].with_suffix(".bin").read_bytes())


def test_shred_makes_objects_unrecoverable():
    with tempfile.TemporaryDirectory() as d:
        k = env.Kek.generate("mlkem768", "k")
        paths = env.make_dataset(Path(d), k, n=1, size=100)
        env.shred(k)
        with pytest.raises(env.ShreddedKey):
            env.decrypt_object(k, paths[0].read_bytes(), paths[0].with_suffix(".bin").read_bytes())


# ---------------------------------------------------------------- Lab 9.2: ML-DSA JWS

@pytest.mark.parametrize("alg,raw_sig", [("ES256", 64), ("EdDSA", 64), ("ML-DSA-44", 2420), ("ML-DSA-65", 3309), ("ML-DSA-87", 4627)])
def test_issue_and_verify_round_trip(alg, raw_sig):
    s = jws.Signer(alg)
    tok = jws.issue(s, jws.id_token_claims())
    claims = jws.verify(s.public_jwk(), tok)
    assert claims["sub"] == "248289761001"
    assert len(jws.b64d(tok.split(".")[2])) == raw_sig


def test_akp_jwk_shape_per_rfc9964():
    s = jws.Signer("ML-DSA-65")
    jwk = s.public_jwk()
    assert jwk["kty"] == "AKP" and jwk["alg"] == "ML-DSA-65" and len(jws.b64d(jwk["pub"])) == 1952
    assert "priv" not in jwk


def test_tampered_token_fails():
    s = jws.Signer("ML-DSA-44")
    tok = jws.issue(s, jws.id_token_claims())
    h, p, sig = tok.split(".")
    bad = jws.b64u(json.dumps({"sub": "attacker"}).encode())
    with pytest.raises(Exception):
        jws.verify(s.public_jwk(), f"{h}.{bad}.{sig}")


def test_ml_dsa_65_token_does_not_fit_a_cookie_but_44_does():
    claims = jws.id_token_claims()
    t44 = jws.issue(jws.Signer("ML-DSA-44"), claims); t65 = jws.issue(jws.Signer("ML-DSA-65"), claims)
    assert jws.fits(len(t44))["cookie (RFC 6265 min)"] is True
    assert jws.fits(len(t65))["cookie (RFC 6265 min)"] is False
    assert jws.fits(len(t65))["nginx header line"] is True
