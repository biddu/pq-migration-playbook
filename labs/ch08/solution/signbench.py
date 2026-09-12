"""Lab 8.1 solution -- sign and verify release artefacts with every signature family the
chapter discusses, and tabulate what a bootloader or package manager would have to store,
transfer and compute.

Algorithms (implementation):
  Ed25519, ECDSA P-256, RSA-3072          cryptography (classical baselines)
  ML-DSA-44 / 65 / 87                     cryptography (FIPS 204)
  SLH-DSA-SHA2-128s / 128f / 192s / 256s  liboqs (FIPS 205; "s" = small signature, slow sign; "f" = fast)
  LMS H10/W8, H10/W4, H5/W8               labs/ch08/solution/lms.py (RFC 8554, SP 800-208); H20 reported by
                                          formula, since its 1,048,576-leaf keygen is impractical in Python

Artefacts: a 4 KiB boot header and a 4 MiB firmware image of random bytes. Every scheme
signs the artefact bytes directly (pure mode); the hash of the artefact is part of the
cost, and for the 4 MiB image it dominates the classical rows, which is the point.

Timing is wall-clock on the host, median of N runs. Absolute numbers do not transfer to a
microcontroller; ratios to the Ed25519 row roughly do, and the "hash calls to verify" column
for the hash-based schemes is exact and platform-independent.

Tested with: Python 3.11/3.12, cryptography 50.0, liboqs-python 0.16.
"""
from __future__ import annotations

import json
import os
import statistics
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, mldsa, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lms  # noqa: E402

HERE = Path(__file__).resolve().parents[1]
RUNS = int(os.environ.get("SIGNBENCH_RUNS", "7"))


def median_ms(fn, runs=RUNS) -> float:
    ts = []
    for _ in range(runs):
        t0 = time.perf_counter(); fn(); ts.append((time.perf_counter() - t0) * 1000)
    return statistics.median(ts)


# ---- adapters: each returns dict(name, family, pk, sig(msg), verify(msg, sig), keygen_ms, note)

def classical(name):
    if name == "Ed25519":
        t0 = time.perf_counter(); k = ed25519.Ed25519PrivateKey.generate(); kg = (time.perf_counter() - t0) * 1000
        pk = k.public_key(); pkb = pk.public_bytes_raw()
        return dict(name=name, family="classical", pk=len(pkb), keygen_ms=kg, sign=k.sign, verify=lambda m, s: pk.verify(s, m))
    if name == "ECDSA P-256":
        t0 = time.perf_counter(); k = ec.generate_private_key(ec.SECP256R1()); kg = (time.perf_counter() - t0) * 1000
        pk = k.public_key()
        return dict(name=name, family="classical", pk=65, keygen_ms=kg, sign=lambda m: k.sign(m, ec.ECDSA(hashes.SHA256())),
                    verify=lambda m, s: pk.verify(s, m, ec.ECDSA(hashes.SHA256())))
    if name == "RSA-3072":
        t0 = time.perf_counter(); k = rsa.generate_private_key(65537, 3072); kg = (time.perf_counter() - t0) * 1000
        pk = k.public_key(); pad = padding.PSS(padding.MGF1(hashes.SHA256()), 32)
        return dict(name=name, family="classical", pk=384 + 3, keygen_ms=kg, sign=lambda m: k.sign(m, pad, hashes.SHA256()),
                    verify=lambda m, s: pk.verify(s, m, pad, hashes.SHA256()))
    raise KeyError(name)


def ml_dsa(level: int):
    cls = {44: mldsa.MLDSA44PrivateKey, 65: mldsa.MLDSA65PrivateKey, 87: mldsa.MLDSA87PrivateKey}[level]
    t0 = time.perf_counter(); k = cls.generate(); kg = (time.perf_counter() - t0) * 1000
    pk = k.public_key()
    return dict(name=f"ML-DSA-{level}", family="lattice", pk=len(pk.public_bytes_raw()), keygen_ms=kg,
                sign=k.sign, verify=lambda m, s: pk.verify(s, m))


def slh_dsa(param: str):
    import oqs
    mech = f"SLH_DSA_PURE_SHA2_{param.upper()}"
    signer = oqs.Signature(mech)
    t0 = time.perf_counter(); pkb = signer.generate_keypair(); kg = (time.perf_counter() - t0) * 1000
    verifier = oqs.Signature(mech)
    return dict(name=f"SLH-DSA-SHA2-{param}", family="hash (stateless)", pk=len(pkb), keygen_ms=kg,
                sign=signer.sign, verify=lambda m, s: (verifier.verify(m, s, pkb) or (_ for _ in ()).throw(ValueError("bad"))))


def lms_scheme(lms_type: int, ots_type: int):
    t0 = time.perf_counter(); k = lms.LmsPrivateKey(lms_type=lms_type, ots_type=ots_type); kg = (time.perf_counter() - t0) * 1000
    sz = lms.sizes(lms_type, ots_type)
    name = f"LMS {lms.LMS_NAME[lms_type].split('_')[-1]}/{lms.LMOTS_NAME[ots_type].split('_')[-1]}"
    return dict(name=name, family="hash (stateful)", pk=len(k.public_key), keygen_ms=kg,
                sign=k.sign, verify=lambda m, s: (lms.lms_verify(k.public_key, m, s) or (_ for _ in ()).throw(ValueError("bad"))),
                capacity=sz["capacity"], hashes_verify=sz["hashes_to_verify_max"])


def bench(scheme: dict, artefacts: dict[str, bytes]) -> dict:
    row = {"name": scheme["name"], "family": scheme["family"], "pk_bytes": scheme["pk"], "keygen_ms": round(scheme["keygen_ms"], 2),
           "capacity": scheme.get("capacity"), "hashes_verify_max": scheme.get("hashes_verify")}
    for label, data in artefacts.items():
        sig = scheme["sign"](data)
        scheme["verify"](data, sig)                                  # must not raise
        row[f"sig_bytes"] = len(sig)
        row[f"sign_ms_{label}"] = round(median_ms(lambda: scheme["sign"](data)), 3)
        row[f"verify_ms_{label}"] = round(median_ms(lambda: scheme["verify"](data, sig)), 3)
    return row


def table(rows: list[dict]) -> str:
    head = (f"{'scheme':<22} {'family':<17} {'pk B':>6} {'sig B':>7} {'keygen ms':>10} {'sign 4K ms':>10} {'verify 4K ms':>12} "
            f"{'sign 4M ms':>10} {'verify 4M ms':>12} {'sigs/key':>9}")
    out = [head, "-" * len(head)]
    for r in rows:
        cap = "unlimited" if r["capacity"] is None else f"{r['capacity']:,}"
        out.append(f"{r['name']:<22} {r['family']:<17} {r['pk_bytes']:>6} {r['sig_bytes']:>7} {r['keygen_ms']:>10.1f} "
                   f"{r['sign_ms_4K']:>10.2f} {r['verify_ms_4K']:>12.3f} {r['sign_ms_4M']:>10.1f} {r['verify_ms_4M']:>12.2f} {cap:>9}")
    return "\n".join(out)


def main() -> int:
    artefacts = {"4K": os.urandom(4096), "4M": os.urandom(4 * 1024 * 1024)}
    schemes = [classical("Ed25519"), classical("ECDSA P-256"), classical("RSA-3072"),
               ml_dsa(44), ml_dsa(65), ml_dsa(87),
               slh_dsa("128s"), slh_dsa("128f"), slh_dsa("192s"), slh_dsa("256s"),
               lms_scheme(5, 4), lms_scheme(6, 4), lms_scheme(6, 3)]
    rows = []
    for sc in schemes:
        r = bench(sc, artefacts); rows.append(r)
        print(f"{r['name']:<22} pk {r['pk_bytes']:>5} B  sig {r['sig_bytes']:>6} B  sign(4K) {r['sign_ms_4K']:>8.2f} ms  verify(4K) {r['verify_ms_4K']:>7.3f} ms")
    # H20/W8 by formula: same signature layout, 20 path nodes; keygen = 2^20 leaves
    sz = lms.sizes(8, 4)
    rows.append({"name": "LMS H20/W8 (formula)", "family": "hash (stateful)", "pk_bytes": sz["public_key"], "sig_bytes": sz["signature"],
                 "keygen_ms": float("nan"), "capacity": sz["capacity"], "hashes_verify_max": sz["hashes_to_verify_max"],
                 "sign_ms_4K": float("nan"), "verify_ms_4K": float("nan"), "sign_ms_4M": float("nan"), "verify_ms_4M": float("nan")})
    print("\n" + table(rows))
    out = HERE / "results" / "signbench.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(rows, indent=2) + "\n")
    print(f"\nwritten {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
