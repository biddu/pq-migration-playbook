"""Lab 2.1 solution -- the size and speed table.

Measures, on the machine it runs on, the byte sizes and median operation times of
the classical algorithms being replaced and the post-quantum algorithms replacing
them, and writes results/table.md. Sizes are deterministic and are asserted by the
acceptance tests against FIPS 203/204/205; timings are machine-dependent.

Two libraries:
  cryptography >= 48   ML-KEM-768/1024, ML-DSA-44/65/87, X25519, Ed25519 (production-grade)
  liboqs-python 0.16   ML-KEM-512, SLH-DSA, FN-DSA (draft, as Falcon), HQC (prototyping only)

Tested with: Python 3.12, cryptography 50.0, liboqs 0.16.
"""
from __future__ import annotations

import statistics
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa, mlkem, x25519

try:
    import oqs
except ImportError:          # liboqs is optional; the table is still useful without it
    oqs = None

MSG = b"post-quantum migration"
N = 200


def median_us(fn, n: int = N) -> float:
    t = []
    for _ in range(n):
        s = time.perf_counter()
        fn()
        t.append(time.perf_counter() - s)
    return statistics.median(t) * 1e6


@dataclass
class Row:
    alg: str
    kind: str            # KEM or SIG
    category: str        # NIST security category, or 'classical'
    pk: int
    sk: int
    payload: int         # ciphertext for a KEM, signature for a signature scheme
    op1_us: float        # keygen
    op2_us: float        # encapsulate / sign
    op3_us: float        # decapsulate / verify
    source: str


# ------------------------------------------------------------- classical baselines

def x25519_row() -> Row:
    """X25519 wrapped as a KEM: the ephemeral public key is the 'ciphertext'."""
    sk = x25519.X25519PrivateKey.generate()
    pk = sk.public_key()

    def encaps():
        eph = x25519.X25519PrivateKey.generate()
        return eph.exchange(pk), eph.public_key().public_bytes_raw()

    ss, ct = encaps()
    eph_pub = x25519.X25519PublicKey.from_public_bytes(ct)
    return Row("X25519", "KEM", "classical", len(pk.public_bytes_raw()), len(sk.private_bytes_raw()), len(ct),
               median_us(x25519.X25519PrivateKey.generate), median_us(encaps),
               median_us(lambda: sk.exchange(eph_pub)), "cryptography")


def ed25519_row() -> Row:
    sk = ed25519.Ed25519PrivateKey.generate()
    pk = sk.public_key()
    sig = sk.sign(MSG)
    return Row("Ed25519", "SIG", "classical", len(pk.public_bytes_raw()), len(sk.private_bytes_raw()), len(sig),
               median_us(ed25519.Ed25519PrivateKey.generate), median_us(lambda: sk.sign(MSG)),
               median_us(lambda: pk.verify(sig, MSG)), "cryptography")


# ------------------------------------------------------------- cryptography PQ

def mlkem_row(name: str, cls, category: str) -> Row:
    sk = cls.generate()
    pk = sk.public_key()
    ss, ct = pk.encapsulate()
    assert sk.decapsulate(ct) == ss
    return Row(name, "KEM", category, len(pk.public_bytes_raw()), len(sk.private_bytes_raw()), len(ct),
               median_us(cls.generate), median_us(pk.encapsulate), median_us(lambda: sk.decapsulate(ct)),
               "cryptography (sk = 64-byte seed)")


def mldsa_row(name: str, cls, category: str) -> Row:
    sk = cls.generate()
    pk = sk.public_key()
    sig = sk.sign(MSG)
    pk.verify(sig, MSG)
    return Row(name, "SIG", category, len(pk.public_bytes_raw()), len(sk.private_bytes_raw()), len(sig),
               median_us(cls.generate), median_us(lambda: sk.sign(MSG)), median_us(lambda: pk.verify(sig, MSG)),
               "cryptography (sk = 32-byte seed)")


# ------------------------------------------------------------- liboqs

def oqs_kem_row(name: str, category: str, label: str | None = None) -> Row:
    with oqs.KeyEncapsulation(name) as server:
        pk = server.generate_keypair()
        d = server.details
        with oqs.KeyEncapsulation(name) as client:
            ct, ss = client.encap_secret(pk)
            assert server.decap_secret(ct) == ss
            return Row(label or name, "KEM", category, d["length_public_key"], d["length_secret_key"],
                       d["length_ciphertext"],
                       median_us(lambda: oqs.KeyEncapsulation(name).generate_keypair(), 50),
                       median_us(lambda: client.encap_secret(pk), 50),
                       median_us(lambda: server.decap_secret(ct), 50), "liboqs")


def oqs_sig_row(name: str, category: str, label: str | None = None, n: int = 20) -> Row:
    with oqs.Signature(name) as signer:
        pk = signer.generate_keypair()
        d = signer.details
        sig = signer.sign(MSG)
        with oqs.Signature(name) as verifier:
            assert verifier.verify(MSG, sig, pk)
            return Row(label or name, "SIG", category, d["length_public_key"], d["length_secret_key"],
                       d["length_signature"],
                       median_us(lambda: oqs.Signature(name).generate_keypair(), n),
                       median_us(lambda: signer.sign(MSG), n),
                       median_us(lambda: verifier.verify(MSG, sig, pk), n), "liboqs")


# ------------------------------------------------------------- table

def build_rows(include_oqs: bool = True) -> list[Row]:
    rows = [
        x25519_row(),
        mlkem_row("ML-KEM-768", mlkem.MLKEM768PrivateKey, "3"),
        mlkem_row("ML-KEM-1024", mlkem.MLKEM1024PrivateKey, "5"),
        ed25519_row(),
        mldsa_row("ML-DSA-44", mldsa.MLDSA44PrivateKey, "2"),
        mldsa_row("ML-DSA-65", mldsa.MLDSA65PrivateKey, "3"),
        mldsa_row("ML-DSA-87", mldsa.MLDSA87PrivateKey, "5"),
    ]
    if include_oqs and oqs is not None:
        rows.insert(1, oqs_kem_row("ML-KEM-512", "1"))
        rows += [
            oqs_sig_row("SLH_DSA_PURE_SHA2_128S", "1", "SLH-DSA-SHA2-128s", n=5),
            oqs_sig_row("SLH_DSA_PURE_SHA2_128F", "1", "SLH-DSA-SHA2-128f", n=5),
            oqs_sig_row("SLH_DSA_PURE_SHA2_192S", "3", "SLH-DSA-SHA2-192s", n=3),
            oqs_sig_row("SLH_DSA_PURE_SHA2_256S", "5", "SLH-DSA-SHA2-256s", n=3),
            oqs_sig_row("Falcon-512", "1", "FN-DSA-512 (draft; Falcon-512)"),
            oqs_sig_row("Falcon-1024", "5", "FN-DSA-1024 (draft; Falcon-1024)"),
            oqs_kem_row("HQC-3", "3", "HQC-3 (selected; no FIPS yet)"),
        ]
    return rows


def to_markdown(rows: list[Row]) -> str:
    head = ("| Algorithm | Kind | Cat. | Public key (B) | Secret key (B) | Ciphertext / signature (B) "
            "| Keygen (us) | Encaps / sign (us) | Decaps / verify (us) | Source |")
    sep = "|---|---|---|---:|---:|---:|---:|---:|---:|---|"
    body = [f"| {r.alg} | {r.kind} | {r.category} | {r.pk:,} | {r.sk:,} | {r.payload:,} "
            f"| {r.op1_us:,.0f} | {r.op2_us:,.0f} | {r.op3_us:,.0f} | {r.source} |" for r in rows]
    return "\n".join([head, sep, *body])


def main(out: str | None = None) -> int:
    rows = build_rows()
    md = to_markdown(rows)
    print(md)
    out_path = Path(out) if out else Path(__file__).resolve().parents[1] / "results" / "table.md"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(md + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
