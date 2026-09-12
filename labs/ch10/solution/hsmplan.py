"""Lab 10.2 solution -- size a post-quantum key estate against an HSM's storage and throughput
ceilings, and see what the seed form does to backup and ceremony.

Every number about the *algorithms* here is from FIPS 203/204/205, RFC 8554 and the classical
standards, in bytes. Every number about the *HSM* (object-store size, signatures per second)
is a parameter you must take from your vendor's data sheet or, better, measure; the defaults
are illustrative and labelled as such. The tool makes three things visible:

  1. Storage: the same key count costs 10-60x more object storage in expanded post-quantum
     form, and about the same as today in seed form (ML-KEM 64 B, ML-DSA 32 B). Whether your
     HSM stores seeds or expanded keys (PKCS#11 3.2 CKA_SEED vs CKA_VALUE) is a capacity question.
  2. Throughput: a signing service sized in ECDSA operations per second needs re-sizing; the
     ratio is the HSM's ML-DSA rate over its ECDSA rate, and only the vendor knows it.
  3. Ceremony and backup: a backup blob of N expanded ML-DSA-65 keys is 4 KB per key; of N
     seeds it is 32 B per key, and a Shamir share of a seed is the same size it was for an
     ECDSA key. Seeds keep the ceremony you already have.

Also included: mu_offload(), the ML-DSA external-mu pattern (FIPS 204 section 6.2). The host
computes the 64-byte message representative mu = H(tr || M') with the public key's tr, and
the HSM signs mu alone, never seeing the message. AWS KMS exposes this as MessageType
EXTERNAL_MU for messages over 4 KB; PKCS#11 3.2 exposes the pre-hash variants as
CKM_HASH_ML_DSA_*. The pattern is what keeps large-artefact signing off the HSM's link.

Tested with: Python 3.12, cryptography 50.0.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]

# (public key bytes, expanded private key bytes, seed-form private key bytes or None)
KEY_BYTES = {
    "ECDSA P-256":   (65, 32, None),
    "RSA-3072":      (387, 1_700, None),          # PKCS#1 private key DER, approximate
    "ML-KEM-768":    (1_184, 2_400, 64),
    "ML-KEM-1024":   (1_568, 3_168, 64),
    "ML-DSA-44":     (1_312, 2_560, 32),
    "ML-DSA-65":     (1_952, 4_032, 32),
    "ML-DSA-87":     (2_592, 4_896, 32),
    "SLH-DSA-128s":  (32, 64, None),              # the private key is already seed-sized
    "LMS H20/W8":    (56, 52, None),              # seed 32 + I 16 + q 4; the tree is recomputed or cached
}
OBJECT_OVERHEAD = 256                             # per-object attribute template, label, handles: illustrative


@dataclass
class Estate:
    name: str
    keys: dict[str, int]                          # algorithm -> count


def storage(estate: Estate, seed_form: bool) -> tuple[int, dict[str, int]]:
    per = {}
    for alg, n in estate.keys.items():
        pk, sk, seed = KEY_BYTES[alg]
        priv = seed if (seed_form and seed is not None) else sk
        per[alg] = n * (pk + priv + OBJECT_OVERHEAD)
    return sum(per.values()), per


def throughput(need_ops_per_s: float, ecdsa_rate: float, pq_rate: float) -> dict:
    """How many HSMs a signing load needs, classical vs post-quantum, given the vendor's rates."""
    import math
    return {"ecdsa_hsms": math.ceil(need_ops_per_s / ecdsa_rate), "pq_hsms": math.ceil(need_ops_per_s / pq_rate),
            "ratio": round(ecdsa_rate / pq_rate, 1)}


def backup(estate: Estate) -> dict:
    exp, _ = storage(estate, seed_form=False)
    seed, _ = storage(estate, seed_form=True)
    n_shares, threshold = 5, 3
    return {"backup_blob_expanded_bytes": exp, "backup_blob_seed_bytes": seed,
            "shamir_share_bytes_per_key_seed_form": 32 + 1,        # a share of a 32-byte secret plus its index, as for ECDSA today
            "shamir_share_bytes_per_key_expanded_ml_dsa_65": 4_032 + 1,
            "shares": n_shares, "threshold": threshold}


def mu_offload(message: bytes) -> dict:
    """The external-mu pattern: hash on the host, sign 64 bytes in the 'HSM'."""
    from cryptography.hazmat.primitives.asymmetric import mldsa
    hsm_key = mldsa.MLDSA65PrivateKey.generate()                  # lives in the module
    pk = hsm_key.public_key()
    h = mldsa.MLDSAMuHasher(pk)                                    # host side: needs only the public key
    for i in range(0, len(message), 1 << 20):
        h.update(message[i:i + (1 << 20)])
    mu = h.finalize()
    sig = hsm_key.sign_mu(mu)                                      # module side: 64 bytes in, 3,309 out
    pk.verify(sig, message)                                        # any verifier checks against the full message
    return {"message_bytes": len(message), "bytes_sent_to_hsm": len(mu), "signature_bytes": len(sig), "verified": True}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Size a post-quantum key estate against HSM storage and throughput.")
    p.add_argument("--object-store-bytes", type=int, default=64 * 1024 * 1024, help="token object store capacity (vendor figure; default illustrative 64 MiB)")
    p.add_argument("--ecdsa-rate", type=float, default=10_000, help="vendor ECDSA P-256 signatures/s per HSM (illustrative default)")
    p.add_argument("--pq-rate", type=float, default=1_500, help="vendor ML-DSA-65 signatures/s per HSM (illustrative default; ask)")
    p.add_argument("--need", type=float, default=4_000, help="peak signatures/s the estate needs")
    a = p.parse_args(argv)

    estate = Estate("PQM Payments (Chapter 1 running example)", {
        "ECDSA P-256": 12_000, "RSA-3072": 800,                     # today's TLS leaves, code-signing, KEKs
        "ML-KEM-768": 6_000, "ML-DSA-65": 12_000, "ML-DSA-87": 40, "SLH-DSA-128s": 4, "LMS H20/W8": 6,
    })
    exp_total, exp_per = storage(estate, seed_form=False)
    seed_total, seed_per = storage(estate, seed_form=True)
    print(f"estate: {estate.name}\n")
    print(f"{'algorithm':<14} {'count':>7} {'pk B':>6} {'sk exp B':>9} {'seed B':>7} {'store expanded':>15} {'store seed-form':>16}")
    for alg, n in estate.keys.items():
        pk, sk, seed = KEY_BYTES[alg]
        print(f"{alg:<14} {n:>7} {pk:>6} {sk:>9} {(seed if seed else '-'):>7} {exp_per[alg]:>15,} {seed_per[alg]:>16,}")
    print(f"{'total':<14} {sum(estate.keys.values()):>7} {'':>6} {'':>9} {'':>7} {exp_total:>15,} {seed_total:>16,}")
    print(f"\nobject store {a.object_store_bytes:,} B: expanded form uses {100 * exp_total / a.object_store_bytes:.0f}%, "
          f"seed form {100 * seed_total / a.object_store_bytes:.0f}%  (whether CKA_SEED or CKA_VALUE is stored is a firmware question)")
    t = throughput(a.need, a.ecdsa_rate, a.pq_rate)
    print(f"\nthroughput: {a.need:,.0f} sig/s needed; at {a.ecdsa_rate:,.0f} ECDSA/s -> {t['ecdsa_hsms']} HSM(s); "
          f"at {a.pq_rate:,.0f} ML-DSA-65/s -> {t['pq_hsms']} HSM(s)  (ratio {t['ratio']}x; both rates are vendor figures to verify)")
    b = backup(estate)
    print(f"\nbackup blob: expanded {b['backup_blob_expanded_bytes']:,} B, seed form {b['backup_blob_seed_bytes']:,} B; "
          f"a Shamir share of a seed is {b['shamir_share_bytes_per_key_seed_form']} B per key (same as ECDSA today), "
          f"of an expanded ML-DSA-65 key {b['shamir_share_bytes_per_key_expanded_ml_dsa_65']:,} B")
    import os
    m = mu_offload(os.urandom(8 * 1024 * 1024))
    print(f"\nexternal mu: {m['message_bytes']:,}-byte artefact hashed on the host, {m['bytes_sent_to_hsm']} bytes sent to the module, "
          f"{m['signature_bytes']}-byte signature back, verified against the full message: {m['verified']}")
    (HERE / "results").mkdir(exist_ok=True)
    (HERE / "results" / "hsmplan.json").write_text(json.dumps({"estate": estate.keys, "storage_expanded": exp_per, "storage_seed": seed_per,
                                                              "throughput": t, "backup": b, "mu": m}, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
