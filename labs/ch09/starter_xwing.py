"""Lab 9.1 STARTER (part 1) -- X-Wing, the general-purpose hybrid KEM (X25519 + ML-KEM-768).

X-Wing is draft-connolly-cfrg-xwing-kem (CFRG), the hybrid KEM that HPKE's post-quantum
draft registers as KEM 0x647a and that Cloud KMS ships as its recommended KEM. It is the
same shape as the TLS hybrid in Chapter 5 but packaged as a KEM you can call from an
application: a 32-byte decapsulation key, a 1,216-byte encapsulation key, a 1,120-byte
ciphertext and a 32-byte shared secret, with the two component secrets bound together by
one SHA3-256 combiner over (ss_M, ss_X, ct_X, pk_X, label).

The combiner is the point of the lab. It is the concrete form of the SP 800-227 advice:
derive the final secret from *both* shared secrets *and* enough of the transcript that the
result is a KEM in its own right, IND-CCA secure as long as either component is.

Everything here is built from cryptography 50's ML-KEM-768, X25519, SHAKE256 and SHA3-256.
Key generation and decapsulation are checked against the draft's own test vector
(fixtures/xwing_tv1.json); encapsulation is randomised, so it is checked by round trip.

Tested with: Python 3.11/3.12, cryptography 50.0.

Complete the four functions marked TODO; the tests check key generation and decapsulation against the
draft's test vector and encapsulation by round trip. `PQ_LAB_IMPL=solution pytest labs/ch09/tests` runs the reference.
"""
from __future__ import annotations

import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import mlkem
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

XWING_LABEL = b"\\./" + b"/^\\"          # 6 bytes, hex 5c2e2f2f5e5c
assert XWING_LABEL.hex() == "5c2e2f2f5e5c"

SK_BYTES, PK_BYTES, CT_BYTES, SS_BYTES = 32, 1216, 1120, 32
PK_M, CT_M = 1184, 1088


def _shake256(data: bytes, n: int) -> bytes:
    h = hashes.Hash(hashes.SHAKE256(n)); h.update(data); return h.finalize()


def _sha3_256(data: bytes) -> bytes:
    h = hashes.Hash(hashes.SHA3_256()); h.update(data); return h.finalize()


def combiner(ss_m: bytes, ss_x: bytes, ct_x: bytes, pk_x: bytes) -> bytes:
    """TODO: SHA3-256 over ss_M || ss_X || ct_X || pk_X || XWING_LABEL"""
    raise NotImplementedError("combiner")



def expand_decapsulation_key(sk: bytes):
    """TODO: SHAKE256(sk, 96 bytes): first 64 -> MLKEM768PrivateKey.from_seed_bytes, last 32 -> X25519PrivateKey.from_private_bytes; return (sk_m, sk_x, pk_m raw, pk_x raw)"""
    raise NotImplementedError("expand_decapsulation_key")



def generate_keypair(sk: bytes | None = None) -> tuple[bytes, bytes]:
    """Returns (decapsulation key, encapsulation key). Pass sk for the derandomised variant."""
    sk = sk or secrets.token_bytes(SK_BYTES)
    _, _, pk_m, pk_x = expand_decapsulation_key(sk)
    return sk, pk_m + pk_x


def encapsulate(pk: bytes) -> tuple[bytes, bytes]:
    """TODO: ephemeral X25519 -> ct_x and ss_x with pk_x; ML-KEM-768 encapsulate to pk_m -> ss_m, ct_m; return (combiner(...), ct_m || ct_x)"""
    raise NotImplementedError("encapsulate")



def decapsulate(sk: bytes, ct: bytes) -> bytes:
    """TODO: split ct into 1088 + 32; ML-KEM decapsulate (implicit rejection), X25519 exchange; return combiner(...)"""
    raise NotImplementedError("decapsulate")



if __name__ == "__main__":
    sk, pk = generate_keypair()
    ss1, ct = encapsulate(pk)
    ss2 = decapsulate(sk, ct)
    print(f"X-Wing: sk {len(sk)} B, pk {len(pk)} B, ct {len(ct)} B, ss {len(ss1)} B, round trip {'OK' if ss1 == ss2 else 'FAILED'}")
