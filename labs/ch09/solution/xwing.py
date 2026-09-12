"""Lab 9.1 solution (part 1) -- X-Wing, the general-purpose hybrid KEM (X25519 + ML-KEM-768).

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
    """SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel): the whole security argument in one line."""
    return _sha3_256(ss_m + ss_x + ct_x + pk_x + XWING_LABEL)


def expand_decapsulation_key(sk: bytes):
    if len(sk) != SK_BYTES:
        raise ValueError("X-Wing decapsulation key is 32 bytes")
    expanded = _shake256(sk, 96)
    sk_m = mlkem.MLKEM768PrivateKey.from_seed_bytes(expanded[0:64])       # ML-KEM.KeyGen_internal(d, z)
    sk_x = X25519PrivateKey.from_private_bytes(expanded[64:96])
    return sk_m, sk_x, sk_m.public_key().public_bytes_raw(), sk_x.public_key().public_bytes_raw()


def generate_keypair(sk: bytes | None = None) -> tuple[bytes, bytes]:
    """Returns (decapsulation key, encapsulation key). Pass sk for the derandomised variant."""
    sk = sk or secrets.token_bytes(SK_BYTES)
    _, _, pk_m, pk_x = expand_decapsulation_key(sk)
    return sk, pk_m + pk_x


def encapsulate(pk: bytes) -> tuple[bytes, bytes]:
    """Returns (shared secret, ciphertext)."""
    if len(pk) != PK_BYTES:
        raise ValueError("X-Wing encapsulation key is 1216 bytes")
    pk_m, pk_x = pk[:PK_M], pk[PK_M:]
    ek_x = X25519PrivateKey.generate()
    ct_x = ek_x.public_key().public_bytes_raw()
    ss_x = ek_x.exchange(X25519PublicKey.from_public_bytes(pk_x))
    ss_m, ct_m = mlkem.MLKEM768PublicKey.from_public_bytes(pk_m).encapsulate()
    return combiner(ss_m, ss_x, ct_x, pk_x), ct_m + ct_x


def decapsulate(sk: bytes, ct: bytes) -> bytes:
    if len(ct) != CT_BYTES:
        raise ValueError("X-Wing ciphertext is 1120 bytes")
    sk_m, sk_x, _, pk_x = expand_decapsulation_key(sk)
    ct_m, ct_x = ct[:CT_M], ct[CT_M:]
    ss_m = sk_m.decapsulate(ct_m)                    # implicit rejection: a wrong ct_m gives a random ss_m, not an error
    ss_x = sk_x.exchange(X25519PublicKey.from_public_bytes(ct_x))
    return combiner(ss_m, ss_x, ct_x, pk_x)


if __name__ == "__main__":
    sk, pk = generate_keypair()
    ss1, ct = encapsulate(pk)
    ss2 = decapsulate(sk, ct)
    print(f"X-Wing: sk {len(sk)} B, pk {len(pk)} B, ct {len(ct)} B, ss {len(ss1)} B, round trip {'OK' if ss1 == ss2 else 'FAILED'}")
