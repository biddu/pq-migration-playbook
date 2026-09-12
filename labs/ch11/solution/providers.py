"""Lab 11.1 solution (part 1) -- the provider layer: one interface per primitive, several
implementations behind it, and metadata the policy engine can reason about.

The application code above this layer never names an algorithm. It asks the registry for "a KEM"
or "a signature scheme" by the name the *policy* chose, and gets an object with the same three
or four methods whatever the algorithm is. That is the provider pattern of OpenSSL 3 (providers
supply algorithm implementations behind EVP), of Java's JCA (providers behind the engine
classes), and of NIST CSWP 39's "crypto API" layer, reduced to what an application needs.

Every provider carries the facts a policy needs: its NIST quantum security level (0 for
anything Shor breaks), its family, and its sizes, so that the negotiation in agile.py can enforce
a floor without knowing algorithm names either.

Tested with: Python 3.12, cryptography 50.0; X-Wing from labs/ch09.
"""
from __future__ import annotations

import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa, mlkem
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "ch09" / "solution"))
import xwing  # noqa: E402


@dataclass(frozen=True)
class Meta:
    name: str
    kind: str                 # "kem" | "sig"
    family: str               # classical | lattice | hybrid
    quantum_level: int        # NIST category; 0 = broken by Shor
    public_bytes: int
    payload_bytes: int        # ciphertext (KEM) or signature (sig)


class KEM(ABC):
    meta: Meta

    @abstractmethod
    def keygen(self) -> tuple[bytes, bytes]: ...           # (private, public)
    @abstractmethod
    def encapsulate(self, public: bytes) -> tuple[bytes, bytes]: ...   # (shared secret, ciphertext)
    @abstractmethod
    def decapsulate(self, private: bytes, ct: bytes) -> bytes: ...


class Signature(ABC):
    meta: Meta

    @abstractmethod
    def keygen(self) -> tuple[bytes, bytes]: ...
    @abstractmethod
    def sign(self, private: bytes, msg: bytes) -> bytes: ...
    @abstractmethod
    def verify(self, public: bytes, msg: bytes, sig: bytes) -> bool: ...


# ------------------------------------------------------------------ KEM providers

class X25519KEM(KEM):
    """Classical ECDH dressed as a KEM (ephemeral key -> shared secret through HKDF); level 0."""
    meta = Meta("X25519", "kem", "classical", 0, 32, 32)

    def keygen(self):
        k = X25519PrivateKey.generate()
        return k.private_bytes_raw(), k.public_key().public_bytes_raw()

    def encapsulate(self, public):
        e = X25519PrivateKey.generate()
        ss = e.exchange(X25519PublicKey.from_public_bytes(public))
        ct = e.public_key().public_bytes_raw()
        return HKDF(hashes.SHA256(), 32, None, b"x25519-kem" + ct + public).derive(ss), ct

    def decapsulate(self, private, ct):
        k = X25519PrivateKey.from_private_bytes(private)
        ss = k.exchange(X25519PublicKey.from_public_bytes(ct))
        return HKDF(hashes.SHA256(), 32, None, b"x25519-kem" + ct + k.public_key().public_bytes_raw()).derive(ss)


class MLKEM768(KEM):
    meta = Meta("ML-KEM-768", "kem", "lattice", 3, 1184, 1088)

    def keygen(self):
        k = mlkem.MLKEM768PrivateKey.generate()
        return k.private_bytes_raw(), k.public_key().public_bytes_raw()

    def encapsulate(self, public):
        return mlkem.MLKEM768PublicKey.from_public_bytes(public).encapsulate()

    def decapsulate(self, private, ct):
        return mlkem.MLKEM768PrivateKey.from_seed_bytes(private).decapsulate(ct)


class XWingKEM(KEM):
    meta = Meta("X-Wing", "kem", "hybrid", 3, 1216, 1120)

    def keygen(self):
        return xwing.generate_keypair()

    def encapsulate(self, public):
        return xwing.encapsulate(public)

    def decapsulate(self, private, ct):
        return xwing.decapsulate(private, ct)


# ------------------------------------------------------------------ signature providers

class Ed25519Sig(Signature):
    meta = Meta("Ed25519", "sig", "classical", 0, 32, 64)

    def keygen(self):
        k = ed25519.Ed25519PrivateKey.generate()
        return k.private_bytes_raw(), k.public_key().public_bytes_raw()

    def sign(self, private, msg):
        return ed25519.Ed25519PrivateKey.from_private_bytes(private).sign(msg)

    def verify(self, public, msg, sig):
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(public).verify(sig, msg); return True
        except Exception:
            return False


class MLDSA65Sig(Signature):
    meta = Meta("ML-DSA-65", "sig", "lattice", 3, 1952, 3309)

    def keygen(self):
        k = mldsa.MLDSA65PrivateKey.generate()
        return k.private_bytes_raw(), k.public_key().public_bytes_raw()

    def sign(self, private, msg):
        return mldsa.MLDSA65PrivateKey.from_seed_bytes(private).sign(msg)

    def verify(self, public, msg, sig):
        try:
            mldsa.MLDSA65PublicKey.from_public_bytes(public).verify(sig, msg); return True
        except Exception:
            return False


# ------------------------------------------------------------------ registry

REGISTRY: dict[str, KEM | Signature] = {p.meta.name: p for p in (X25519KEM(), MLKEM768(), XWingKEM(), Ed25519Sig(), MLDSA65Sig())}


def get(name: str) -> KEM | Signature:
    try:
        return REGISTRY[name]
    except KeyError:
        raise LookupError(f"no provider for {name!r}; known: {sorted(REGISTRY)}") from None


def available(kind: str) -> list[str]:
    return [n for n, p in REGISTRY.items() if p.meta.kind == kind]
