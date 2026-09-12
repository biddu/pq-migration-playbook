"""Lab 2.2 starter -- hybrid X25519 + ML-KEM-768 KEM. Fill in every TODO.
Specification: Chapter 2, Lab 2.2. Reference solution: solution/hybrid.py."""
from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import mlkem, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MLKEM_EK_LEN, MLKEM_CT_LEN, X25519_LEN = 1184, 1088, 32


def combine(ss_mlkem: bytes, ss_x25519: bytes, transcript: bytes, length: int = 32) -> bytes:
    """HKDF-SHA256 over ss_mlkem || ss_x25519 with the transcript as info."""
    raise NotImplementedError  # TODO


@dataclass
class ClientState:
    mlkem_sk: mlkem.MLKEM768PrivateKey
    x_sk: x25519.X25519PrivateKey
    key_share: bytes


def client_keygen() -> ClientState:
    """key_share = ML-KEM encapsulation key || X25519 public key (1,216 bytes)."""
    raise NotImplementedError  # TODO


def server_encaps(client_share: bytes, transcript: bytes) -> tuple[bytes, bytes]:
    """Returns (server share = ML-KEM ciphertext || X25519 public key, shared secret)."""
    raise NotImplementedError  # TODO


def client_decaps(state: ClientState, server_share: bytes, transcript: bytes) -> bytes:
    raise NotImplementedError  # TODO
