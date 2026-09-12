"""Lab 2.2 solution -- a hybrid X25519 + ML-KEM-768 KEM with a concatenation combiner.

This is the construction TLS 1.3 uses for the X25519MLKEM768 group, reduced to
its essentials so that the byte counts and the hedge are visible. It is a
teaching implementation: in production you use the TLS stack's own hybrid group.

  client key share  = ML-KEM encapsulation key (1,184 B) || X25519 public key (32 B) = 1,216 B
  server key share  = ML-KEM ciphertext (1,088 B)        || X25519 public key (32 B) = 1,120 B
  shared secret     = KDF( ss_mlkem || ss_x25519 , transcript )

Tested with: Python 3.12, cryptography 50.0.
"""
from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import mlkem, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MLKEM_EK_LEN, MLKEM_CT_LEN, X25519_LEN = 1184, 1088, 32


def combine(ss_mlkem: bytes, ss_x25519: bytes, transcript: bytes, length: int = 32) -> bytes:
    """Concatenate-then-KDF. Secure if either component KEM is secure (SP 800-227, section 5)."""
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=transcript).derive(ss_mlkem + ss_x25519)


@dataclass
class ClientState:
    mlkem_sk: mlkem.MLKEM768PrivateKey
    x_sk: x25519.X25519PrivateKey
    key_share: bytes                        # what goes on the wire in the ClientHello


def client_keygen() -> ClientState:
    m = mlkem.MLKEM768PrivateKey.generate()
    x = x25519.X25519PrivateKey.generate()
    share = m.public_key().public_bytes_raw() + x.public_key().public_bytes_raw()
    assert len(share) == MLKEM_EK_LEN + X25519_LEN
    return ClientState(m, x, share)


def server_encaps(client_share: bytes, transcript: bytes) -> tuple[bytes, bytes]:
    """Returns (server key share, shared secret)."""
    ek = mlkem.MLKEM768PublicKey.from_public_bytes(client_share[:MLKEM_EK_LEN])
    client_x = x25519.X25519PublicKey.from_public_bytes(client_share[MLKEM_EK_LEN:])
    ss_m, ct = ek.encapsulate()
    eph = x25519.X25519PrivateKey.generate()
    ss_x = eph.exchange(client_x)
    share = ct + eph.public_key().public_bytes_raw()
    assert len(share) == MLKEM_CT_LEN + X25519_LEN
    return share, combine(ss_m, ss_x, transcript)


def client_decaps(state: ClientState, server_share: bytes, transcript: bytes) -> bytes:
    ct, server_x = server_share[:MLKEM_CT_LEN], server_share[MLKEM_CT_LEN:]
    ss_m = state.mlkem_sk.decapsulate(ct)
    ss_x = state.x_sk.exchange(x25519.X25519PublicKey.from_public_bytes(server_x))
    return combine(ss_m, ss_x, transcript)


if __name__ == "__main__":
    transcript = b"ClientHello||ServerHello"      # in TLS, the handshake transcript hash
    c = client_keygen()
    s_share, k_server = server_encaps(c.key_share, transcript)
    k_client = client_decaps(c, s_share, transcript)
    assert k_client == k_server
    print(f"client key share {len(c.key_share):,} B, server key share {len(s_share):,} B, "
          f"shared secret {len(k_client)} B, agree={k_client == k_server}")
