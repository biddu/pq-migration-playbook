"""Lab 6.2 solution -- post-quantum pre-shared keys for WireGuard.

WireGuard's handshake is X25519 only, and it has no algorithm negotiation, so the
protocol itself cannot move to ML-KEM. It does have a 32-byte optional pre-shared
key that is mixed into the handshake, and the WireGuard paper says what it is for:
"a post-quantum mitigation". If the PSK is derived from an ML-KEM shared secret,
the tunnel's session keys depend on a secret a quantum adversary cannot recover,
even though the X25519 handshake still runs. That is the idea Rosenpass turns
into a daemon; this lab is the minimal version, so you can see every byte of it.

Protocol (out-of-band channel = anything you already have: SSH, the existing tunnel,
a configuration-management push):
  responder: generate an ML-KEM-768 key pair once; publish the encapsulation key
  initiator: encapsulate to it -> (shared secret, 1,088-byte ciphertext); send ciphertext
  both:      psk = HKDF-SHA256(shared_secret, info = "wg-pq-psk" || wg_pub_A || wg_pub_B || epoch)
  both:      wg set IFACE peer PEER_WG_PUB preshared-key <file with base64(psk)>
Rotate by incrementing the epoch and repeating. Dry-run mode prints the commands.

Tested with: Python 3.12, cryptography 50.0. No WireGuard needed to run the dry run.
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import mlkem
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

INFO_PREFIX = b"wg-pq-psk-v1"


def derive_psk(shared_secret: bytes, wg_pub_a: bytes, wg_pub_b: bytes, epoch: int) -> bytes:
    """32-byte PSK bound to both WireGuard identities and a rotation epoch."""
    if len(wg_pub_a) != 32 or len(wg_pub_b) != 32:
        raise ValueError("WireGuard public keys are 32 bytes")
    lo, hi = sorted((wg_pub_a, wg_pub_b))               # same PSK whichever side computes it
    info = INFO_PREFIX + lo + hi + epoch.to_bytes(4, "big")
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(shared_secret)


def responder_keygen(path: Path) -> bytes:
    sk = mlkem.MLKEM768PrivateKey.generate()
    path.write_bytes(sk.private_bytes_raw())          # 64-byte seed; protect like any private key
    return sk.public_key().public_bytes_raw()


def initiator_encapsulate(responder_ek: bytes) -> tuple[bytes, bytes]:
    ek = mlkem.MLKEM768PublicKey.from_public_bytes(responder_ek)
    ss, ct = ek.encapsulate()
    return ss, ct


def responder_decapsulate(seed: bytes, ciphertext: bytes) -> bytes:
    return mlkem.MLKEM768PrivateKey.from_seed_bytes(seed).decapsulate(ciphertext)


def wg_command(iface: str, peer_wg_pub_b64: str, psk: bytes) -> str:
    return f"wg set {iface} peer {peer_wg_pub_b64} preshared-key <(printf '%s\\n' '{base64.b64encode(psk).decode()}')"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Derive and install ML-KEM-based WireGuard pre-shared keys.")
    sub = p.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("keygen", help="responder: create an ML-KEM-768 key pair; prints the encapsulation key")
    g.add_argument("--out", required=True)
    e = sub.add_parser("encaps", help="initiator: encapsulate to the responder's key; prints ciphertext and installs PSK")
    e.add_argument("--responder-ek", required=True, help="base64 encapsulation key")
    e.add_argument("--wg-pub-self", required=True); e.add_argument("--wg-pub-peer", required=True)
    e.add_argument("--epoch", type=int, default=1); e.add_argument("--iface", default="wg0"); e.add_argument("--dry-run", action="store_true")
    d = sub.add_parser("decaps", help="responder: decapsulate the ciphertext; installs the same PSK")
    d.add_argument("--key", required=True); d.add_argument("--ciphertext", required=True, help="base64")
    d.add_argument("--wg-pub-self", required=True); d.add_argument("--wg-pub-peer", required=True)
    d.add_argument("--epoch", type=int, default=1); d.add_argument("--iface", default="wg0"); d.add_argument("--dry-run", action="store_true")
    a = p.parse_args(argv)

    if a.cmd == "keygen":
        ek = responder_keygen(Path(a.out))
        print(json.dumps({"encapsulation_key_b64": base64.b64encode(ek).decode(), "bytes": len(ek)}))
        return 0

    self_pub, peer_pub = base64.b64decode(a.wg_pub_self), base64.b64decode(a.wg_pub_peer)
    if a.cmd == "encaps":
        ss, ct = initiator_encapsulate(base64.b64decode(a.responder_ek))
        print(json.dumps({"ciphertext_b64": base64.b64encode(ct).decode(), "ciphertext_bytes": len(ct), "epoch": a.epoch}))
    else:
        ss = responder_decapsulate(Path(a.key).read_bytes(), base64.b64decode(a.ciphertext))
    psk = derive_psk(ss, self_pub, peer_pub, a.epoch)
    cmd = wg_command(a.iface, a.wg_pub_peer, psk)
    print(("DRY RUN: " if a.dry_run else "") + cmd)
    if not a.dry_run:
        import subprocess
        subprocess.run(["bash", "-c", cmd], check=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
