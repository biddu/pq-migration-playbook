"""Lab 9.1 solution (part 2) -- envelope encryption with a hybrid KEM, and re-keying a data set
without touching the data.

Envelope encryption is the pattern every KMS and every sane storage system uses: each object
is encrypted under its own random data-encryption key (DEK) with AES-256-GCM, and the DEK is
wrapped under a long-lived key-encryption key (KEK). The post-quantum exposure is entirely in
the wrap: an RSA-OAEP or ECIES-wrapped DEK recorded today is a DEK a quantum adversary reads
tomorrow, and with it the object. The AES-256 ciphertext itself is fine.

So the migration is a re-wrap, not a re-encryption. This module:

  * wraps DEKs three ways, so the header sizes can be compared:
      rsa3072    RSA-OAEP(SHA-256)            legacy, 384-byte wrapped key
      mlkem768   ML-KEM-768 KEM + HKDF + AES-GCM   pure post-quantum, 1,088-byte ct
      xwing      X-Wing KEM + HKDF + AES-GCM       hybrid, 1,120-byte ct
  * writes each object as two files, the way an object store keeps key material in metadata:
      name.hdr   scheme, KEK id and the wrapped DEK
      name.bin   nonce || AES-256-GCM(DEK, body)
  * rekey(): unwraps every object's DEK with the old KEK, re-wraps with the new KEK, and
    rewrites only the .hdr files; the .bin bodies are never read or written. (If the header
    were stored inline ahead of the body, a header that grows by 800 bytes would force the
    whole object to be rewritten; that is a storage-layout decision worth making before the
    migration, not during it.)
  * shred(): destroys a KEK, which makes every object wrapped under it unreadable at once
    (crypto-shredding), and shows what that does and does not delete

Tested with: Python 3.11/3.12, cryptography 50.0.
"""
from __future__ import annotations

import json
import os
import secrets
import struct
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import mlkem, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

sys.path.insert(0, str(Path(__file__).resolve().parent))
import xwing  # noqa: E402

HERE = Path(__file__).resolve().parents[1]
MAGIC = b"PQENV1"
INFO = b"pqm-envelope-dek-wrap-v1"


# ------------------------------------------------------------------ key-encryption keys

@dataclass
class Kek:
    scheme: str            # rsa3072 | mlkem768 | xwing
    kid: str
    private: object        # rsa key | mlkem private key | bytes (xwing sk)
    public: bytes          # DER (rsa) or raw

    @staticmethod
    def generate(scheme: str, kid: str) -> "Kek":
        if scheme == "rsa3072":
            k = rsa.generate_private_key(65537, 3072)
            return Kek(scheme, kid, k, k.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
        if scheme == "mlkem768":
            k = mlkem.MLKEM768PrivateKey.generate()
            return Kek(scheme, kid, k, k.public_key().public_bytes_raw())
        if scheme == "xwing":
            sk, pk = xwing.generate_keypair()
            return Kek(scheme, kid, sk, pk)
        raise ValueError(scheme)


def _kdf(ss: bytes, kid: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=INFO + kid.encode()).derive(ss)


def wrap_dek(kek: Kek, dek: bytes) -> bytes:
    """Returns the wrapped DEK blob for the header."""
    if kek.scheme == "rsa3072":
        pub = serialization.load_der_public_key(kek.public)
        return pub.encrypt(dek, padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))
    if kek.scheme == "mlkem768":
        ss, ct = mlkem.MLKEM768PublicKey.from_public_bytes(kek.public).encapsulate()
    else:
        ss, ct = xwing.encapsulate(kek.public)
    nonce = secrets.token_bytes(12)
    return ct + nonce + AESGCM(_kdf(ss, kek.kid)).encrypt(nonce, dek, kek.kid.encode())


def unwrap_dek(kek: Kek, blob: bytes) -> bytes:
    if kek.scheme == "shredded":
        raise ShreddedKey(f"{kek.kid} has been destroyed; nothing wrapped under it can be recovered")
    if kek.scheme == "rsa3072":
        return kek.private.decrypt(blob, padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))
    ct_len = 1088 if kek.scheme == "mlkem768" else 1120
    ct, nonce, wrapped = blob[:ct_len], blob[ct_len:ct_len + 12], blob[ct_len + 12:]
    ss = kek.private.decapsulate(ct) if kek.scheme == "mlkem768" else xwing.decapsulate(kek.private, ct)
    return AESGCM(_kdf(ss, kek.kid)).decrypt(nonce, wrapped, kek.kid.encode())


# ------------------------------------------------------------------ objects

def _header(scheme: str, kid: str, wrapped: bytes) -> bytes:
    meta = json.dumps({"scheme": scheme, "kid": kid}).encode()
    return MAGIC + struct.pack(">HH", len(meta), len(wrapped)) + meta + wrapped


def _parse_header(blob: bytes) -> tuple[dict, bytes, int]:
    if blob[:6] != MAGIC:
        raise ValueError("not an envelope object")
    ml, wl = struct.unpack(">HH", blob[6:10])
    meta = json.loads(blob[10:10 + ml]); wrapped = blob[10 + ml:10 + ml + wl]
    return meta, wrapped, 10 + ml + wl


def encrypt_object(kek: Kek, body: bytes) -> tuple[bytes, bytes]:
    """Returns (header, encrypted body)."""
    dek = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    return _header(kek.scheme, kek.kid, wrap_dek(kek, dek)), nonce + AESGCM(dek).encrypt(nonce, body, None)


def decrypt_object(kek: Kek, header: bytes, body: bytes) -> bytes:
    meta, wrapped, _ = _parse_header(header)
    if meta["kid"] != kek.kid:
        raise KeyError(f"object is wrapped under {meta['kid']}, not {kek.kid}")
    dek = unwrap_dek(kek, wrapped)
    return AESGCM(dek).decrypt(body[:12], body[12:], None)


# ------------------------------------------------------------------ the data set, re-key and shred

def make_dataset(d: Path, kek: Kek, n: int, size: int) -> list[Path]:
    """Creates n objects; returns the .hdr paths (the .bin sits beside each)."""
    d.mkdir(parents=True, exist_ok=True)
    paths = []
    for i in range(n):
        p = d / f"object-{i:05d}.hdr"
        header, body = encrypt_object(kek, os.urandom(size))
        p.write_bytes(header); p.with_suffix(".bin").write_bytes(body)
        paths.append(p)
    return paths


def rekey(paths: list[Path], old: Kek, new: Kek) -> dict:
    """Re-wrap every DEK from old to new; rewrite .hdr files only. Returns what was read and written."""
    t0 = time.perf_counter(); read = written = bodies = 0
    for p in paths:
        header = p.read_bytes()
        meta, wrapped, _ = _parse_header(header)
        if meta["kid"] != old.kid:
            continue
        dek = unwrap_dek(old, wrapped)
        new_header = _header(new.scheme, new.kid, wrap_dek(new, dek))
        p.write_bytes(new_header)
        read += len(header); written += len(new_header); bodies += p.with_suffix(".bin").stat().st_size
    return {"objects": len(paths), "header_bytes_read": read, "header_bytes_written": written,
            "body_bytes_untouched": bodies, "seconds": round(time.perf_counter() - t0, 3)}


class ShreddedKey(Exception):
    pass


def shred(kek: Kek) -> None:
    """Crypto-shredding: destroy the KEK; every DEK wrapped under it is now unrecoverable."""
    kek.private = None
    kek.public = b""
    kek.scheme = "shredded"


def main() -> int:
    d = HERE / "data" / "objects"
    n, size = 200, 64 * 1024
    old = Kek.generate("rsa3072", "kek-rsa-2019")
    t0 = time.perf_counter(); paths = make_dataset(d, old, n, size); t_make = time.perf_counter() - t0
    h_old = len(paths[0].read_bytes())
    print(f"created {n} objects of {size // 1024} KiB under {old.scheme} ({old.kid}); header {h_old} B; {t_make:.1f} s")
    rows = {"objects": n, "object_kib": size // 1024, "headers": {"rsa3072": h_old}}
    for scheme in ("mlkem768", "xwing"):
        new = Kek.generate(scheme, f"kek-{scheme}-2026")
        r = rekey(paths, old, new)
        h = len(paths[0].read_bytes())
        total = r["header_bytes_written"] + r["body_bytes_untouched"]
        print(f"re-keyed to {scheme:<9}: header {h} B (+{h - h_old}); wrote {r['header_bytes_written']:,} header bytes, "
              f"left {r['body_bytes_untouched']:,} body bytes untouched ({100 * r['header_bytes_written'] / total:.2f}% of the store rewritten) in {r['seconds']} s")
        assert decrypt_object(new, paths[0].read_bytes(), paths[0].with_suffix(".bin").read_bytes())   # still decrypts, under the new KEK
        rows["headers"][scheme] = h; rows[f"rekey_{scheme}"] = r
        old = new
    shred(old)
    try:
        decrypt_object(old, paths[0].read_bytes(), paths[0].with_suffix(".bin").read_bytes()); print("BUG: decrypted after shred")
    except ShreddedKey as e:
        print(f"after shredding: {e}; the ciphertext is still on disk, "
              f"{paths[0].with_suffix('.bin').stat().st_size:,} B per object, and no key exists to read it")
    (HERE / "results").mkdir(exist_ok=True)
    (HERE / "results" / "envelope.json").write_text(json.dumps(rows, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
