"""Lab 8.2 solution -- LMS / HSS hash-based signatures (RFC 8554, SP 800-208) in plain Python,
with the state handling done wrong on purpose and then done right.

The point of the lab is the failure mode, so the implementation is deliberately small
and readable rather than fast: LM-OTS (one-time signatures, Winternitz chains), LMS (a
Merkle tree of LM-OTS public keys) and just enough HSS (a two-level tree of trees) to
verify RFC 8554's Test Case 1. Parameter sets follow RFC 8554 section 5 and 4.1:
LMS_SHA256_M32_H{5,10,15,20,25} and LMOTS_SHA256_N32_W{1,2,4,8}.

Three private-key classes share one signing routine and differ only in how they treat q,
the index of the next unused one-time key:

  LmsPrivateKey            correct: q advances before the signature is released, and the
                           key refuses to sign once q reaches 2^h
  ForgetfulLmsPrivateKey   the bug: q lives in memory, a "restore from backup" resets it,
                           and the same one-time key signs twice
  CommittedLmsPrivateKey   the fix: q is written to durable storage and read back before
                           every signature (the pattern an HSM enforces), with a reservation
                           so that a crash loses signatures rather than reusing them

forge_after_reuse() is the attack: given two or more signatures made with the same one-time
key on different messages, it produces a valid signature on a message of the attacker's
choosing, using only public information. With two reused signatures the search needs on the
order of 10^7 to 10^8 tries for W=8 (hours on one laptop core, and trivially parallel); with
four it takes seconds, because every extra signature lowers the attacker's known position
on every chain.

Tested with: Python 3.11/3.12; cross-checked against the hsslms package and RFC 8554.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import struct
from dataclasses import dataclass
from pathlib import Path

D_PBLC, D_MESG, D_LEAF, D_INTR = b"\x80\x80", b"\x81\x81", b"\x82\x82", b"\x83\x83"

# LMOTS types: typecode -> (n, w, p, ls)
LMOTS = {1: (32, 1, 265, 7), 2: (32, 2, 133, 6), 3: (32, 4, 67, 4), 4: (32, 8, 34, 0)}
LMOTS_NAME = {1: "LMOTS_SHA256_N32_W1", 2: "LMOTS_SHA256_N32_W2", 3: "LMOTS_SHA256_N32_W4", 4: "LMOTS_SHA256_N32_W8"}
# LMS types: typecode -> (m, h)
LMS = {5: (32, 5), 6: (32, 10), 7: (32, 15), 8: (32, 20), 9: (32, 25)}
LMS_NAME = {5: "LMS_SHA256_M32_H5", 6: "LMS_SHA256_M32_H10", 7: "LMS_SHA256_M32_H15", 8: "LMS_SHA256_M32_H20", 9: "LMS_SHA256_M32_H25"}


def H(*parts: bytes) -> bytes:
    return hashlib.sha256(b"".join(parts)).digest()


def u32(x: int) -> bytes: return struct.pack(">I", x)
def u16(x: int) -> bytes: return struct.pack(">H", x)
def u8(x: int) -> bytes: return bytes([x])


# ------------------------------------------------------------------ LM-OTS (RFC 8554 section 4)

def coef(s: bytes, i: int, w: int) -> int:
    """The i-th w-bit digit of byte string s (RFC 8554 section 3.1.3)."""
    return (2 ** w - 1) & (s[(i * w) // 8] >> (8 - (w * (i % (8 // w)) + w)))


def checksum(q: bytes, w: int, ls: int) -> bytes:
    n = len(q)
    s = sum((2 ** w - 1) - coef(q, i, w) for i in range(n * 8 // w))
    return u16(s << ls)


def ots_private(seed: bytes, I: bytes, q: int, typecode: int) -> list[bytes]:
    """Derive the p chain starting values pseudorandomly (SP 800-208 / RFC 8554 Appendix A)."""
    n, w, p, ls = LMOTS[typecode]
    return [H(I, u32(q), u16(i), b"\xff", seed) for i in range(p)]


def ots_public(x: list[bytes], I: bytes, q: int, typecode: int) -> bytes:
    n, w, p, ls = LMOTS[typecode]
    parts = [I, u32(q), D_PBLC]                       # the typecode is in the encoded key, not in the hash
    for i, xi in enumerate(x):
        tmp = xi
        for j in range(2 ** w - 1):
            tmp = H(I, u32(q), u16(i), u8(j), tmp)
        parts.append(tmp)
    return H(*parts)


def ots_sign(message: bytes, x: list[bytes], I: bytes, q: int, typecode: int, C: bytes | None = None) -> bytes:
    n, w, p, ls = LMOTS[typecode]
    C = C if C is not None else secrets.token_bytes(n)
    Q = H(I, u32(q), D_MESG, C, message)
    V = Q + checksum(Q, w, ls)
    y = []
    for i in range(p):
        a = coef(V, i, w)
        tmp = x[i]
        for j in range(a):
            tmp = H(I, u32(q), u16(i), u8(j), tmp)
        y.append(tmp)
    return u32(typecode) + C + b"".join(y)


def ots_pubkey_from_sig(message: bytes, sig: bytes, I: bytes, q: int) -> bytes:
    """Algorithm 4b: recompute the candidate one-time public key from a signature."""
    typecode = struct.unpack(">I", sig[:4])[0]
    n, w, p, ls = LMOTS[typecode]
    C, ys = sig[4:4 + n], sig[4 + n:]
    if len(ys) != p * n:
        raise ValueError("bad LM-OTS signature length")
    Q = H(I, u32(q), D_MESG, C, message)
    V = Q + checksum(Q, w, ls)
    parts = [I, u32(q), D_PBLC]
    for i in range(p):
        a = coef(V, i, w)
        tmp = ys[i * n:(i + 1) * n]
        for j in range(a, 2 ** w - 1):
            tmp = H(I, u32(q), u16(i), u8(j), tmp)
        parts.append(tmp)
    return H(*parts)


# ------------------------------------------------------------------ LMS (RFC 8554 section 5)

def lms_tree(seed: bytes, I: bytes, lms_type: int, ots_type: int) -> list[bytes]:
    """All 2^(h+1) node hashes, indexed 1..2^(h+1)-1 as in the RFC; node[1] is the root."""
    m, h = LMS[lms_type]
    leaves = 2 ** h
    T = [b""] * (2 * leaves)
    for q in range(leaves):
        K = ots_public(ots_private(seed, I, q, ots_type), I, q, ots_type)
        T[leaves + q] = H(I, u32(leaves + q), D_LEAF, K)
    for r in range(leaves - 1, 0, -1):
        T[r] = H(I, u32(r), D_INTR, T[2 * r], T[2 * r + 1])
    return T


def lms_public_key(lms_type: int, ots_type: int, I: bytes, root: bytes) -> bytes:
    return u32(lms_type) + u32(ots_type) + I + root


def lms_sign_with(seed: bytes, I: bytes, lms_type: int, ots_type: int, T: list[bytes], q: int, message: bytes,
                  C: bytes | None = None) -> bytes:
    m, h = LMS[lms_type]
    ots = ots_sign(message, ots_private(seed, I, q, ots_type), I, q, ots_type, C)
    node = 2 ** h + q
    path = []
    for _ in range(h):
        path.append(T[node ^ 1])
        node //= 2
    return u32(q) + ots + u32(lms_type) + b"".join(path)


def lms_verify(pubkey: bytes, message: bytes, sig: bytes) -> bool:
    try:
        lms_type, ots_type = struct.unpack(">II", pubkey[:8])
        I, root = pubkey[8:24], pubkey[24:]
        m, h = LMS[lms_type]
        n, w, p, ls = LMOTS[ots_type]
        q = struct.unpack(">I", sig[:4])[0]
        ots_len = 4 + n + p * n
        ots = sig[4:4 + ots_len]
        sig_lms_type = struct.unpack(">I", sig[4 + ots_len:8 + ots_len])[0]
        path = sig[8 + ots_len:]
        if sig_lms_type != lms_type or struct.unpack(">I", ots[:4])[0] != ots_type or len(path) != h * m or q >= 2 ** h:
            return False
        Kc = ots_pubkey_from_sig(message, ots, I, q)
        node = 2 ** h + q
        tmp = H(I, u32(node), D_LEAF, Kc)
        for i in range(h):
            sib = path[i * m:(i + 1) * m]
            tmp = H(I, u32(node // 2), D_INTR, tmp, sib) if node % 2 == 0 else H(I, u32(node // 2), D_INTR, sib, tmp)
            node //= 2
        return tmp == root
    except (struct.error, KeyError, IndexError):
        return False


def hss_verify(pubkey: bytes, message: bytes, sig: bytes) -> bool:
    """Enough HSS (RFC 8554 section 6) to verify multi-level signatures such as the RFC test vectors."""
    L = struct.unpack(">I", pubkey[:4])[0]
    key = pubkey[4:]
    Nspk = struct.unpack(">I", sig[:4])[0]
    if Nspk != L - 1:
        return False
    pos = 4
    for _ in range(Nspk):
        lms_type, ots_type = struct.unpack(">II", key[:8])
        m, h = LMS[lms_type]; n, w, p, ls = LMOTS[ots_type]
        siglen = 4 + (4 + n + p * n) + 4 + h * m
        s, pos = sig[pos:pos + siglen], pos + siglen
        next_lms = struct.unpack(">I", sig[pos:pos + 4])[0]
        nm, nh = LMS[next_lms]
        keylen = 8 + 16 + nm
        nextkey, pos = sig[pos:pos + keylen], pos + keylen
        if not lms_verify(key, nextkey, s):
            return False
        key = nextkey
    return lms_verify(key, message, sig[pos:])


# ------------------------------------------------------------------ private keys and state

class ExhaustedKey(Exception):
    pass


@dataclass
class LmsPrivateKey:
    """Correct state handling: q is advanced *before* the signature leaves this object."""
    lms_type: int = 6            # H10: 1,024 signatures
    ots_type: int = 4            # W8: p = 34, the smallest signature
    seed: bytes = b""
    I: bytes = b""
    q: int = 0

    def __post_init__(self):
        self.seed = self.seed or secrets.token_bytes(32)
        self.I = self.I or secrets.token_bytes(16)
        self.T = lms_tree(self.seed, self.I, self.lms_type, self.ots_type)
        self.public_key = lms_public_key(self.lms_type, self.ots_type, self.I, self.T[1])
        self.capacity = 2 ** LMS[self.lms_type][1]

    def _take_index(self) -> int:
        if self.q >= self.capacity:
            raise ExhaustedKey(f"all {self.capacity} one-time keys used; generate a new LMS key")
        q, self.q = self.q, self.q + 1
        return q

    def sign(self, message: bytes) -> bytes:
        q = self._take_index()                   # commit first ...
        return lms_sign_with(self.seed, self.I, self.lms_type, self.ots_type, self.T, q, message)   # ... then sign

    @property
    def remaining(self) -> int:
        return self.capacity - self.q


class ForgetfulLmsPrivateKey(LmsPrivateKey):
    """The bug: state kept only in memory, and a naive backup/restore that puts q back."""
    def snapshot(self) -> dict:
        return {"seed": self.seed.hex(), "I": self.I.hex(), "q": self.q, "lms_type": self.lms_type, "ots_type": self.ots_type}

    def restore(self, snap: dict) -> None:
        self.q = snap["q"]                       # this line is the vulnerability


class CommittedLmsPrivateKey(LmsPrivateKey):
    """The fix: q is persisted (fsync'd) before signing, in reservations, and the stored value wins."""
    def __init__(self, state_file: Path, reservation: int = 8, **kw):
        self.state_file = Path(state_file)
        self.reservation = reservation
        if self.state_file.exists():
            st = json.loads(self.state_file.read_text())
            super().__init__(seed=bytes.fromhex(st["seed"]), I=bytes.fromhex(st["I"]), q=st["q_reserved"],
                             lms_type=st["lms_type"], ots_type=st["ots_type"])
            self._reserved_until = st["q_reserved"]      # after a crash we start at the reservation boundary: lost, not reused
        else:
            super().__init__(**kw)
            self._reserved_until = 0
            self._persist(0)

    def _persist(self, q_reserved: int) -> None:
        tmp = self.state_file.with_suffix(".tmp")
        tmp.write_text(json.dumps({"seed": self.seed.hex(), "I": self.I.hex(), "q_reserved": q_reserved,
                                   "lms_type": self.lms_type, "ots_type": self.ots_type}))
        with open(tmp, "rb") as f:
            os.fsync(f.fileno())
        os.replace(tmp, self.state_file)                  # atomic: the file is either the old state or the new one

    def _take_index(self) -> int:
        if self.q >= self._reserved_until:
            new_until = min(self.q + self.reservation, self.capacity)
            if new_until <= self.q:
                raise ExhaustedKey(f"all {self.capacity} one-time keys used; generate a new LMS key")
            self._persist(new_until)                     # durable *before* any signature in the block is produced
            self._reserved_until = new_until
        q, self.q = self.q, self.q + 1
        return q


# ------------------------------------------------------------------ the attack

def forge_after_reuse(pubkey: bytes, reused: list[tuple[bytes, bytes]], target: bytes,
                      max_tries: int = 2_000_000) -> tuple[bytes | None, int, float]:
    """Given two or more LMS signatures that reused the same one-time key (same q) on different
    messages, forge a signature on `target` using only public information.
    Returns (signature or None, tries made, expected tries from the per-chain pass rates)."""
    lms_type, ots_type = struct.unpack(">II", pubkey[:8])
    I = pubkey[8:24]
    n, w, p, ls = LMOTS[ots_type]
    qs = {struct.unpack(">I", sig[:4])[0] for _, sig in reused}
    if len(reused) < 2 or len(qs) != 1:
        raise ValueError("need two or more signatures made with the same one-time key (same q)")
    q = qs.pop()
    ots_len = 4 + n + p * n
    path = reused[0][1][8 + ots_len:]                    # same leaf, same authentication path (after the LMS typecode)

    def digits_and_ys(msg, sig):
        C, ys = sig[8:8 + n], sig[8 + n:4 + ots_len]
        Q = H(I, u32(q), D_MESG, C, msg)
        V = Q + checksum(Q, w, ls)
        return [coef(V, i, w) for i in range(p)], [ys[i * n:(i + 1) * n] for i in range(p)]

    # for each chain the attacker learns the value at the lowest position any signature revealed,
    # and can hash forward from there to any higher position
    known: list[tuple[int, bytes]] = [(2 ** w, b"")] * p
    for msg, sig in reused:
        d, y = digits_and_ys(msg, sig)
        known = [(d[i], y[i]) if d[i] < known[i][0] else known[i] for i in range(p)]
    expected = 1.0
    for pos, _ in known:
        expected /= (2 ** w - pos) / 2 ** w
    for tries in range(1, max_tries + 1):
        C = secrets.token_bytes(n)
        Q = H(I, u32(q), D_MESG, C, target)
        V = Q + checksum(Q, w, ls)
        d = [coef(V, i, w) for i in range(p)]
        if all(d[i] >= known[i][0] for i in range(p)):
            ys = []
            for i in range(p):
                pos, tmp = known[i]
                for j in range(pos, d[i]):
                    tmp = H(I, u32(q), u16(i), u8(j), tmp)
                ys.append(tmp)
            ots = u32(ots_type) + C + b"".join(ys)
            return u32(q) + ots + u32(lms_type) + path, tries, expected
    return None, max_tries, expected


def sizes(lms_type: int, ots_type: int) -> dict:
    m, h = LMS[lms_type]; n, w, p, ls = LMOTS[ots_type]
    return {"public_key": 24 + m, "signature": 4 + (4 + n + p * n) + 4 + h * m, "capacity": 2 ** h,
            "chains": p, "hashes_to_verify_max": p * (2 ** w - 1) + h + 1}


if __name__ == "__main__":
    k = LmsPrivateKey(lms_type=5)                       # H5 for a quick demo
    s = k.sign(b"firmware v1.0")
    print("LMS", LMS_NAME[k.lms_type], LMOTS_NAME[k.ots_type], "pk", len(k.public_key), "B, sig", len(s), "B,",
          "verify", lms_verify(k.public_key, b"firmware v1.0", s), "remaining", k.remaining)
