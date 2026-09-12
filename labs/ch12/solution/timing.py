"""Lab 12.2 solution -- a dudect-style timing-leak detector, applied to a deliberately leaky toy
decapsulation, to a constant-time one, and to the real ML-KEM in the cryptography package.

The method (Reparaz, Balasch and Verbauwhede, "Dude, is my code constant time?", 2017) needs no
model of the CPU: measure the operation many times on two classes of input, interleaved in random
order; crop the upper tail of each class (interrupts and cache misses live there); compute
Welch's t-statistic between the two distributions. |t| above about 4.5 means the two classes are
distinguishable by timing, i.e. execution time depends on the input, and for a decapsulation the
input includes secret-dependent intermediate values. It cannot prove the absence of a leak, only
fail to find one at this sample size on this machine; the chapter says what that is worth.

Targets:
  leaky_fo       a toy KEM decapsulation whose implicit-rejection branch does visibly different work
                 for a valid and a tampered ciphertext (the non-constant-time FO transform: the class
                 of bug behind several early Kyber implementations)
  ct_fo          the same toy with a constant-time select between the two outcomes
  leaky_compare  an early-exit byte comparison of a 32-byte tag (the classic MAC-check leak)
  ct_compare     hmac.compare_digest
  mlkem768       cryptography 50's ML-KEM-768 decapsulate: valid vs tampered ciphertext

Classes for the KEM targets: A = a valid ciphertext, B = the same ciphertext with one byte flipped
(so decapsulation takes the implicit-rejection path). Python adds noise of its own, so the toy leaks
are made large enough to see through it; the point is the method, which transfers to C with a
cycle counter.

Tested with: Python 3.12, cryptography 50.0.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import random
import secrets
import statistics
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import mlkem

HERE = Path(__file__).resolve().parents[1]
T_THRESHOLD = 4.5


# ------------------------------------------------------------------ the statistic

def welch_t(a: list[float], b: list[float]) -> float:
    ma, mb = statistics.fmean(a), statistics.fmean(b)
    va, vb = statistics.pvariance(a), statistics.pvariance(b)
    denom = math.sqrt(va / len(a) + vb / len(b))
    return (ma - mb) / denom if denom else 0.0


def crop(xs: list[float], pct: float = 0.9) -> list[float]:
    """Keep the lowest pct of samples: dudect's cropping of the noisy upper tail."""
    xs = sorted(xs)
    return xs[: max(2, int(len(xs) * pct))]


def measure(fn, inputs_a: list, inputs_b: list, n: int, warmup: int = 200) -> dict:
    """Interleave the two classes in random order, time each call, return the t-statistic."""
    for _ in range(warmup):
        fn(inputs_a[0]); fn(inputs_b[0])
    ta, tb = [], []
    order = [0] * n + [1] * n
    random.shuffle(order)
    ia = ib = 0
    for cls in order:
        if cls == 0:
            x = inputs_a[ia % len(inputs_a)]; ia += 1
            t0 = time.perf_counter_ns(); fn(x); ta.append(time.perf_counter_ns() - t0)
        else:
            x = inputs_b[ib % len(inputs_b)]; ib += 1
            t0 = time.perf_counter_ns(); fn(x); tb.append(time.perf_counter_ns() - t0)
    ca, cb = crop(ta), crop(tb)
    t = welch_t(ca, cb)
    return {"n_per_class": n, "median_a_ns": statistics.median(ta), "median_b_ns": statistics.median(tb),
            "t": round(t, 2), "leak": abs(t) > T_THRESHOLD}


# ------------------------------------------------------------------ targets

class ToyKEM:
    """A toy KEM with the Fujisaki-Okamoto shape: decapsulate re-derives the ciphertext and either returns
    the real key or an implicit-rejection key. Two implementations of the final step."""

    def __init__(self):
        self.sk = secrets.token_bytes(32)
        self.z = secrets.token_bytes(32)                 # implicit-rejection secret
        self.pk = hashlib.sha256(b"pk" + self.sk).digest()

    def encapsulate(self) -> tuple[bytes, bytes]:
        m = secrets.token_bytes(32)
        k, r = hashlib.sha256(b"K" + m + self.pk).digest(), hashlib.sha256(b"r" + m).digest()
        ct = bytes(a ^ b for a, b in zip(m, hashlib.sha256(b"enc" + self.pk + r).digest())) + r
        return k, ct

    def _decrypt(self, ct: bytes) -> bytes:
        r = ct[32:]
        return bytes(a ^ b for a, b in zip(ct[:32], hashlib.sha256(b"enc" + self.pk + r).digest()))

    def _reencrypt(self, m: bytes) -> bytes:
        r = hashlib.sha256(b"r" + m).digest()
        return bytes(a ^ b for a, b in zip(m, hashlib.sha256(b"enc" + self.pk + r).digest())) + r

    def decaps_leaky(self, ct: bytes) -> bytes:
        m = self._decrypt(ct)
        if self._reencrypt(m) == ct:                   # branch on a secret-derived comparison ...
            return hashlib.sha256(b"K" + m + self.pk).digest()
        # ... and do *different* work on rejection: the rejection key is derived with extra hashing
        k = self.z + ct
        for _ in range(40):
            k = hashlib.sha256(k).digest()
        return k

    def decaps_ct(self, ct: bytes) -> bytes:
        m = self._decrypt(ct)
        ok = hmac.compare_digest(self._reencrypt(m), ct)
        k_good = hashlib.sha256(b"K" + m + self.pk).digest()
        k_bad = hashlib.sha256(b"J" + self.z + ct).digest()     # same amount of work on both paths
        mask = 0xFF if ok else 0x00                              # constant-time select (in spirit; Python has no such guarantee)
        return bytes((g & mask) | (b & (mask ^ 0xFF)) for g, b in zip(k_good, k_bad))


def leaky_compare(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    for x, y in zip(a, b):
        if x != y:
            return False                                # early exit: time reveals the first differing byte
    return True


def flip(ct: bytes, i: int = 0) -> bytes:
    return ct[:i] + bytes([ct[i] ^ 1]) + ct[i + 1:]


# ------------------------------------------------------------------ runs

def run_all(n: int = 4000) -> list[dict]:
    rows = []
    toy = ToyKEM()
    k, ct = toy.encapsulate()
    good = [ct]; bad = [flip(ct, i % 64) for i in range(16)]
    rows.append({"target": "toy FO, leaky rejection", **measure(toy.decaps_leaky, good, bad, n)})
    rows.append({"target": "toy FO, constant-time", **measure(toy.decaps_ct, good, bad, n)})

    tag = secrets.token_bytes(32)
    same = [tag]; first_byte_wrong = [flip(tag, 0)]
    rows.append({"target": "early-exit compare", **measure(lambda g: leaky_compare(tag, g), same, first_byte_wrong, n)})
    rows.append({"target": "hmac.compare_digest", **measure(lambda g: hmac.compare_digest(tag, g), same, first_byte_wrong, n)})

    sk = mlkem.MLKEM768PrivateKey.generate()
    ss, ct = sk.public_key().encapsulate()
    good = [ct]; bad = [flip(ct, i * 37 % len(ct)) for i in range(16)]
    assert sk.decapsulate(bad[0]) != ss                   # implicit rejection: a wrong key, not an error
    rows.append({"target": "cryptography ML-KEM-768 decapsulate", **measure(sk.decapsulate, good, bad, n)})
    return rows


def main() -> int:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 4000
    rows = run_all(n)
    print(f"{'target':<38} {'median A ns':>12} {'median B ns':>12} {'t':>8}  verdict")
    for r in rows:
        print(f"{r['target']:<38} {r['median_a_ns']:>12.0f} {r['median_b_ns']:>12.0f} {r['t']:>8.2f}  "
              f"{'LEAK (|t| > 4.5)' if r['leak'] else 'no leak found at this n'}")
    (HERE / "results").mkdir(exist_ok=True)
    (HERE / "results" / "timing.json").write_text(json.dumps(rows, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
