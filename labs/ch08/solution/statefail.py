"""Lab 8.2 driver -- break LMS state handling, forge a firmware signature, then fix it.

Scene 1  A build server signs firmware with an LMS key whose index q lives only in memory.
         Operations "restores the signing VM from last night's snapshot". Four builds later,
         four signatures share one one-time key.
Scene 2  An attacker who has only the public key and the four published signatures forges
         a valid signature on firmware of their choosing.
Scene 3  The same pipeline with committed state: q is fsync'd in reservations before any
         signature in the block is released; a crash costs at most one reservation of
         indices and can never reuse one.

Tested with: Python 3.11/3.12.
"""
from __future__ import annotations

import json
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lms  # noqa: E402

HERE = Path(__file__).resolve().parents[1]


def scene1(reuses: int) -> tuple[lms.ForgetfulLmsPrivateKey, list[tuple[bytes, bytes]]]:
    key = lms.ForgetfulLmsPrivateKey(lms_type=5, ots_type=4)          # H5/W8: 32 signatures, 1,292 B each
    snapshot = key.snapshot()                                          # "nightly backup" of the signing VM
    published = []
    for i in range(reuses):
        key.restore(snapshot)                                          # "restore from backup" before each build
        msg = f"firmware-1.{i}.bin sha256=...".encode()
        sig = key.sign(msg)
        published.append((msg, sig))
        assert lms.lms_verify(key.public_key, msg, sig)
    qs = sorted({int.from_bytes(s[:4], "big") for _, s in published})
    print(f"scene 1: {reuses} builds signed; one-time key indices used: {qs}  <- the same q every time")
    return key, published


def scene2(pub: bytes, published: list[tuple[bytes, bytes]], target: bytes) -> dict:
    results = {}
    for k in range(2, len(published) + 1):
        t0 = time.perf_counter()
        forged, tries, expected = lms.forge_after_reuse(pub, published[:k], target, max_tries=1_000_000)
        dt = time.perf_counter() - t0
        ok = forged is not None and lms.lms_verify(pub, target, forged)
        results[k] = {"forged": ok, "tries": tries, "seconds": round(dt, 2), "expected_tries_uniform_model": round(expected)}
        print(f"scene 2: with {k} reused signatures: {'FORGED' if ok else 'not found'} after {tries:,} tries "
              f"in {dt:.1f} s{'' if ok else f' (gave up; at least {expected:,.0f} tries needed on the uniform-digit model, which underestimates)'}")
        if ok:
            break
    return results


def scene3(tmp: Path) -> dict:
    state = tmp / "lms_state.json"
    key = lms.CommittedLmsPrivateKey(state, reservation=8, lms_type=5, ots_type=4)
    pub = key.public_key
    used = []
    for i in range(3):                                                 # three builds, then the server dies
        sig = key.sign(f"firmware-2.{i}.bin".encode())
        used.append(int.from_bytes(sig[:4], "big"))
    del key                                                            # crash: in-memory q (3) is gone
    key2 = lms.CommittedLmsPrivateKey(state)                           # restart from durable state
    assert key2.public_key == pub
    after = [int.from_bytes(key2.sign(f"firmware-2.{i}.bin".encode())[:4], "big") for i in range(3, 5)]
    print(f"scene 3: before crash used q = {used}; after restart q = {after}; "
          f"indices {list(range(used[-1] + 1, after[0]))} were lost, none reused; {key2.remaining} signatures left of {key2.capacity}")
    return {"before_crash": used, "after_restart": after, "lost": list(range(used[-1] + 1, after[0])), "remaining": key2.remaining}


def main() -> int:
    key, published = scene1(reuses=4)
    target = b"firmware-6.6.6.bin sha256=... (attacker's build)"
    forgery = scene2(key.public_key, published, target)
    with tempfile.TemporaryDirectory() as d:
        fixed = scene3(Path(d))
    out = HERE / "results" / "statefail.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps({"reuses": 4, "forgery": forgery, "committed_state": fixed}, indent=2) + "\n")
    print(f"written {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
