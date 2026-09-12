"""Lab 11.1 STARTER (part 2) -- policy-as-code, negotiation, the kill switch, rollback, telemetry.

Agility, operationally, is four verbs: SWAP an algorithm without touching code, NEGOTIATE with a
peer whose policy differs, ROLL BACK when the new algorithm misbehaves, and OBSERVE what every
connection actually used. This module does all four against the provider layer in providers.py:

  Policy      loads a YAML file (policies/policy-v3.yaml) and applies its rules as of a date:
              preferred order, allowed set, minimum quantum level (floor), dated deprecations,
              and the kill switch. Policies are versioned files; the loader keeps the previous
              version so that rollback() is a one-call operation.
  negotiate() the first algorithm in our preferred order that is allowed by both sides as of
              `now`, not killed, and at or above the floor; emits a telemetry Event whether it
              succeeds or fails, with a `downgrade` flag when it chose a level-0 algorithm while a
              higher one was on offer from the peer.
  Channel     a KEM + AES-GCM + signature "connection" between two policies, so the whole path
              from policy file to bytes on the wire can be exercised and property-tested.
  kill()      adds a name to the kill switch and writes a new policy version; the next
              negotiation excludes it. rollback() restores the previous version.

Every decision is a pure function of (policy, peer offer, date), which is what makes Lab 11.2's
property tests possible: the tests generate random policies, offers and dates and assert the
invariants that the chapter says an agile system must have.

Tested with: Python 3.12, cryptography 50.0, PyYAML 6.

Complete the three methods/functions marked TODO. `PQ_LAB_IMPL=solution pytest labs/ch11/tests` runs the reference.
"""
from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import secrets
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path

import yaml
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

sys.path.insert(0, str(Path(__file__).resolve().parent))
import providers  # noqa: E402

HERE = Path(__file__).resolve().parent          # labs/chNN (the solution lives one level deeper)


# ------------------------------------------------------------------ policy

class PolicyError(Exception):
    pass


@dataclass
class Policy:
    version: int
    kem_preferred: list[str]
    kem_allowed: list[str]
    kem_floor: int
    sig_preferred: list[str]
    sig_allowed: list[str]
    sig_floor: int
    deprecations: dict[str, dict[str, dt.date]]
    kill_switch: list[str]
    source: Path | None = None
    previous: "Policy | None" = field(default=None, repr=False)

    # ---- loading and validation
    @classmethod
    def from_dict(cls, d: dict, source: Path | None = None) -> "Policy":
        def dates(m):
            out = {}
            for alg, spec in (m or {}).items():
                out[alg] = {k: (v if isinstance(v, dt.date) else dt.date.fromisoformat(str(v))) for k, v in spec.items()}
            return out
        p = cls(int(d["version"]), list(d["kem"]["preferred"]), list(d["kem"]["allowed"]), int(d["kem"].get("floor", 0)),
                list(d["sig"]["preferred"]), list(d["sig"]["allowed"]), int(d["sig"].get("floor", 0)),
                dates(d.get("deprecations")), list(d.get("kill_switch") or []), source)
        p.validate()
        return p

    @classmethod
    def load(cls, path: Path) -> "Policy":
        return cls.from_dict(yaml.safe_load(Path(path).read_text()), Path(path))

    def to_dict(self) -> dict:
        return {"version": self.version,
                "kem": {"preferred": self.kem_preferred, "allowed": self.kem_allowed, "floor": self.kem_floor},
                "sig": {"preferred": self.sig_preferred, "allowed": self.sig_allowed, "floor": self.sig_floor},
                "deprecations": {a: {k: v.isoformat() for k, v in s.items()} for a, s in self.deprecations.items()},
                "kill_switch": self.kill_switch}

    def validate(self) -> None:
        for kind, pref, allowed in (("kem", self.kem_preferred, self.kem_allowed), ("sig", self.sig_preferred, self.sig_allowed)):
            known = set(providers.available(kind))
            for n in pref + allowed:
                if n not in known:
                    raise PolicyError(f"{kind}: unknown algorithm {n!r} (providers: {sorted(known)})")
            if set(pref) != set(allowed):
                raise PolicyError(f"{kind}: preferred and allowed must name the same algorithms (preferred is the order)")
            if not pref:
                raise PolicyError(f"{kind}: at least one algorithm required")
        for alg, spec in self.deprecations.items():
            if "warn_after" in spec and "disallow_after" in spec and spec["warn_after"] > spec["disallow_after"]:
                raise PolicyError(f"{alg}: warn_after must not be later than disallow_after")

    def digest(self) -> str:
        return hashlib.sha256(json.dumps(self.to_dict(), sort_keys=True).encode()).hexdigest()[:16]

    # ---- rules as of a date
    def is_killed(self, alg: str) -> bool:
        return alg in self.kill_switch

    def is_disallowed(self, alg: str, now: dt.date) -> bool:
        d = self.deprecations.get(alg, {}).get("disallow_after")
        return d is not None and now > d

    def is_warned(self, alg: str, now: dt.date) -> bool:
        w = self.deprecations.get(alg, {}).get("warn_after")
        return w is not None and now > w

    def usable(self, kind: str, now: dt.date) -> list[str]:
        """TODO: preferred order for `kind`, dropping killed algorithms, those past disallow_after as of now, and those whose provider quantum_level is below the floor"""
        raise NotImplementedError("usable")


    # ---- change control
    def with_kill(self, alg: str) -> "Policy":
        """TODO: deep-copy self, set previous=self, version+1, append alg to kill_switch if absent"""
        raise NotImplementedError("with_kill")


    def rollback(self) -> "Policy":
        if self.previous is None:
            raise PolicyError("no previous policy version to roll back to")
        return self.previous


# ------------------------------------------------------------------ negotiation and telemetry

@dataclass
class Event:
    ts: str
    kind: str
    policy_version: int
    policy_digest: str
    our_usable: list[str]
    peer_offer: list[str]
    chosen: str | None
    quantum_level: int | None
    downgrade: bool          # chose level 0 while a higher-level algorithm was in both lists
    warned: bool             # chosen algorithm is past its warn_after date
    reason: str


TELEMETRY: list[Event] = []


def negotiate(policy: Policy, kind: str, peer_offer: list[str], now: dt.date | None = None) -> Event:
    """TODO: ours = policy.usable(kind, now); common = [a for a in ours if a in peer_offer]; chosen = first common or None;
    build the Event (downgrade = chosen is level 0 while some common algorithm has level > 0; warned = past warn_after),
    append it to TELEMETRY and return it. Emit an event even when nothing is chosen."""
    raise NotImplementedError("negotiate")



# ------------------------------------------------------------------ a channel, end to end

class Channel:
    """Two policies establish a key with the negotiated KEM and authenticate with the negotiated signature."""

    def __init__(self, ours: Policy, theirs: Policy, now: dt.date | None = None):
        now = now or dt.date.today()
        self.kem_event = negotiate(ours, "kem", theirs.usable("kem", now), now)
        self.sig_event = negotiate(ours, "sig", theirs.usable("sig", now), now)
        if not self.kem_event.chosen or not self.sig_event.chosen:
            raise ConnectionError(f"negotiation failed: kem={self.kem_event.reason}; sig={self.sig_event.reason}")
        self.kem = providers.get(self.kem_event.chosen)
        self.sig = providers.get(self.sig_event.chosen)
        # responder keys (their long-term signature key, their KEM key for this session)
        self.sig_priv, self.sig_pub = self.sig.keygen()
        kem_priv, kem_pub = self.kem.keygen()
        # initiator encapsulates; responder signs the transcript and decapsulates
        ss_i, ct = self.kem.encapsulate(kem_pub)
        transcript = self.kem.meta.name.encode() + kem_pub + ct
        self.transcript_sig = self.sig.sign(self.sig_priv, transcript)
        if not self.sig.verify(self.sig_pub, transcript, self.transcript_sig):
            raise ConnectionError("transcript signature failed")
        ss_r = self.kem.decapsulate(kem_priv, ct)
        assert ss_i == ss_r
        self.key = ss_i
        self.wire_bytes = len(kem_pub) + len(ct) + len(self.transcript_sig) + len(self.sig_pub)

    def seal(self, msg: bytes) -> bytes:
        n = secrets.token_bytes(12)
        return n + AESGCM(self.key).encrypt(n, msg, None)

    def open(self, blob: bytes) -> bytes:
        return AESGCM(self.key).decrypt(blob[:12], blob[12:], None)


# ------------------------------------------------------------------ CLI

def main(argv: list[str] | None = None) -> int:
    import argparse
    p = argparse.ArgumentParser(description="Policy-driven algorithm negotiation with kill switch and rollback.")
    p.add_argument("--policy", default=str(HERE / "policies" / "policy-v3.yaml"))
    p.add_argument("--peer-policy", default=None, help="peer's policy file (default: same as ours)")
    p.add_argument("--date", default=None, help="evaluate rules as of YYYY-MM-DD")
    p.add_argument("--kill", default=None, help="disable this algorithm before negotiating")
    p.add_argument("--rollback", action="store_true", help="after --kill, roll back and negotiate again")
    p.add_argument("--json", default=None)
    a = p.parse_args(argv)
    now = dt.date.fromisoformat(a.date) if a.date else dt.date.today()
    ours = Policy.load(Path(a.policy)); theirs = Policy.load(Path(a.peer_policy)) if a.peer_policy else ours
    print(f"policy v{ours.version} ({ours.digest()}) as of {now}: kem usable {ours.usable('kem', now)}, sig usable {ours.usable('sig', now)}")
    steps = [("baseline", ours)]
    if a.kill:
        steps.append((f"kill {a.kill}", ours.with_kill(a.kill)))
        if a.rollback:
            steps.append(("rollback", steps[-1][1].rollback()))
    for label, pol in steps:
        try:
            ch = Channel(pol, theirs, now)
            print(f"{label:<18} v{pol.version}: kem {ch.kem_event.chosen} (L{ch.kem_event.quantum_level}{', DOWNGRADE' if ch.kem_event.downgrade else ''}"
                  f"{', deprecated-warn' if ch.kem_event.warned else ''}), sig {ch.sig_event.chosen}, {ch.wire_bytes} B handshake; "
                  f"round trip {'OK' if ch.open(ch.seal(b'hello')) == b'hello' else 'FAILED'}")
        except ConnectionError as e:
            print(f"{label:<18} v{pol.version}: FAILED: {e}")
    if a.json:
        Path(a.json).write_text(json.dumps([asdict(e) for e in TELEMETRY], indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
