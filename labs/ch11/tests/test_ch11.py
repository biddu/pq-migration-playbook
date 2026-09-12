"""Lab 11.2 (part 2) -- property tests for the agile layer.

Hypothesis generates random policies, peer offers and dates, and these tests assert the
invariants the chapter says an agile system must hold:

  P1  the negotiated algorithm is in both parties' usable lists (never invents, never leaks)
  P2  a killed algorithm is never chosen, whatever the peer offers
  P3  an algorithm past its disallow_after date is never chosen
  P4  with floor >= 1, a level-0 algorithm is never chosen (the "remove the old path" state)
  P5  with floor 0, a level-0 choice while a higher common option existed is flagged as a downgrade
  P6  rollback restores the previous policy exactly (same digest)
  P7  every negotiation emits exactly one telemetry event, success or failure
  P8  (simulated deprecation) killing the preferred hybrid falls to the pure PQ KEM, never to classical,
      as long as the pure PQ KEM is common

Run with PQ_LAB_IMPL=solution for the reference; the starter's negotiate() and usable() are stubs.
"""
import datetime as dt
import importlib
import os
import sys
from pathlib import Path

import pytest
from hypothesis import given, settings, strategies as st

HERE = Path(__file__).resolve().parent.parent
use_solution = os.environ.get("PQ_LAB_IMPL", "starter") == "solution"
sys.path.insert(0, str(HERE / "solution"))
if not use_solution:
    sys.path.insert(0, str(HERE))
try:
    agile = importlib.import_module("agile" if use_solution else "starter_agile")
except ModuleNotFoundError:
    agile = importlib.import_module("agile")
providers = importlib.import_module("providers")

KEMS = providers.available("kem")            # X25519, ML-KEM-768, X-Wing
SIGS = providers.available("sig")            # Ed25519, ML-DSA-65
DATES = st.dates(min_value=dt.date(2026, 1, 1), max_value=dt.date(2036, 12, 31))


@st.composite
def policies(draw):
    kem = draw(st.permutations(KEMS).filter(lambda p: len(p) >= 1))
    kem = list(kem[: draw(st.integers(min_value=1, max_value=len(kem)))])
    sig = list(draw(st.permutations(SIGS)))
    sig = sig[: draw(st.integers(min_value=1, max_value=len(sig)))]
    deps = {}
    for a in draw(st.lists(st.sampled_from(KEMS + SIGS), unique=True, max_size=3)):
        warn = draw(DATES); dis = draw(st.dates(min_value=warn, max_value=dt.date(2036, 12, 31)))
        deps[a] = {"warn_after": warn, "disallow_after": dis}
    kill = draw(st.lists(st.sampled_from(KEMS + SIGS), unique=True, max_size=2))
    return agile.Policy.from_dict({"version": draw(st.integers(min_value=1, max_value=50)),
                                   "kem": {"preferred": kem, "allowed": kem, "floor": draw(st.integers(min_value=0, max_value=3))},
                                   "sig": {"preferred": sig, "allowed": sig, "floor": draw(st.integers(min_value=0, max_value=3))},
                                   "deprecations": deps, "kill_switch": kill})


offers = st.lists(st.sampled_from(KEMS), unique=True)


@settings(max_examples=300, deadline=None)
@given(policies(), offers, DATES)
def test_p1_choice_is_common_and_p7_one_event_per_negotiation(pol, offer, now):
    before = len(agile.TELEMETRY)
    ev = agile.negotiate(pol, "kem", offer, now)
    assert len(agile.TELEMETRY) == before + 1
    if ev.chosen is not None:
        assert ev.chosen in offer and ev.chosen in pol.usable("kem", now)
        assert ev.chosen == [a for a in pol.usable("kem", now) if a in offer][0]      # our preference order decides
    else:
        assert not [a for a in pol.usable("kem", now) if a in offer]


@settings(max_examples=300, deadline=None)
@given(policies(), offers, DATES)
def test_p2_killed_never_chosen(pol, offer, now):
    ev = agile.negotiate(pol, "kem", offer, now)
    assert ev.chosen not in pol.kill_switch


@settings(max_examples=300, deadline=None)
@given(policies(), offers, DATES)
def test_p3_disallowed_after_date_never_chosen(pol, offer, now):
    ev = agile.negotiate(pol, "kem", offer, now)
    if ev.chosen is not None:
        assert not pol.is_disallowed(ev.chosen, now)


@settings(max_examples=300, deadline=None)
@given(policies(), offers, DATES)
def test_p4_floor_forbids_classical(pol, offer, now):
    ev = agile.negotiate(pol, "kem", offer, now)
    if pol.kem_floor >= 1 and ev.chosen is not None:
        assert providers.get(ev.chosen).meta.quantum_level >= pol.kem_floor


@settings(max_examples=300, deadline=None)
@given(policies(), offers, DATES)
def test_p5_downgrade_flag_is_exact(pol, offer, now):
    ev = agile.negotiate(pol, "kem", offer, now)
    common = [a for a in pol.usable("kem", now) if a in offer]
    higher_available = any(providers.get(a).meta.quantum_level > 0 for a in common)
    expected = ev.chosen is not None and providers.get(ev.chosen).meta.quantum_level == 0 and higher_available
    assert ev.downgrade == expected


@settings(max_examples=100, deadline=None)
@given(policies(), st.sampled_from(KEMS + SIGS))
def test_p6_rollback_restores_digest(pol, victim):
    killed = pol.with_kill(victim)
    assert killed.version == pol.version + 1 and victim in killed.kill_switch
    assert killed.rollback().digest() == pol.digest()


def test_p8_simulated_break_of_hybrid_falls_to_pure_pq_not_classical():
    p = agile.Policy.load(HERE / "policies" / "policy-v3.yaml")
    now = dt.date(2029, 3, 1)
    assert agile.negotiate(p, "kem", KEMS, now).chosen == "X-Wing"
    broken = p.with_kill("X-Wing")                                  # "X-Wing has a flaw; kill it today"
    ev = agile.negotiate(broken, "kem", KEMS, now)
    assert ev.chosen == "ML-KEM-768" and ev.quantum_level == 3 and not ev.downgrade
    assert broken.rollback().digest() == p.digest()


def test_policy_validation_rejects_unknown_and_inconsistent():
    with pytest.raises(agile.PolicyError):
        agile.Policy.from_dict({"version": 1, "kem": {"preferred": ["Kyber-768"], "allowed": ["Kyber-768"]},
                                "sig": {"preferred": ["Ed25519"], "allowed": ["Ed25519"]}})
    with pytest.raises(agile.PolicyError):
        agile.Policy.from_dict({"version": 1, "kem": {"preferred": ["X-Wing"], "allowed": ["X-Wing", "X25519"]},
                                "sig": {"preferred": ["Ed25519"], "allowed": ["Ed25519"]}})


def test_channel_end_to_end_and_legacy_peer_fallback_is_not_a_downgrade():
    p = agile.Policy.load(HERE / "policies" / "policy-v3.yaml")
    legacy = agile.Policy.load(HERE / "policies" / "peer-legacy.yaml")
    ch = agile.Channel(p, p, dt.date(2026, 9, 12))
    assert ch.kem_event.chosen == "X-Wing" and ch.open(ch.seal(b"x")) == b"x"
    ch2 = agile.Channel(p, legacy, dt.date(2026, 9, 12))
    assert ch2.kem_event.chosen == "X25519" and not ch2.kem_event.downgrade      # fallback: the peer had nothing better
    with pytest.raises(ConnectionError):
        agile.Channel(p, legacy, dt.date(2031, 6, 1))                            # after X25519's disallow date: hard fail
