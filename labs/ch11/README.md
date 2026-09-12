# Labs 11.1–11.2 — a provider layer, policy-as-code, the kill switch, and property tests for agility

**Lab 11.1** builds the two layers an agile system needs: a *provider* layer (`providers.py`)
with one interface per primitive (KEM, signature) and several implementations behind it, each
carrying metadata (NIST quantum level, family, sizes); and a *policy* layer (`agile.py`) that
reads a versioned YAML file and decides, as a pure function of (policy, peer offer, date),
which algorithm a connection uses — with preference order, a quantum-level floor, dated
deprecations, a kill switch, rollback, and a telemetry event per decision. `Channel` runs a
KEM + AES-GCM + signature "connection" between two policies end to end.
**Lab 11.2** is the proof: `drill.py` rehearses the kill-switch and rollback path on a schedule,
and `tests/test_ch11.py` uses Hypothesis to generate random policies, offers and dates and
asserts the eight invariants the chapter states (no downgrade below the floor, killed and
date-disallowed algorithms never chosen, rollback restores the digest, one event per decision,
a broken hybrid falls to pure PQ and never to classical).

| File | What it is |
|---|---|
| `solution/providers.py` | KEM/Signature interfaces, X25519 / ML-KEM-768 / X-Wing and Ed25519 / ML-DSA-65 providers, registry. |
| `solution/agile.py` | `Policy` (load/validate/usable/with_kill/rollback), `negotiate`, `Event`, `TELEMETRY`, `Channel`, CLI. `starter_agile.py` is your file. |
| `solution/drill.py` | The kill-switch drill; writes `results/drill.json`. |
| `policies/policy-v3.yaml` | The running example's policy: the one place algorithm choices live. `peer-legacy.yaml` is a classical-only peer. |
| `tests/test_ch11.py` | Property tests P1–P8 (Hypothesis) plus validation and end-to-end tests. |

```bash
pip install hypothesis pyyaml
python labs/ch11/solution/agile.py                                   # negotiate under policy-v3
python labs/ch11/solution/agile.py --kill X-Wing --rollback          # swap, then roll back
python labs/ch11/solution/agile.py --date 2031-06-01                 # X25519 past its disallow date
python labs/ch11/solution/agile.py --peer-policy labs/ch11/policies/peer-legacy.yaml
python labs/ch11/solution/drill.py                                   # the rehearsal; run it in CI on a schedule
pytest labs/ch11/tests                                               # PQ_LAB_IMPL=solution pytest ... runs the reference
```

`agile.py` is a model of the pattern, not a TLS stack: the same rules live, for real systems, in
OpenSSL's provider and configuration layers, in RHEL's `crypto-policies`, in Java's
`jdk.tls.namedGroups`, and in whatever feature-flag system your services already use. The
point of the lab is that each of the four verbs (swap, negotiate, roll back, observe) is one
file edit or one function, and that the invariants can be tested rather than asserted.
