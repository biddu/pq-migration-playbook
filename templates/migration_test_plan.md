# Post-quantum migration test plan (template)

Fill in per population (edge TLS, service mesh, SSH fleet, PKI, signing service, storage, tokens).
Every check is one of: an automated test with a command and a pass criterion, or a MANUAL item
with the evidence to attach. `labs/ch12/solution/testplan.py` is a worked instance over the
book's lab estate; adapt its sections to yours. Owner and date on every row.

Population: ______________________  Owner: ______________  Policy version under test: ______

## 1. Correctness (automated)
1.1 Unit and acceptance tests of every component that changed (library, configuration, provider layer)
    pass in CI. Command: ____________  Criterion: 0 failures.
1.2 Round trips: encapsulate/decapsulate, sign/verify, wrap/unwrap for every algorithm in the policy,
    across the language runtimes in the population. Criterion: all pass; tampered inputs rejected
    (or, for KEMs, yield a different key without error: implicit rejection).
1.3 Negative tests: the classical-only peer, the unknown group, the oversized token, the header past
    the budget. Criterion: each fails the way the design says (fallback, HRR, hard fail, 431).

## 2. Known-answer tests (automated + evidence)
2.1 Standards' own vectors pass against the deployed library version: FIPS 203/204/205 (ACVP),
    RFC 8554 (LMS), X-Wing draft Appendix C, RFC 9881 encodings. Criterion: byte-exact.
2.2 Sizes match the standards: ML-KEM-768 1,184/1,088/32; ML-DSA-65 1,952/3,309; X-Wing 1,216/1,120.
2.3 MANUAL: CAVP certificate numbers for the algorithm implementations in the CBOM; CMVP certificate or
    submission date for any module that must be validated (Chapters 8, 10). Attach.

## 3. Interoperability (automated matrix)
3.1 Every (server implementation, client implementation, group/algorithm) pair that production
    requires is in the matrix and OK, with the negotiated algorithm read from the wire (Chapter 5
    observer), not from either side's log. Command: `labs/ch12/solution/interop.py` adapted.
3.2 Every cell marked n/s (cannot be configured) or FAIL is listed with an owner and a date, or an
    explicit "accepted: fallback to ___".
3.3 The matrix is re-run on every library, runtime or OS crypto-policy change, and on a schedule.
3.4 MANUAL: browser and mobile clients against the edge (Chapter 5's one-command test from each).

## 4. Side channels and implementation hygiene
4.1 Detector sanity: the dudect-style test flags a known-leaky toy and passes a constant-time one on
    the CI machine (so a "no leak" result means something). Command: `labs/ch12/solution/timing.py`.
4.2 No leak found (|t| < 4.5 at n >= 10,000) for decapsulation with valid vs tampered ciphertext and
    for signature verification with valid vs invalid signature, on the deployed library. MANUAL: the
    library's constant-time statement; compiler and flags used for the build (KyberSlash, clangover).
4.3 Randomness: keys and hedged signatures come from the platform DRBG; seeds are never logged;
    seed-form private keys (32/64 bytes) are handled as the key, not as configuration.
4.4 Comparisons of tags, MACs and re-encrypted ciphertexts use constant-time primitives.

## 5. Performance budgets (automated where possible)
5.1 Loopback ratios vs the classical baseline within budget: hybrid KEX handshake time <= 1.10x;
    ML-DSA-65 certificate handshake <= 2.5x; ML-DSA verify on a large artefact <= 2.5x Ed25519.
5.2 MANUAL: on the real path, p50/p99 handshake latency and error rate on the canary vs control;
    server first-flight size vs the initial congestion window (Chapter 7 Table); token sizes vs cookie
    and header limits (Chapter 9 Table). Budgets: ________ ms p99, ________ % errors.
5.3 CPU: handshakes per core per second before and after; capacity plan updated.

## 6. Agility (automated)
6.1 The policy file validates; every algorithm in it has a provider; preferred == allowed.
6.2 Property tests pass: no choice below the floor; killed and date-disallowed algorithms never chosen;
    one telemetry event per decision; rollback restores the digest (Chapter 11 Lab 11.2).
6.3 The kill-switch drill passes with the victim rotating through every algorithm in the policy, and
    reports zero downgrades where the floor permits classical fallback.

## 7. Rollout and rollback (runbook, rehearsed)
7.1 The rollout runbook (templates/rollout_runbook.md) is filled in for this population.
7.2 Rollback has been rehearsed against production configuration within the last quarter: date ____,
    time-to-last-reload ____ s, downgrades observed ____.
7.3 Telemetry alarms are live before the first canary: downgrade events, warned-algorithm use,
    negotiation-failure rate after a policy digest change.

Sign-off: engineering ______  security ______  operations ______  date ______
