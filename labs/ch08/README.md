# Labs 8.1–8.2 — signing artefacts, and the state failure of stateful hashes

**Lab 8.1** signs a boot header and a firmware image with every signature family the
chapter weighs (classical, ML-DSA, SLH-DSA, LMS) and tabulates public-key size,
signature size, keygen, sign and verify time, and how many signatures a key can make.
**Lab 8.2** is an LMS/HSS implementation (RFC 8554, SP 800-208) built to be read: it
verifies the RFC's own test vector, then shows what happens when the one-time-key index
`q` is mishandled — a working forgery from public information — and then fixes it with
committed state.

| File | What it is |
|---|---|
| `solution/lms.py` | LM-OTS + LMS + enough HSS to verify RFC 8554 TC1; three private-key classes; the forgery. `starter_lms.py` is your file. |
| `solution/signbench.py` | Lab 8.1 benchmark across all families; writes `results/signbench.json`. |
| `solution/statefail.py` | Lab 8.2 story: reuse, forge, fix; writes `results/statefail.json`. |
| `fixtures/rfc8554_tc1.json` | RFC 8554 Appendix F Test Case 1 (public key, message, signature). |
| `results/` | Reference outputs from the book's container. |

```bash
export LD_LIBRARY_PATH=/opt/openssl35/lib64        # only for the OpenSSL-backed comparison, if you add one
pytest labs/ch08/tests                             # PQ_LAB_IMPL=solution pytest ... runs the reference
python labs/ch08/solution/signbench.py             # ~10 min: SLH-DSA-256s signing and LMS H10 keygen are the slow rows
python labs/ch08/solution/statefail.py             # reuse -> forgery -> committed-state fix
```

The forgery in `statefail.py` is real: with four signatures that reused one W=8 one-time
key it produces a valid signature on an attacker-chosen message in well under a second,
using only the public key and the published signatures. Two reused signatures are enough
in principle but need tens of millions of tries; the lab shows the search getting cheaper
with each extra reuse. This is why SP 800-208 requires the signing state to live in
validated hardware, and why NSA's CNSA 2.0 prefers LMS/XMSS only where a signer can
guarantee it. `lms.py` is a teaching implementation — do not sign anything real with it.
