# Labs 10.1–10.3 — auditing an HSM interface for post-quantum readiness, sizing the key estate, and a cloud KMS

**Lab 10.1** audits any PKCS#11 module against the post-quantum mechanisms of PKCS#11 v3.2
(OASIS Standard, June 2026), resolving mechanism numbers with the real 3.2 header, and
generates the procurement requirements line from the gap. SoftHSM 2.6 is the honest
baseline (Cryptoki 2.40, no PQ mechanisms); a mock 3.2 token shows a passing report.
**Lab 10.2** sizes a key estate against object-store and throughput ceilings, shows what the
seed form does to backup and ceremony, and demonstrates ML-DSA external-μ signing (64 bytes
to the module, whatever the artefact size). **Lab 10.3** (optional, needs an AWS account)
creates and uses an ML-DSA key in AWS KMS, or prints the request shapes without one.

| File | What it is |
|---|---|
| `solution/p11audit.py` | Header parser, module enumeration, gap report, requirements line, mock token. `starter_p11audit.py` is your file. |
| `solution/hsmplan.py` | Storage/throughput/backup calculator and `mu_offload()`. |
| `solution/kms_mldsa.py` | AWS KMS ML-DSA: dry-run request bodies, or `--live`. |
| `fixtures/pkcs11t-v3.2.h` | The OASIS PKCS#11 v3.2 type header (mechanism, key-type, parameter-set and flag constants). |
| `softhsm/` | `init.sh` and config for a throwaway SoftHSM token. |
| `results/` | Reference outputs: `softhsm_audit.json`, `mock_audit.json`, `hsmplan.json/.txt`. |

```bash
sh labs/ch10/softhsm/init.sh && export SOFTHSM2_CONF=$PWD/labs/ch10/softhsm/softhsm2.conf
python labs/ch10/solution/p11audit.py --requirements                 # SoftHSM: NOT READY, and the RFP sentence
python labs/ch10/solution/p11audit.py --module /path/to/vendor-pkcs11.so --token <label> --json audit.json
python labs/ch10/solution/p11audit.py --mock                         # what READY looks like
python labs/ch10/solution/hsmplan.py --object-store-bytes ... --ecdsa-rate ... --pq-rate ...   # vendor figures
python labs/ch10/solution/kms_mldsa.py                               # dry run; add --live with credentials
pytest labs/ch10/tests                                               # PQ_LAB_IMPL=solution pytest ... runs the reference
```

Vendor mechanism numbers below 3.2 are vendor-defined (≥ 0x80000000); the audit marks them and
the verdict becomes NOT PORTABLE rather than NOT READY, which is the right question to put to
the vendor. HSM storage and throughput figures in `hsmplan.py` are illustrative defaults;
replace them with your data sheet's, or measure.
