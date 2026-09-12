# Labs 3.1–3.3 — Inventory, CBOM, TLS scan, and change report

**Lab 3.1** scans a source tree with the rules in `rules.yaml`, parses any
certificates it finds, and writes a CycloneDX 1.6 CBOM that validates against
the real schema. **Lab 3.2** scans TLS endpoints (`openssl s_client -brief`)
and merges what they negotiate into the same CBOM. **Lab 3.3** diffs two CBOMs
into a Markdown change report.

| File | What it is |
|---|---|
| `rules.yaml` | Discovery rules: one regex per call site or config directive, mapped to an asset. Extend this, not the scanner. |
| `sample_service/` | The fixture tree: Python API, Go gateway, nginx, sshd, an RSA certificate. |
| `starter_cbomscan.py` | Your file for Lab 3.1. |
| `solution/cbomscan.py`, `tlsmerge.py`, `cbomdiff.py`, `validate.py` | Reference solutions. |
| `fixtures/` | Saved `s_client -brief -showcerts` output for three hosts, for offline scanning and tests. |
| `schema/` | CycloneDX 1.6 JSON schema and its two dependencies, for validation. |
| `results/` | Outputs from the reference run. |
| `tests/test_ch03.py` | Acceptance tests. |

```bash
pip install pyyaml "cryptography>=48" jsonschema pytest
pytest labs/ch03/tests                       # tests your starter
PQ_LAB_IMPL=solution pytest labs/ch03/tests  # tests the reference

cd labs/ch03
python solution/cbomscan.py sample_service --name payments-gateway
python solution/validate.py results/sample_service.cbom.json
python solution/tlsmerge.py fixtures/hosts.txt --fixtures fixtures --cbom results/sample_service.cbom.json -o results/merged.cbom.json
python solution/tlsmerge.py my_hosts.txt --cbom results/sample_service.cbom.json -o results/live.cbom.json   # live; needs OpenSSL 3.5+
python solution/cbomdiff.py results/sample_service.cbom.json results/merged.cbom.json -o results/change_report.md
```

Tested with: Python 3.12, PyYAML 6.0, cryptography 50.0, jsonschema 4.26, pytest 9.
