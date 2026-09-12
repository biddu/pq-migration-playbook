# Labs 12.1–12.3 — the interoperability matrix, a timing-leak detector, and the test plan as code

**Lab 12.1** runs every TLS implementation in the lab estate against every other, for every
hybrid group, reading the negotiated group from the wire with the Chapter 5 observer: OpenSSL 3.5,
Go 1.24 `crypto/tls` (the small program in `gotls/`), and the system Python `ssl` module. The
matrix is run twice, with Python loading the system OpenSSL 3.0 and with it loading OpenSSL 3.5
via `LD_LIBRARY_PATH`, because the same Python is classical or post-quantum depending on which
shared library the loader finds. **Lab 12.2** is a dudect-style detector (Welch's t on two input
classes) applied to a leaky toy FO decapsulation, a constant-time one, an early-exit compare,
`hmac.compare_digest`, and `cryptography`'s ML-KEM-768 decapsulation. **Lab 12.3** runs the
migration test plan (`templates/migration_test_plan.md`) as an executable over the whole lab estate
and writes a report; the rollout runbook is `templates/rollout_runbook.md`.

| File | What it is |
|---|---|
| `solution/interop.py` | Matrix harness; writes `results/interop.json` (+ `.txt`). `OPENSSL_LD_LIBRARY_PATH` keeps the CLI's libssl separate from Python's. |
| `gotls/main.go` | Go TLS 1.3 server/client with `-groups`; `go build -o gotls .` inside `gotls/`. |
| `solution/timing.py` | Detector and targets; writes `results/timing.json`. `starter_timing.py` is your file. |
| `solution/testplan.py` | Executable test plan over labs ch01–ch11 + the matrix + the detector + the drill; writes `results/testplan_report.md`. |
| `results/` | Reference outputs, including both interop matrices and the test-plan report. |

```bash
(cd labs/ch12/gotls && go build -o gotls .)
export OPENSSL_BIN=/opt/openssl35/bin/openssl OPENSSL_LD_LIBRARY_PATH=/opt/openssl35/lib64
python labs/ch12/solution/interop.py interop.json            # pyssl on the system libssl
LD_LIBRARY_PATH=/opt/openssl35/lib64 python labs/ch12/solution/interop.py interop_pyssl35.json
python labs/ch12/solution/timing.py 4000                      # ~1 min
python labs/ch12/solution/testplan.py                         # ~15 min: runs every chapter's tests
pytest labs/ch12/tests                                        # PQ_LAB_IMPL=solution pytest ... runs the reference
```

The detector cannot prove the absence of a leak; it can only fail to find one at a given sample
size on a given machine, which is why the plan also asks for the library's constant-time statement
and its compiler flags. Go 1.24 supports only X25519MLKEM768 and does not expose the negotiated
group in `ConnectionState` (Go 1.25 adds `CurveID`), which is why the harness reads it from the wire.
