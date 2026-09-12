# Labs 5.1–5.3 — Hybrid key exchange in TLS 1.3, measured

**Lab 5.1** is a TLS record observer: a TCP relay that logs every record and
parses the plaintext ClientHello / ServerHello / HelloRetryRequest, so the
hybrid key shares, the selected group and the byte budget are visible without
packet-capture privileges. **Lab 5.2** drives OpenSSL 3.5 through it for five
group configurations and two certificate types, including a forced
HelloRetryRequest. **Lab 5.3** measures handshake throughput with `s_time`.

| File | What it is |
|---|---|
| `solution/tlsobserve.py` | The observer (reference). `starter_tlsobserve.py` is your file. |
| `solution/handshakes.py` | Runs the scenarios; writes `results/handshakes.json`. |
| `solution/loadtest.py` | `s_time` comparison; writes `results/loadtest.json`. |
| `certs/` | ECDSA P-256 and ML-DSA-65 self-signed certs, plus two-certificate chains of each. |
| `fixtures/` | Raw byte streams of three handshakes (classical, hybrid, HRR) for offline tests. |
| `tests/test_ch05.py` | Parser tests offline; one live test if OpenSSL 3.5+ is available. |

```bash
# OpenSSL 3.5+ is required for the live labs. If your system OpenSSL is older:
export OPENSSL_BIN=/opt/openssl35/bin/openssl LD_LIBRARY_PATH=/opt/openssl35/lib64
pytest labs/ch05/tests
python labs/ch05/solution/handshakes.py
python labs/ch05/solution/loadtest.py 5
# by hand: server, relay, client in three terminals
$OPENSSL_BIN s_server -accept 4433 -cert labs/ch05/certs/ecdsa.crt -key labs/ch05/certs/ecdsa.key -tls1_3 -groups X25519MLKEM768:X25519 -quiet
python labs/ch05/solution/tlsobserve.py --listen 4434 --upstream 127.0.0.1:4433
$OPENSSL_BIN s_client -connect 127.0.0.1:4434 -tls1_3 -brief </dev/null
```

Tested with: Python 3.12, OpenSSL 3.5.4, pytest 9.
