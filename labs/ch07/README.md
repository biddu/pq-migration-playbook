# Labs 7.1–7.3 — a post-quantum private CA, its cost on the wire, and the renewal loop

**Lab 7.1** builds two-tier private CAs with OpenSSL 3.5 in seven algorithm profiles
(ECDSA baseline, ML-DSA-44/65/87, SLH-DSA root over ML-DSA, ML-DSA under a classical
root, classical leaf under an ML-DSA CA), issues server and client certificates and a
CRL, and validates the chain with both `openssl verify` and Python's `cryptography`.
**Lab 7.2** runs each hierarchy through a TLS 1.3 handshake behind the Chapter 5
observer and measures the server's first flight, with and without client
certificates. **Lab 7.3** is a minimal ACME client run against Pebble (Let's
Encrypt's test CA) plus the renewal arithmetic for the 47-day lifetime.

| File | What it is |
|---|---|
| `solution/pkilab.py` | CA builder (reference). `starter_pkilab.py` is your file. Writes `ca/<profile>/` and `results/hierarchies.json`. |
| `solution/chainsize.py` | Handshake measurement per profile; writes `results/chainsize.json`. Imports `labs/ch05/solution/tlsobserve.py`. |
| `solution/acmeclient.py` | RFC 8555 client: account, order, http-01, finalize; `--csr-key ML-DSA-65` to see the CA reject it. |
| `solution/renewal.py` | SC-081v3 schedule, renewal point, fleet renewals per day, CA capacity from the measured issuance time. |
| `pebble/` | Pebble config (47-day profile), its TLS certificate, `run.sh`. |
| `results/` | Reference outputs from the book's container (`*.txt` are the printed tables). |

```bash
export OPENSSL_BIN=/opt/openssl35/bin/openssl LD_LIBRARY_PATH=/opt/openssl35/lib64
python labs/ch07/solution/pkilab.py                      # seven hierarchies, ~10 s (SLH-DSA root takes the time)
python labs/ch07/solution/chainsize.py                   # fourteen handshakes through the observer
go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest
sh labs/ch07/pebble/run.sh &                             # ACME directory at https://127.0.0.1:14000/dir
python labs/ch07/solution/acmeclient.py --count 20 --json labs/ch07/results/acme_p256.json
python labs/ch07/solution/acmeclient.py --csr-key ML-DSA-65
python labs/ch07/solution/renewal.py --certs 1200
pytest labs/ch07/tests                                   # PQ_LAB_IMPL=solution pytest ... runs the reference
```

`ca/` is generated and disposable; nothing in it should ever be trusted by a real
system. The `cryptography` package in the reference container (50.0) verifies ML-DSA
chains but does not recognise SLH-DSA public keys; the SLH-DSA-root profile records that
result on purpose.
