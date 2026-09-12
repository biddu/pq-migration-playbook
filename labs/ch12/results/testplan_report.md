# Migration test plan -- run report

Generated 2026-09-12 17:35:55 on the lab estate.

| Section | Check | Status | Detail |
|---|---|---|---|
| 1 correctness | ch01 acceptance tests | PASS | 9 passed |
| 1 correctness | ch02 acceptance tests | PASS | 16 passed |
| 1 correctness | ch03 acceptance tests | PASS | 10 passed |
| 1 correctness | ch04 acceptance tests | PASS | 6 passed |
| 1 correctness | ch05 acceptance tests | PASS | 6 passed |
| 1 correctness | ch06 acceptance tests | PASS | 8 passed |
| 1 correctness | ch07 acceptance tests | PASS | 9 passed, 1 skipped |
| 1 correctness | ch08 acceptance tests | PASS | 10 passed |
| 1 correctness | ch09 acceptance tests | PASS | 15 passed |
| 1 correctness | ch10 acceptance tests | PASS | 9 passed |
| 1 correctness | ch11 acceptance tests | PASS | 9 passed |
| 2 known-answer | RFC 8554 Test Case 1 verifies (LMS/HSS) | PASS | 1 passed |
| 2 known-answer | X-Wing keygen matches draft vector | PASS | 1 passed |
| 2 known-answer | X-Wing decapsulation matches draft vector | PASS | 1 passed |
| 2 known-answer | FIPS 204 ML-DSA-65 sizes | PASS | 1 passed |
| 2 known-answer | CAVP/ACVP vectors for the production library | MANUAL | attach the CAVP certificate numbers or ACVP run for the library versions in the CBOM (plan section 2.3) |
| 3 interoperability | openssl server <- openssl client, X25519MLKEM768 | PASS | negotiated X25519MLKEM768, ClientHello 1418 B |
| 3 interoperability | openssl server <- go client, X25519MLKEM768 | PASS | negotiated X25519MLKEM768, ClientHello 1412 B |
| 3 interoperability | go server <- openssl client, X25519MLKEM768 | PASS | negotiated X25519MLKEM768, ClientHello 1418 B |
| 3 interoperability | go server <- go client, X25519MLKEM768 | PASS | negotiated X25519MLKEM768, ClientHello 1412 B |
| 3 interoperability | known gaps are known | INFO | 15 cells not configurable, 10 handshake failures; pyssl on OpenSSL 3.0.13 (no post-quantum groups) |
| 4 side channels | toy FO, leaky rejection | PASS | t = -186.83, leak (expected); detector sanity check |
| 4 side channels | toy FO, constant-time | PASS | t = 0.56, no leak (expected); detector sanity check |
| 4 side channels | early-exit compare | PASS | t = 759.26, leak (expected); detector sanity check |
| 4 side channels | hmac.compare_digest | PASS | t = 1.99, no leak (expected); library under test |
| 4 side channels | cryptography ML-KEM-768 decapsulate | PASS | t = 2.72, no leak (expected); library under test |
| 4 side channels | constant-time claims of the production library | MANUAL | the detector cannot prove absence; attach the vendor's/library's constant-time statement and CAVP/CMVP status (plan 4.2) |
| 5 performance | hybrid KEX handshake time ratio | PASS | 1.00x vs budget 1.1x (Lab 5.3) |
| 5 performance | ML-DSA-65 certificate handshake time ratio | PASS | 2.09x vs budget 2.5x (Lab 5.3) |
| 5 performance | ML-DSA-65 verify on 4 MiB vs Ed25519 | PASS | 1.80x vs budget 2.5x (Lab 8.1) |
| 5 performance | production p99 handshake latency on the canary | MANUAL | measure on the real path; the loopback ratios above do not include the extra round trip (plan 5.2) |
| 6 agility | kill-switch drill | PASS | telemetry events: 300, downgrades flagged: 0, drill PASSED |
| 7 rollback | rollback restored policy digest and choices | PASS | 0.141 s; 0 downgrades flagged during drill |
| 7 rollback | production rollback rehearsed within the last quarter | MANUAL | date and duration of the last rehearsal against production configuration (runbook section R3) |

Summary: INFO 1, MANUAL 4, PASS 29
