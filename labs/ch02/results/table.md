| Algorithm | Kind | Cat. | Public key (B) | Secret key (B) | Ciphertext / signature (B) | Keygen (us) | Encaps / sign (us) | Decaps / verify (us) | Source |
|---|---|---|---:|---:|---:|---:|---:|---:|---|
| X25519 | KEM | classical | 32 | 32 | 32 | 35 | 75 | 37 | cryptography |
| ML-KEM-512 | KEM | 1 | 800 | 1,632 | 768 | 12 | 9 | 10 | liboqs |
| ML-KEM-768 | KEM | 3 | 1,184 | 64 | 1,088 | 100 | 23 | 36 | cryptography (sk = 64-byte seed) |
| ML-KEM-1024 | KEM | 5 | 1,568 | 64 | 1,568 | 141 | 31 | 46 | cryptography (sk = 64-byte seed) |
| Ed25519 | SIG | classical | 32 | 32 | 64 | 35 | 35 | 115 | cryptography |
| ML-DSA-44 | SIG | 2 | 1,312 | 32 | 2,420 | 110 | 454 | 117 | cryptography (sk = 32-byte seed) |
| ML-DSA-65 | SIG | 3 | 1,952 | 32 | 3,309 | 196 | 778 | 182 | cryptography (sk = 32-byte seed) |
| ML-DSA-87 | SIG | 5 | 2,592 | 32 | 4,627 | 275 | 933 | 288 | cryptography (sk = 32-byte seed) |
| SLH-DSA-SHA2-128s | SIG | 1 | 32 | 64 | 7,856 | 77,481 | 585,590 | 597 | liboqs |
| SLH-DSA-SHA2-128f | SIG | 1 | 32 | 64 | 17,088 | 1,217 | 28,001 | 1,707 | liboqs |
| SLH-DSA-SHA2-192s | SIG | 3 | 48 | 96 | 16,224 | 113,174 | 1,079,396 | 878 | liboqs |
| SLH-DSA-SHA2-256s | SIG | 5 | 64 | 128 | 29,792 | 76,335 | 981,904 | 1,302 | liboqs |
| FN-DSA-512 (draft; Falcon-512) | SIG | 1 | 897 | 1,281 | 752 | 7,271 | 243 | 43 | liboqs |
| FN-DSA-1024 (draft; Falcon-1024) | SIG | 5 | 1,793 | 2,305 | 1,462 | 19,974 | 535 | 89 | liboqs |
| HQC-3 (selected; no FIPS yet) | KEM | 3 | 4,514 | 4,602 | 8,978 | 4,654 | 9,169 | 13,828 | liboqs |
