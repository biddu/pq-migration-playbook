# CBOM change report: sample_service.cbom.json -> merged.cbom.json

**Added (6)**

- `ECDSA-SHA256` (ECDSA-SHA256): tls://edge.payments.example:443:0
- `TLS group X25519MLKEM768` (X25519MLKEM768): tls://edge.payments.example:443:0
- `TLS signature RSA-PSS` (RSA-PSS): tls://api.payments.example:443:0
- `TLS signature ecdsa_secp256r1_sha256` (ecdsa_secp256r1_sha256): tls://edge.payments.example:443:0
- `C=IE,O=Payments Ltd,CN=edge.payments.example`: tls://edge.payments.example:443:0
- `TLS` (unreachable): tls://legacy.payments.example:8443:0

**Removed (0)**


**Changed (7)**

- `ECDSA` (P-256): new sites tls://edge.payments.example:443:0
- `RSA` (RSA-2048): new sites tls://api.payments.example:443:0
- `RSA-SHA256` (RSA-SHA256): new sites tls://api.payments.example:443:0
- `TLS group X25519` (X25519): new sites tls://api.payments.example:443:0
- `C=IE,O=Payments Ltd,CN=api.payments.example`: new sites tls://api.payments.example:443:0
- `TLS` (1.2): new sites tls://api.payments.example:443:0
- `TLS` (1.3): new sites tls://edge.payments.example:443:0

**Still quantum-vulnerable in merged.cbom.json (16)**

- `ECDSA` (P-256)
- `ECDSA-SHA256` (ECDSA-SHA256)
- `JWS RS256` (RS256)
- `RSA` (RSA-2048)
- `RSA-OAEP` (RSA-OAEP)
- `RSA-SHA256` (RSA-SHA256)
- `SHA-1` (SHA-1)
- `SSH KEX curve25519-sha256` (curve25519-sha256)
- `SSH KEX ecdh-sha2-nistp256` (ecdh-sha2-nistp256)
- `SSH host key ed25519` (ed25519)
- `SSH host key rsa` (rsa)
- `TLS group CurveP256` (CurveP256)
- `TLS group X25519` (X25519)
- `TLS group prime256v1` (prime256v1)
- `TLS signature RSA-PSS` (RSA-PSS)
- `TLS signature ecdsa_secp256r1_sha256` (ecdsa_secp256r1_sha256)
