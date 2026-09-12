"""Lab 9.2 STARTER -- ML-DSA-signed JWTs (RFC 9964) and the header budget they have to fit.

RFC 9964 (May 2026) registers "ML-DSA-44", "ML-DSA-65" and "ML-DSA-87" as JOSE `alg`
values and a new JWK key type "AKP" (Algorithm Key Pair) with `pub` and `priv` members,
the private key being the 32-byte seed. This module issues and verifies compact JWS tokens
with those algorithms (and ES256 / EdDSA as baselines), using a realistic OpenID Connect
ID-token payload, then measures the token against the places a token has to fit:

  cookie           4,096 B    RFC 6265 minimum a user agent must accept per cookie
  nginx header     8,192 B    large_client_header_buffers default (one header line)
  Apache header    8,190 B    LimitRequestFieldSize default
  ALB/CloudFront   16,384 B   typical per-request header total on managed load balancers
  Node.js headers  16,384 B   --max-http-header-size default (all headers)

The budgets are defaults and vary by deployment; the point is that a token which fit in a
cookie with ES256 does not with ML-DSA-65, and the fix is architectural (opaque reference
tokens, or a different algorithm), not a configuration flag.

Tested with: Python 3.11/3.12, cryptography 50.0.
"""
from __future__ import annotations

import base64
import json
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, mldsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

HERE = Path(__file__).resolve().parent          # labs/chNN (the solution lives one level deeper)

BUDGETS = {"cookie (RFC 6265 min)": 4096, "nginx header line": 8192, "Apache header line": 8190,
           "ALB/CloudFront headers": 16384, "Node.js all headers": 16384}

MLDSA = {"ML-DSA-44": mldsa.MLDSA44PrivateKey, "ML-DSA-65": mldsa.MLDSA65PrivateKey, "ML-DSA-87": mldsa.MLDSA87PrivateKey}


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# ------------------------------------------------------------------ keys and JWKs

class Signer:
    def __init__(self, alg: str, kid: str = "2026-09-k1"):
        self.alg, self.kid = alg, kid
        if alg in MLDSA:
            self.key = MLDSA[alg].generate()
        elif alg == "ES256":
            self.key = ec.generate_private_key(ec.SECP256R1())
        elif alg == "EdDSA":
            self.key = ed25519.Ed25519PrivateKey.generate()
        else:
            raise ValueError(alg)

    def public_jwk(self) -> dict:
        if self.alg in MLDSA:                                    # RFC 9964: kty AKP, alg required, pub = raw public key
            return {"kty": "AKP", "alg": self.alg, "kid": self.kid, "pub": b64u(self.key.public_key().public_bytes_raw())}
        if self.alg == "ES256":
            n = self.key.public_key().public_numbers()
            return {"kty": "EC", "crv": "P-256", "kid": self.kid, "x": b64u(n.x.to_bytes(32, "big")), "y": b64u(n.y.to_bytes(32, "big"))}
        return {"kty": "OKP", "crv": "Ed25519", "kid": self.kid, "x": b64u(self.key.public_key().public_bytes_raw())}

    def sign(self, signing_input: bytes) -> bytes:
        if self.alg in MLDSA:
            return self.key.sign(signing_input)                  # pure ML-DSA, empty context, per RFC 9964
        if self.alg == "ES256":
            r, s = decode_dss_signature(self.key.sign(signing_input, ec.ECDSA(hashes.SHA256())))
            return r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return self.key.sign(signing_input)


def verify(jwk: dict, token: str) -> dict:
    """TODO: split the compact JWS; decode header; dispatch on alg: AKP pub -> MLDSA*PublicKey.from_public_bytes(...).verify(sig, signing_input); ES256 -> raw r||s to DER; EdDSA raw; return payload claims"""
    raise NotImplementedError("verify")



# ------------------------------------------------------------------ tokens

def id_token_claims(now: int = 1_757_678_400) -> dict:
    """A realistic OpenID Connect ID token payload (about 350 bytes of JSON)."""
    return {"iss": "https://login.example.test", "sub": "248289761001", "aud": "s6BhdRkqt3",
            "exp": now + 3600, "iat": now, "auth_time": now - 30, "nonce": "n-0S6_WzA2Mj",
            "acr": "urn:mace:incommon:iap:silver", "amr": ["pwd", "otp"], "azp": "s6BhdRkqt3",
            "email": "alice@example.test", "email_verified": True, "name": "Alice Example",
            "groups": ["payments-ops", "sre", "oncall-eu"], "sid": "08a5019c-17e1-4977-8f42-65a12843ea02"}


def issue(signer: Signer, claims: dict, extra_header: dict | None = None) -> str:
    """TODO: header {alg, typ: JWT, kid, **extra}; base64url(header).base64url(payload); signature over the ASCII signing input; return the three parts joined by dots"""
    raise NotImplementedError("issue")



def fits(token_bytes: int) -> dict:
    """TODO: header line = len("Authorization: Bearer ") + token_bytes + 2 (CRLF); compare with each BUDGETS entry"""
    raise NotImplementedError("fits")



def main() -> int:
    claims = id_token_claims()
    rows = []
    for alg in ("ES256", "EdDSA", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"):
        s = Signer(alg); jwk = s.public_jwk()
        tok = issue(s, claims)
        assert verify(jwk, tok)["sub"] == claims["sub"]
        t0 = time.perf_counter(); [issue(s, claims) for _ in range(50)]; sign_ms = (time.perf_counter() - t0) * 20
        t0 = time.perf_counter(); [verify(jwk, tok) for _ in range(50)]; ver_ms = (time.perf_counter() - t0) * 20
        h64, p64, s64 = tok.split(".")
        row = {"alg": alg, "token_bytes": len(tok), "header_b64": len(h64), "payload_b64": len(p64), "signature_b64": len(s64),
               "signature_raw": len(b64d(s64)), "jwk_bytes": len(json.dumps(jwk, separators=(",", ":"))),
               "sign_ms": round(sign_ms, 3), "verify_ms": round(ver_ms, 3), "fits": fits(len(tok))}
        rows.append(row)
        print(f"{alg:<10} token {len(tok):>5} B  (sig {len(b64d(s64)):>4} raw / {len(s64):>4} b64)  JWK {row['jwk_bytes']:>5} B  "
              f"sign {sign_ms:6.3f} ms  verify {ver_ms:6.3f} ms  cookie {'yes' if row['fits']['cookie (RFC 6265 min)'] else 'NO '}")
    # the x5c case: an ML-DSA-65 certificate chain embedded in the header
    cert_dir = HERE.parent / "ch07" / "ca" / "mldsa65"
    if (cert_dir / "server.crt").exists():
        from cryptography import x509
        certs = [x509.load_pem_x509_certificate(p.read_bytes()) for p in (cert_dir / "server.crt", cert_dir / "issuing.crt")]
        x5c = [base64.b64encode(c.public_bytes(__import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.DER)).decode() for c in certs]
        s = Signer("ML-DSA-65"); tok = issue(s, claims, {"x5c": x5c})
        rows.append({"alg": "ML-DSA-65 + x5c (2 certs)", "token_bytes": len(tok), "fits": fits(len(tok))})
        print(f"{'ML-DSA-65+x5c':<10} token {len(tok):>5} B with a two-certificate ML-DSA-65 chain in the header")
    print("\nbudget" + " " * 22 + "".join(f"{r['alg'][:14]:>16}" for r in rows))
    for name, limit in BUDGETS.items():
        print(f"{name:<22} {limit:>5} B" + "".join(f"{('fits' if r['fits'][name] else 'NO'):>16}" for r in rows))
    (HERE / "results").mkdir(exist_ok=True)
    (HERE / "results" / "jws.json").write_text(json.dumps(rows, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
