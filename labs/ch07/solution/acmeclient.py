"""Lab 7.3 solution -- a minimal ACME (RFC 8555) client, driven against a local Pebble server.

The point of the lab is not to replace certbot. It is to see every step a renewal takes
(account, order, authorization, http-01 challenge, CSR, finalize, download) as HTTP calls
you can read, then run the loop many times and measure it, because at 47-day lifetimes
the loop is the certificate programme.

  account key   ES256 (P-256), as every production client uses today; JWS per RFC 7515
  challenge     http-01, served by a thread on the port Pebble validates against (5002)
  CSR key       P-256 by default; --csr-key ML-DSA-65 shows what a Go-based CA does with a
                post-quantum CSR (a Go 1.24 build rejects it: the CA's library version decides)

Pebble is Let's Encrypt's small ACME test server (github.com/letsencrypt/pebble). Start it
with labs/ch07/pebble/run.sh; it listens on https://127.0.0.1:14000/dir with a self-signed
certificate whose PEM is in labs/ch07/pebble/. Pebble issues from its own ECDSA CA.

Tested with: Python 3.12, cryptography 50.0, Pebble v2 built with Go 1.24 (a Go 1.27 build has ML-DSA in crypto/x509 and may accept the CSR).
"""
from __future__ import annotations

import argparse
import base64
import http.server
import json
import ssl
import sys
import threading
import time
import urllib.request
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, mldsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

HERE = Path(__file__).resolve().parents[1]
DIRECTORY = "https://127.0.0.1:14000/dir"
PEBBLE_CA_PEM = HERE / "pebble" / "pebble.minica.pem"
CHALLENGE_PORT = 5002


def b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class Acme:
    def __init__(self, directory: str = DIRECTORY, account_key: ec.EllipticCurvePrivateKey | None = None,
                 verify_pem: Path = PEBBLE_CA_PEM):
        ctx = ssl.create_default_context(cafile=str(verify_pem)) if verify_pem.exists() else ssl._create_unverified_context()
        self.opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
        self.dir = json.loads(self.opener.open(directory).read())
        self.key = account_key or ec.generate_private_key(ec.SECP256R1())
        self.kid: str | None = None
        self.nonce: str | None = None
        self.calls: list[tuple[str, int]] = []

    # ---- JWS (RFC 8555 section 6.2; ES256 per RFC 7518)
    def jwk(self) -> dict:
        n = self.key.public_key().public_numbers()
        return {"kty": "EC", "crv": "P-256", "x": b64(n.x.to_bytes(32, "big")), "y": b64(n.y.to_bytes(32, "big"))}

    def sign(self, url: str, payload: dict | None) -> bytes:
        protected = {"alg": "ES256", "nonce": self.get_nonce(), "url": url}
        protected.update({"kid": self.kid} if self.kid else {"jwk": self.jwk()})
        p64 = b64(json.dumps(protected).encode())
        pl64 = "" if payload is None else b64(json.dumps(payload).encode())          # POST-as-GET has an empty payload
        der = self.key.sign(f"{p64}.{pl64}".encode(), ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return json.dumps({"protected": p64, "payload": pl64, "signature": b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))}).encode()

    def get_nonce(self) -> str:
        if self.nonce:
            n, self.nonce = self.nonce, None
            return n
        r = self.opener.open(urllib.request.Request(self.dir["newNonce"], method="HEAD"))
        return r.headers["Replay-Nonce"]

    def post(self, url: str, payload: dict | None) -> tuple[int, dict, dict | bytes]:
        req = urllib.request.Request(url, data=self.sign(url, payload), method="POST",
                                     headers={"Content-Type": "application/jose+json"})
        try:
            r = self.opener.open(req)
            status, headers, body = r.status, dict(r.headers), r.read()
        except urllib.error.HTTPError as e:
            status, headers, body = e.code, dict(e.headers), e.read()
        self.nonce = headers.get("Replay-Nonce")
        self.calls.append((url.split("/")[3] if url.count("/") > 3 else url, status))
        ctype = headers.get("Content-Type", "")
        return status, headers, (json.loads(body) if "json" in ctype and body else body)

    # ---- protocol steps
    def new_account(self) -> None:
        st, h, body = self.post(self.dir["newAccount"], {"termsOfServiceAgreed": True, "contact": ["mailto:pki@example.test"]})
        if st not in (200, 201):
            raise RuntimeError(f"newAccount {st}: {body}")
        self.kid = h["Location"]

    def new_order(self, hosts: list[str]) -> tuple[str, dict]:
        st, h, order = self.post(self.dir["newOrder"], {"identifiers": [{"type": "dns", "value": x} for x in hosts]})
        if st != 201:
            raise RuntimeError(f"newOrder {st}: {order}")
        return h["Location"], order

    def http01(self, authz_url: str, tokens: dict) -> None:
        _, _, authz = self.post(authz_url, None)
        if authz["status"] == "valid":                     # the CA reused an authorization we completed earlier
            return
        ch = next(c for c in authz["challenges"] if c["type"] == "http-01")
        thumb = b64(_thumbprint(self.jwk()))
        tokens[ch["token"]] = f"{ch['token']}.{thumb}"
        st, _, body = self.post(ch["url"], {})                                          # "I am ready": empty JSON object
        if st != 200:
            raise RuntimeError(f"challenge {st}: {body}")
        for _ in range(50):
            _, _, authz = self.post(authz_url, None)
            if authz["status"] == "valid":
                return
            if authz["status"] == "invalid":
                raise RuntimeError(f"authorization invalid: {json.dumps(authz)[:300]}")
            time.sleep(0.2)
        raise TimeoutError("authorization did not become valid")

    def finalize(self, order_url: str, order: dict, csr_der: bytes) -> bytes:
        st, _, body = self.post(order["finalize"], {"csr": b64(csr_der)})
        if st != 200:
            raise RuntimeError(f"finalize {st}: {body}")
        for _ in range(50):
            _, _, o = self.post(order_url, None)
            if o["status"] == "valid":
                _, _, pem = self.post(o["certificate"], None)
                return pem
            if o["status"] == "invalid":
                raise RuntimeError(f"order invalid: {json.dumps(o)[:300]}")
            time.sleep(0.2)
        raise TimeoutError("order did not become valid")


def _thumbprint(jwk: dict) -> bytes:
    h = hashes.Hash(hashes.SHA256())
    h.update(json.dumps(jwk, sort_keys=True, separators=(",", ":")).encode())          # RFC 7638
    return h.finalize()


class ChallengeServer(threading.Thread):
    """Serves /.well-known/acme-challenge/<token> for every token in `tokens`."""
    def __init__(self, tokens: dict, port: int = CHALLENGE_PORT):
        super().__init__(daemon=True)
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                tok = self.path.rsplit("/", 1)[-1]
                if tok in outer.tokens:
                    body = outer.tokens[tok].encode()
                    self.send_response(200); self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
                else:
                    self.send_response(404); self.end_headers()
            def log_message(self, *a): pass
        self.tokens = tokens
        self.httpd = http.server.ThreadingHTTPServer(("0.0.0.0", port), H)

    def run(self): self.httpd.serve_forever()
    def stop(self): self.httpd.shutdown()


def make_csr(host: str, key_alg: str):
    key = (ec.generate_private_key(ec.SECP256R1()) if key_alg == "P-256"
           else getattr(mldsa, f"{key_alg.replace('-', '')}PrivateKey").generate())
    b = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
    b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
    csr = b.sign(key, hashes.SHA256() if key_alg == "P-256" else None)
    return key, csr.public_bytes(serialization.Encoding.DER)


def issue_once(acme: Acme, host: str, tokens: dict, key_alg: str = "P-256") -> dict:
    t0 = time.perf_counter()
    order_url, order = acme.new_order([host])
    for authz_url in order["authorizations"]:
        acme.http01(authz_url, tokens)
    key, csr_der = make_csr(host, key_alg)
    pem = acme.finalize(order_url, order, csr_der)
    certs = x509.load_pem_x509_certificates(pem)
    leaf = certs[0]
    return {"host": host, "csr_key": key_alg, "ms": round((time.perf_counter() - t0) * 1000, 1),
            "not_after": leaf.not_valid_after_utc.isoformat(), "lifetime_days": (leaf.not_valid_after_utc - leaf.not_valid_before_utc).days,
            "chain_bytes": sum(len(c.public_bytes(serialization.Encoding.DER)) for c in certs), "chain_len": len(certs),
            "leaf_sig_alg": leaf.signature_algorithm_oid._name, "posts": len(acme.calls)}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Minimal ACME client against Pebble.")
    p.add_argument("--host", default="localhost")
    p.add_argument("--count", type=int, default=1, help="issue this many certificates in a row (renewal loop)")
    p.add_argument("--csr-key", default="P-256", choices=["P-256", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"])
    p.add_argument("--json")
    a = p.parse_args(argv)
    tokens: dict = {}
    srv = ChallengeServer(tokens); srv.start()
    acme = Acme()
    acme.new_account()
    print(f"account {acme.kid}")
    rows = []
    try:
        for i in range(a.count):
            try:
                r = issue_once(acme, a.host, tokens, a.csr_key)
                rows.append(r)
                print(f"[{i + 1}/{a.count}] issued in {r['ms']:.0f} ms: {r['lifetime_days']}-day certificate, chain {r['chain_bytes']} B, {r['leaf_sig_alg']}")
            except RuntimeError as e:
                rows.append({"host": a.host, "csr_key": a.csr_key, "error": str(e)[:300]})
                print(f"[{i + 1}/{a.count}] FAILED: {str(e)[:200]}")
                break
    finally:
        srv.stop()
    if a.json:
        Path(a.json).write_text(json.dumps(rows, indent=2) + "\n")
    ok = [r for r in rows if "ms" in r]
    if ok:
        print(f"\n{len(ok)} issuances, mean {sum(r['ms'] for r in ok) / len(ok):.0f} ms, "
              f"{len(acme.calls) / len(ok):.1f} signed POSTs per certificate")
    return 0


if __name__ == "__main__":
    sys.exit(main())
