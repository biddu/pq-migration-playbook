"""Lab 7.1 solution -- build two-tier private CA hierarchies with OpenSSL 3.5 in several
algorithm profiles, issue server and client certificates, publish a CRL, and validate the
chain from Python.

A profile names the algorithm of each tier: root, issuing (intermediate) CA, leaf.
OpenSSL 3.5 key-type names are used throughout (ML-DSA-44/65/87, SLH-DSA-SHA2-128s,
EC P-256 via "ec:P-256"). Profiles in PROFILES:

  ecdsa          P-256 / P-256 / P-256                 today's private PKI, the baseline
  mldsa65        ML-DSA-65 / ML-DSA-65 / ML-DSA-65     the book's default recommendation
  mldsa44        ML-DSA-44 throughout                  the smallest pure-PQ chain
  mldsa87        ML-DSA-87 throughout                  CNSA 2.0's parameter set
  slh-root       SLH-DSA-SHA2-128s / ML-DSA-65 / ML-DSA-65   hash-based root, lattice below
  pq-under-classical  P-256 / ML-DSA-65 / ML-DSA-65   PQ issuing CA cross-signed by today's root
  pq-ca-classical-leaf  ML-DSA-65 / ML-DSA-65 / P-256  Chrome's "Stage 3" shape: PQ CA, classical TLS key

Every certificate is written as PEM and DER; sizes are reported per certificate and per
chain (leaf + issuing CA, which is what a TLS server sends). A CRL with a configurable
number of revoked serials is issued from the issuing CA so the revocation-data size can
be seen too. Chain validation is done twice: with `openssl verify` and with the
`cryptography` package's X.509 verifier, and the result of each is recorded, because they
do not agree on every profile (see the chapter).

Set OPENSSL_BIN / LD_LIBRARY_PATH for an OpenSSL 3.5+ build that is not on PATH.

Tested with: Python 3.12, OpenSSL 3.5.4, cryptography 50.0.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
CA_ROOT = HERE / "ca"
OPENSSL = os.environ.get("OPENSSL_BIN", shutil.which("openssl") or "openssl")

PROFILES: dict[str, tuple[str, str, str]] = {
    "ecdsa":                ("ec:P-256", "ec:P-256", "ec:P-256"),
    "mldsa65":              ("ML-DSA-65", "ML-DSA-65", "ML-DSA-65"),
    "mldsa44":              ("ML-DSA-44", "ML-DSA-44", "ML-DSA-44"),
    "mldsa87":              ("ML-DSA-87", "ML-DSA-87", "ML-DSA-87"),
    "slh-root":             ("SLH-DSA-SHA2-128s", "ML-DSA-65", "ML-DSA-65"),
    "pq-under-classical":   ("ec:P-256", "ML-DSA-65", "ML-DSA-65"),
    "pq-ca-classical-leaf": ("ML-DSA-65", "ML-DSA-65", "ec:P-256"),
}

ROOT_EXT = "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n"
INT_EXT = ("basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n"
           "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n")
SERVER_EXT = ("basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n"
              "subjectAltName=DNS:{host}\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n"
              "crlDistributionPoints=URI:http://pki.example.test/issuing.crl\n")
CLIENT_EXT = ("basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n"
              "subjectAltName=email:{user}\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n")


@dataclass
class CertInfo:
    name: str
    key_alg: str
    sig_alg: str
    der_bytes: int
    public_key_bytes: int
    signature_bytes: int
    keygen_ms: float
    sign_ms: float


@dataclass
class Hierarchy:
    profile: str
    root: CertInfo
    issuing: CertInfo
    server: CertInfo
    client: CertInfo
    chain_bytes_sent_by_server: int     # leaf + issuing CA DER, what a TLS server's Certificate message carries
    full_chain_bytes: int               # leaf + issuing + root
    crl_bytes_empty: int
    crl_bytes_n: int
    crl_entries: int
    openssl_verify: str
    python_verify: str


# ------------------------------------------------------------------ openssl helpers

def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=True, **kw)


def newkey_args(alg: str) -> list[str]:
    if alg.startswith("ec:"):
        return ["-newkey", "ec", "-pkeyopt", f"ec_paramgen_curve:{alg.split(':', 1)[1]}"]
    return ["-newkey", alg]


def timed(fn, *a, **k) -> tuple[object, float]:
    t0 = time.perf_counter()
    r = fn(*a, **k)
    return r, (time.perf_counter() - t0) * 1000.0


def der_len(pem: Path) -> int:
    return len(subprocess.run([OPENSSL, "x509", "-in", str(pem), "-outform", "DER"], capture_output=True, check=True).stdout)


def cert_facts(pem: Path) -> tuple[str, str, int, int]:
    """(key algorithm, signature algorithm, raw public key bytes, signature bytes) via the cryptography package."""
    from cryptography import x509
    c = x509.load_pem_x509_certificate(pem.read_bytes())
    sig_alg = c.signature_algorithm_oid._name if c.signature_algorithm_oid._name != "Unknown OID" else c.signature_algorithm_oid.dotted_string
    try:
        pk = c.public_key()
        key_alg = type(pk).__name__.replace("PublicKey", "")
        raw = getattr(pk, "public_bytes_raw", None)
        pk_bytes = len(raw()) if raw else len(pk.public_bytes(
            __import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.X962,
            __import__("cryptography.hazmat.primitives.serialization", fromlist=["PublicFormat"]).PublicFormat.UncompressedPoint))
    except Exception as e:                      # key type the package does not know (SLH-DSA in 50.0)
        key_alg, pk_bytes = f"unsupported({type(e).__name__})", -1
    return key_alg, sig_alg, pk_bytes, len(c.signature)


# ------------------------------------------------------------------ building

def make_root(d: Path, alg: str, subject: str) -> CertInfo:
    ext = d / "root.ext"; ext.write_text(ROOT_EXT)
    _, ms = timed(run, [OPENSSL, "req", "-x509", "-new", *newkey_args(alg), "-noenc", "-keyout", str(d / "root.key"),
                        "-out", str(d / "root.crt"), "-subj", subject, "-days", "5475", "-config", str(d / "openssl.cnf"),
                        "-extensions", "v3_root"])
    return _info("root", d / "root.crt", ms, ms)


def issue(d: Path, name: str, alg: str, subject: str, ca: str, days: int, ext_text: str) -> CertInfo:
    csr = d / f"{name}.csr"
    _, kg = timed(run, [OPENSSL, "req", "-new", *newkey_args(alg), "-noenc", "-keyout", str(d / f"{name}.key"),
                        "-out", str(csr), "-subj", subject])
    ext = d / f"{name}.ext"; ext.write_text(ext_text)
    _, sg = timed(run, [OPENSSL, "x509", "-req", "-in", str(csr), "-CA", str(d / f"{ca}.crt"), "-CAkey", str(d / f"{ca}.key"),
                        "-out", str(d / f"{name}.crt"), "-days", str(days), "-extfile", str(ext), "-CAcreateserial"])
    return _info(name, d / f"{name}.crt", kg, sg)


def _info(name: str, pem: Path, keygen_ms: float, sign_ms: float) -> CertInfo:
    key_alg, sig_alg, pk_bytes, sig_bytes = cert_facts(pem)
    return CertInfo(name, key_alg, sig_alg, der_len(pem), pk_bytes, sig_bytes, round(keygen_ms, 1), round(sign_ms, 1))


def make_crl(d: Path, n_revoked: int) -> tuple[int, int]:
    """Issue an empty CRL and one with n_revoked serials from the issuing CA; return DER sizes."""
    cnf = d / "openssl.cnf"
    for f, init in (("index.txt", ""), ("crlnumber", "1000\n")):
        (d / f).write_text(init)
    run([OPENSSL, "ca", "-config", str(cnf), "-gencrl", "-out", str(d / "empty.crl"), "-batch"])
    empty = len(subprocess.run([OPENSSL, "crl", "-in", str(d / "empty.crl"), "-outform", "DER"], capture_output=True, check=True).stdout)
    # revoked entries: fabricate index.txt rows (serial, revocation date) -- the CA signs whatever the index says
    rows = []
    for i in range(n_revoked):
        serial = f"{0x1000 + i:X}".zfill(2)
        rows.append(f"R\t300101000000Z\t250101000000Z\t{serial}\tunknown\t/CN=revoked-{i}\n")
    (d / "index.txt").write_text("".join(rows))
    run([OPENSSL, "ca", "-config", str(cnf), "-gencrl", "-out", str(d / "issuing.crl"), "-batch"])
    full = len(subprocess.run([OPENSSL, "crl", "-in", str(d / "issuing.crl"), "-outform", "DER"], capture_output=True, check=True).stdout)
    return empty, full


def write_cnf(d: Path) -> None:
    (d / "openssl.cnf").write_text(f"""
[ req ]
distinguished_name = dn
prompt = no
[ dn ]
CN = placeholder
[ v3_root ]
{ROOT_EXT}
[ ca ]
default_ca = issuing
[ issuing ]
dir = {d}
database = $dir/index.txt
crlnumber = $dir/crlnumber
certificate = $dir/issuing.crt
private_key = $dir/issuing.key
default_crl_days = 7
default_md = default
""")


def verify_openssl(d: Path, leaf: str) -> str:
    r = subprocess.run([OPENSSL, "verify", "-CAfile", str(d / "root.crt"), "-untrusted", str(d / "issuing.crt"),
                        "-crl_check", "-CRLfile", str(d / "empty.crl"), str(d / f"{leaf}.crt")], capture_output=True, text=True)
    return "OK" if r.returncode == 0 else (r.stderr.strip().splitlines() or ["failed"])[-1]


def verify_python(d: Path, host: str) -> str:
    from cryptography import x509
    from cryptography.x509.verification import PolicyBuilder, Store
    try:
        root = x509.load_pem_x509_certificate((d / "root.crt").read_bytes())
        issuing = x509.load_pem_x509_certificate((d / "issuing.crt").read_bytes())
        leaf = x509.load_pem_x509_certificate((d / "server.crt").read_bytes())
        v = PolicyBuilder().store(Store([root])).build_server_verifier(x509.DNSName(host))
        chain = v.verify(leaf, [issuing])
        return f"OK ({len(chain)} certificates)"
    except Exception as e:
        return f"{type(e).__name__}: {str(e)[:90]}"


def build(profile: str, host: str = "api.example.test", user: str = "alice@example.test", crl_entries: int = 1000,
          leaf_days: int = 47) -> Hierarchy:
    root_alg, int_alg, leaf_alg = PROFILES[profile]
    d = CA_ROOT / profile
    if d.exists():
        shutil.rmtree(d)
    d.mkdir(parents=True)
    write_cnf(d)
    root = make_root(d, root_alg, "/CN=PQM Lab Root CA/O=PQM Payments")
    issuing = issue(d, "issuing", int_alg, "/CN=PQM Lab Issuing CA 1/O=PQM Payments", "root", 1825, INT_EXT)
    server = issue(d, "server", leaf_alg, f"/CN={host}", "issuing", leaf_days, SERVER_EXT.format(host=host))
    client = issue(d, "client", leaf_alg, f"/CN={user}", "issuing", 365, CLIENT_EXT.format(user=user))
    (d / "chain.pem").write_text((d / "server.crt").read_text() + (d / "issuing.crt").read_text())
    (d / "fullchain.pem").write_text((d / "chain.pem").read_text() + (d / "root.crt").read_text())
    empty, full = make_crl(d, crl_entries)
    return Hierarchy(profile, root, issuing, server, client,
                     server.der_bytes + issuing.der_bytes, server.der_bytes + issuing.der_bytes + root.der_bytes,
                     empty, full, crl_entries, verify_openssl(d, "server"), verify_python(d, host))


def table(rows: list[Hierarchy]) -> str:
    head = (f"{'profile':<22} {'root':<10} {'issuing':<10} {'leaf':<10} {'root B':>7} {'iss B':>7} {'leaf B':>7} "
            f"{'sent B':>7} {'CRL0 B':>7} {'CRL1k B':>8} {'openssl':<8} python")
    out = [head, "-" * len(head)]
    for h in rows:
        out.append(f"{h.profile:<22} {h.root.key_alg[:10]:<10} {h.issuing.key_alg[:10]:<10} {h.server.key_alg[:10]:<10} "
                   f"{h.root.der_bytes:>7} {h.issuing.der_bytes:>7} {h.server.der_bytes:>7} {h.chain_bytes_sent_by_server:>7} "
                   f"{h.crl_bytes_empty:>7} {h.crl_bytes_n:>8} {h.openssl_verify:<8} {h.python_verify}")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Build two-tier private CAs in several post-quantum profiles.")
    p.add_argument("profiles", nargs="*", default=list(PROFILES), help=f"subset of {', '.join(PROFILES)}")
    p.add_argument("--crl-entries", type=int, default=1000)
    p.add_argument("--json", default=str(HERE / "results" / "hierarchies.json"))
    a = p.parse_args(argv)
    rows = []
    for prof in a.profiles:
        h = build(prof, crl_entries=a.crl_entries)
        rows.append(h)
        print(f"built {prof:<22} root {h.root.key_alg} ({h.root.sign_ms:.0f} ms self-sign), issuing {h.issuing.key_alg}, "
              f"leaf {h.server.key_alg}; server sends {h.chain_bytes_sent_by_server} B; "
              f"openssl {h.openssl_verify}; python {h.python_verify}")
    print("\n" + table(rows))
    Path(a.json).parent.mkdir(exist_ok=True)
    Path(a.json).write_text(json.dumps([asdict(r) for r in rows], indent=2) + "\n")
    print(f"\nwritten {a.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
