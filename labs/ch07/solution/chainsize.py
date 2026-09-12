"""Lab 7.2 solution -- what each certificate profile costs on the wire in a TLS 1.3 handshake.

For every hierarchy built by Lab 7.1 (labs/ch07/ca/<profile>/), run an OpenSSL 3.5
s_server with the leaf certificate and the issuing CA as chain, connect an s_client that
verifies against the root, and pass the connection through the Chapter 5 record observer
so the server's first flight (ServerHello .. Finished) is measured from the bytes rather
than estimated. Two variants per profile:

  server-auth   the usual case: the server sends leaf + issuing CA and one CertificateVerify
  mutual        mTLS: the client also sends its certificate chain and CertificateVerify

Key exchange is fixed at X25519MLKEM768 for every row so that the differences between rows
are authentication bytes only. A final "composite" row is computed, not measured: OpenSSL
3.5 does not implement composite ML-DSA, so its sizes are taken from the sizes table of
draft-ietf-lamps-pq-composite-sigs and added to the measured ML-DSA-65 chain.

Set OPENSSL_BIN / LD_LIBRARY_PATH for an OpenSSL 3.5+ build that is not on PATH.

Tested with: Python 3.12, OpenSSL 3.5.4.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import asdict
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
CA_ROOT = HERE / "ca"
sys.path.insert(0, str(HERE.parent / "ch05" / "solution"))
from tlsobserve import observe_one  # noqa: E402

OPENSSL = os.environ.get("OPENSSL_BIN", shutil.which("openssl") or "openssl")
GROUPS = "X25519MLKEM768"
MSS = 1460
CONGESTION_WINDOW_BYTES = 10 * MSS           # Linux initcwnd 10 segments: the flight fits in one round trip below this

# draft-ietf-lamps-pq-composite-sigs-19, Appendix A (maxima): public key, signature
COMPOSITE = {"MLDSA65-ECDSA-P256-SHA512": (2017, 3381), "MLDSA44-ECDSA-P256-SHA256": (1377, 2492),
             "MLDSA65-Ed25519-SHA512": (1984, 3373), "MLDSA87-ECDSA-P384-SHA512": (2689, 4731)}


def start_server(port: int, d: Path, mutual: bool) -> subprocess.Popen:
    cmd = [OPENSSL, "s_server", "-accept", str(port), "-cert", str(d / "server.crt"), "-key", str(d / "server.key"),
           "-cert_chain", str(d / "issuing.crt"), "-tls1_3", "-groups", GROUPS, "-quiet", "-naccept", "1"]
    if mutual:
        cmd += ["-Verify", "2", "-CAfile", str(d / "root.crt")]
    p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    time.sleep(0.3)
    return p


def run_client(port: int, d: Path, mutual: bool) -> str:
    cmd = [OPENSSL, "s_client", "-connect", f"127.0.0.1:{port}", "-tls1_3", "-groups", GROUPS, "-brief",
           "-CAfile", str(d / "root.crt"), "-verify_return_error"]
    if mutual:
        cmd += ["-cert", str(d / "client.crt"), "-key", str(d / "client.key"), "-cert_chain", str(d / "issuing.crt")]
    r = subprocess.run(cmd, input=b"", capture_output=True, timeout=20)
    return (r.stderr + r.stdout).decode(errors="replace")


def measure(profile: str, mutual: bool, server_port: int = 4453, relay_port: int = 4454) -> dict:
    d = CA_ROOT / profile
    srv = start_server(server_port, d, mutual)
    box: dict = {}
    t = threading.Thread(target=lambda: box.setdefault("s", observe_one(relay_port, ("127.0.0.1", server_port))))
    t.start(); time.sleep(0.2)
    brief = run_client(relay_port, d, mutual)
    t.join(timeout=20); srv.wait(timeout=5)
    s = box["s"]
    ok = "Verification: OK" in brief
    return {"profile": profile, "mutual": mutual, "verified": ok,
            "server_flight_bytes": s.server_first_flight_bytes,
            "server_flight_segments": -(-s.server_first_flight_bytes // MSS),
            "fits_initcwnd": s.server_first_flight_bytes <= CONGESTION_WINDOW_BYTES,
            "bytes_c2s": s.bytes_c2s, "bytes_s2c": s.bytes_s2c,
            "brief": brief.strip().splitlines()[:8]}


def composite_row(base: dict, name: str, hier: dict) -> dict:
    """Estimate: replace ML-DSA-65 key+signature in leaf and issuing certificates by the composite sizes."""
    pk, sig = COMPOSITE[name]
    d_pk, d_sig = pk - 1952, sig - 3309
    extra = 2 * (d_pk + d_sig) + d_sig            # two certificates (key + signature each) and the CertificateVerify
    flight = base["server_flight_bytes"] + extra
    return {"profile": f"composite {name} (computed)", "mutual": False, "verified": None,
            "server_flight_bytes": flight, "server_flight_segments": -(-flight // MSS),
            "fits_initcwnd": flight <= CONGESTION_WINDOW_BYTES, "bytes_c2s": None, "bytes_s2c": None, "brief": []}


def table(rows: list[dict]) -> str:
    head = f"{'profile':<44} {'auth':<7} {'srv flight B':>12} {'seg':>4} {'1 RTT?':>6} {'c2s B':>7} {'s2c B':>7} verified"
    out = [head, "-" * len(head)]
    for r in rows:
        out.append(f"{r['profile']:<44} {('mutual' if r['mutual'] else 'server'):<7} {r['server_flight_bytes']:>12} "
                   f"{r['server_flight_segments']:>4} {('yes' if r['fits_initcwnd'] else 'NO'):>6} "
                   f"{(r['bytes_c2s'] if r['bytes_c2s'] is not None else '-'):>7} {(r['bytes_s2c'] if r['bytes_s2c'] is not None else '-'):>7} "
                   f"{r['verified']}")
    return "\n".join(out)


def main() -> int:
    profiles = [p.name for p in sorted(CA_ROOT.iterdir()) if (p / "server.crt").exists()]
    if not profiles:
        print("run labs/ch07/solution/pkilab.py first", file=sys.stderr)
        return 1
    order = ["ecdsa", "mldsa44", "mldsa65", "mldsa87", "pq-under-classical", "pq-ca-classical-leaf", "slh-root"]
    profiles.sort(key=lambda p: order.index(p) if p in order else 99)
    rows = []
    for prof in profiles:
        for mutual in (False, True):
            r = measure(prof, mutual)
            rows.append(r)
            print(f"{prof:<22} {'mutual' if mutual else 'server'}: server flight {r['server_flight_bytes']} B "
                  f"({r['server_flight_segments']} segments), verified={r['verified']}")
    base = next(r for r in rows if r["profile"] == "mldsa65" and not r["mutual"])
    hier = {h["profile"]: h for h in json.loads((HERE / "results" / "hierarchies.json").read_text())} if (HERE / "results" / "hierarchies.json").exists() else {}
    for name in ("MLDSA65-ECDSA-P256-SHA512", "MLDSA44-ECDSA-P256-SHA256"):
        rows.append(composite_row(base, name, hier))
    print("\n" + table(rows))
    out = HERE / "results" / "chainsize.json"
    out.write_text(json.dumps(rows, indent=2) + "\n")
    print(f"\nwritten {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
