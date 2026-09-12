"""Lab 5.1 / 5.2 driver -- run OpenSSL 3.5 server and client through the observer for
several group configurations and tabulate what happens on the wire.

Scenarios (server groups | client groups):
  classical      X25519:secp256r1                 | X25519:secp256r1
  hybrid         X25519MLKEM768:X25519            | X25519MLKEM768:X25519
  hybrid-1024    SecP384r1MLKEM1024               | SecP384r1MLKEM1024
  hrr            X25519MLKEM768                   | secp256r1:X25519MLKEM768   (client shares P-256 only -> HRR)
  legacy-client  X25519MLKEM768:X25519            | X25519                     (old client, server falls back)
Each scenario is run with an ECDSA P-256 certificate and again with an ML-DSA-65
certificate, so that the key-exchange bytes and the authentication bytes can be
seen separately.

Needs an OpenSSL 3.5+ binary; set OPENSSL_BIN and LD_LIBRARY_PATH if it is not on PATH.

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

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tlsobserve import Summary, observe_one, report  # noqa: E402

HERE = Path(__file__).resolve().parents[1]
CERTS = HERE / "certs"
OPENSSL = os.environ.get("OPENSSL_BIN", shutil.which("openssl") or "openssl")

SCENARIOS = {
    "classical":     ("X25519:secp256r1",       "X25519:secp256r1"),
    "hybrid":        ("X25519MLKEM768:X25519",  "X25519MLKEM768:X25519"),
    "hybrid-1024":   ("SecP384r1MLKEM1024",     "SecP384r1MLKEM1024"),
    "hrr":           ("X25519MLKEM768",         "secp256r1:X25519MLKEM768"),
    "legacy-client": ("X25519MLKEM768:X25519",  "X25519"),
}
CERT_SETS = {"ecdsa": ("ecdsa.crt", "ecdsa.key"), "mldsa65": ("mldsa65.crt", "mldsa65.key")}


def openssl_version() -> str:
    return subprocess.run([OPENSSL, "version"], capture_output=True, text=True).stdout.strip()


def start_server(port: int, groups: str, cert: str, key: str) -> subprocess.Popen:
    cmd = [OPENSSL, "s_server", "-accept", str(port), "-cert", str(CERTS / cert), "-key", str(CERTS / key),
           "-tls1_3", "-groups", groups, "-quiet", "-naccept", "1"]
    p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    time.sleep(0.3)
    return p


def run_client(port: int, groups: str) -> str:
    cmd = [OPENSSL, "s_client", "-connect", f"127.0.0.1:{port}", "-tls1_3", "-groups", groups, "-brief"]
    r = subprocess.run(cmd, input=b"", capture_output=True, timeout=20)
    return (r.stderr + r.stdout).decode(errors="replace")


def run_scenario(name: str, server_groups: str, client_groups: str, cert_set: str,
                 server_port: int = 4433, relay_port: int = 4434) -> tuple[Summary, str]:
    cert, key = CERT_SETS[cert_set]
    srv = start_server(server_port, server_groups, cert, key)
    result: dict = {}

    def observe():
        result["summary"] = observe_one(relay_port, ("127.0.0.1", server_port))

    t = threading.Thread(target=observe)
    t.start()
    time.sleep(0.2)
    brief = run_client(relay_port, client_groups)
    t.join(timeout=20)
    srv.wait(timeout=5)
    return result["summary"], brief


def negotiated(brief: str) -> str:
    for line in brief.splitlines():
        if line.startswith("Negotiated TLS1.3 group:"):
            return line.split(":", 1)[1].strip()
        if line.startswith(("Peer Temp Key:", "Server Temp Key:")):        # classical groups are reported this way
            return line.split(":", 1)[1].split(",")[0].strip()
    return "?"


def main() -> int:
    print(f"using {OPENSSL}: {openssl_version()}")
    rows = []
    for cert_set in CERT_SETS:
        for name, (sg, cg) in SCENARIOS.items():
            s, brief = run_scenario(name, sg, cg, cert_set)
            rows.append({"scenario": name, "cert": cert_set, "server_groups": sg, "client_groups": cg,
                         "negotiated": negotiated(brief), **asdict(s)})
            print(f"\n== {name} / {cert_set} certificate ==\n{report(s)}")
    out = HERE / "results" / "handshakes.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(rows, indent=2, default=str) + "\n")

    print("\n" + f"{'scenario':<14} {'cert':<8} {'negotiated':<19} {'CH B':>6} {'CH seg':>6} {'HRR':>4} {'SH B':>6} {'srv flight B':>12} {'seg':>4} {'c2s':>6} {'s2c':>6}")
    for r in rows:
        print(f"{r['scenario']:<14} {r['cert']:<8} {r['negotiated']:<19} {r['client_hello_bytes']:>6} "
              f"{-(-r['client_hello_bytes'] // 1460):>6} {'yes' if r['hello_retry_request'] else 'no':>4} "
              f"{r['server_hello_bytes']:>6} {r['server_first_flight_bytes']:>12} {-(-r['server_first_flight_bytes'] // 1460):>4} "
              f"{r['bytes_c2s']:>6} {r['bytes_s2c']:>6}")
    print(f"\nwritten {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
