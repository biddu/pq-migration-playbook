"""Lab 5.3 solution -- handshake throughput and per-handshake latency, classical vs hybrid,
ECDSA vs ML-DSA-65, single certificate vs two-certificate chain.

Uses `openssl s_time -new` to run full handshakes against an s_server for a fixed
number of seconds and reports connections per second and mean handshake time. This
measures the whole cost (CPU on both ends plus the loopback network), which is what
you will see in production, and it uses the same binary your servers run.

Set OPENSSL_BIN / LD_LIBRARY_PATH for an OpenSSL 3.5+ build that is not on PATH.

Tested with: Python 3.12, OpenSSL 3.5.4.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
CERTS = HERE / "certs"
OPENSSL = os.environ.get("OPENSSL_BIN", shutil.which("openssl") or "openssl")

CONFIGS = [
    # name,               server groups,            cert file,                 key file
    ("X25519 / ECDSA",          "X25519",          "ecdsa.crt",          "ecdsa.key"),
    ("X25519MLKEM768 / ECDSA",  "X25519MLKEM768",  "ecdsa.crt",          "ecdsa.key"),
    ("X25519 / ML-DSA-65",      "X25519",          "mldsa65.crt",        "mldsa65.key"),
    ("X25519MLKEM768 / ML-DSA-65", "X25519MLKEM768", "mldsa65.crt",     "mldsa65.key"),
    ("X25519MLKEM768 / ECDSA chain",  "X25519MLKEM768", "chain-ecdsa.pem",   "leaf-ecdsa.key"),
    ("X25519MLKEM768 / ML-DSA-65 chain", "X25519MLKEM768", "chain-mldsa65.pem", "leaf-mldsa65.key"),
]


def s_time(port: int, seconds: int, cafile: str) -> dict:
    cmd = [OPENSSL, "s_time", "-connect", f"127.0.0.1:{port}", "-new", "-time", str(seconds), "-CAfile", cafile]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=seconds + 30).stdout
    m = re.search(r"(\d+) connections in ([\d.]+)s; ([\d.]+) connections/user sec", out)
    m2 = re.search(r"(\d+) connections in (\d+) real seconds", out)
    conns, real = (int(m2.group(1)), int(m2.group(2))) if m2 else (0, seconds)
    return {"connections": conns, "real_seconds": real,
            "per_second": conns / real if real else 0.0,
            "mean_ms": 1000.0 * real / conns if conns else float("nan"),
            "user_cps": float(m.group(3)) if m else float("nan")}


def run(seconds: int = 5, port: int = 4455) -> list[dict]:
    rows = []
    for name, groups, cert, key in CONFIGS:
        cafile = str(CERTS / ("root-mldsa65.crt" if "mldsa65" in cert else "root-ecdsa.crt" if "chain" in cert else cert))
        srv = subprocess.Popen([OPENSSL, "s_server", "-accept", str(port), "-cert", str(CERTS / cert),
                                "-key", str(CERTS / key), "-tls1_3", "-groups", groups, "-quiet", "-www"],
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.4)
        try:
            r = s_time(port, seconds, cafile)
        finally:
            srv.terminate(); srv.wait(timeout=5)
        rows.append({"config": name, "groups": groups, "cert": cert, **r})
        print(f"{name:<36} {r['connections']:>6} handshakes in {r['real_seconds']}s  "
              f"{r['per_second']:>8.1f}/s  mean {r['mean_ms']:.2f} ms")
        port += 1
    return rows


def main() -> int:
    seconds = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    rows = run(seconds)
    out = HERE / "results" / "loadtest.json"
    out.write_text(json.dumps(rows, indent=2) + "\n")
    base = rows[0]["mean_ms"]
    print("\nrelative to X25519 / ECDSA:")
    for r in rows:
        print(f"  {r['config']:<36} {r['mean_ms'] / base:5.2f}x mean handshake time")
    print(f"written {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
