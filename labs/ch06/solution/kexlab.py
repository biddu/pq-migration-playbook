"""Lab 6.1 driver -- run the lab sshd with several KexAlgorithms settings, connect through the
observer, and tabulate what is negotiated and what it costs in bytes. Also saves the raw
byte streams of each handshake into fixtures/ for the offline tests.

Set OPENSSH_PREFIX (default /opt/openssh10) to the OpenSSH 10 build.
Tested with: Python 3.12, OpenSSH 10.1p1."""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sshobserve import SshParser, Summary, report  # noqa: E402

HERE = Path(__file__).resolve().parents[1]
PREFIX = Path(os.environ.get("OPENSSH_PREFIX", "/opt/openssh10"))
SSHD, SSH = PREFIX / "sbin" / "sshd", PREFIX / "bin" / "ssh"
CONF = HERE / "sshd" / "sshd_lab.conf"
KEY = HERE / "sshd" / "client_ed25519"

SCENARIOS = {
    # name:           (server KexAlgorithms,                          client KexAlgorithms)
    "default":        (None,                                          None),
    "pq-only-server": ("mlkem768x25519-sha256",                       None),
    "legacy-client":  (None,                                          "curve25519-sha256"),
    "legacy-server":  ("curve25519-sha256,ecdh-sha2-nistp256",        None),
    "sntrup":         ("sntrup761x25519-sha512",                      None),
    "mismatch":       ("mlkem768x25519-sha256",                       "curve25519-sha256"),
}


def run_scenario(name: str, server_kex: str | None, client_kex: str | None, port: int = 2222, relay: int = 2223,
                 save_fixture: bool = True) -> tuple[Summary, int]:
    cmd = [str(SSHD), "-D", "-f", str(CONF), "-p", str(port)]
    if server_kex:
        cmd += ["-o", f"KexAlgorithms={server_kex}"]
    srv = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.4)
    s, raw = Summary(), {"c2s": bytearray(), "s2c": bytearray()}

    def relay_once():
        ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ls.bind(("127.0.0.1", relay)); ls.listen(1); ls.settimeout(20)
        cl, _ = ls.accept(); up = socket.create_connection(("127.0.0.1", port))
        def pump(a, b, parser, key):
            try:
                while True:
                    d = a.recv(65536)
                    if not d:
                        break
                    raw[key] += d; parser.feed(d); b.sendall(d)
            except OSError:
                pass
            finally:
                try: b.shutdown(socket.SHUT_WR)
                except OSError: pass
        t1 = threading.Thread(target=pump, args=(cl, up, SshParser("c2s", s), "c2s"))
        t2 = threading.Thread(target=pump, args=(up, cl, SshParser("s2c", s), "s2c"))
        t1.start(); t2.start(); t1.join(); t2.join(); cl.close(); up.close(); ls.close()

    t = threading.Thread(target=relay_once); t.start(); time.sleep(0.2)
    ccmd = [str(SSH), "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "BatchMode=yes",
            "-i", str(KEY), "-p", str(relay)]
    if client_kex:
        ccmd += ["-o", f"KexAlgorithms={client_kex}"]
    ccmd += ["root@127.0.0.1", "true"]
    rc = subprocess.run(ccmd, capture_output=True, timeout=30).returncode
    t.join(25); srv.terminate(); srv.wait(5)
    if save_fixture:
        (HERE / "fixtures").mkdir(exist_ok=True)
        (HERE / "fixtures" / f"{name}_c2s.bin").write_bytes(raw["c2s"])
        (HERE / "fixtures" / f"{name}_s2c.bin").write_bytes(raw["s2c"])
    return s, rc


def main() -> int:
    rows = []
    for name, (sk, ck) in SCENARIOS.items():
        s, rc = run_scenario(name, sk, ck)
        rows.append({"scenario": name, "server_kex": sk or "(default)", "client_kex": ck or "(default)",
                     "exit": rc, **asdict(s)})
        print(f"\n== {name} (ssh exit {rc}) ==\n{report(s)}")
    (HERE / "results").mkdir(exist_ok=True)
    (HERE / "results" / "kex.json").write_text(json.dumps(rows, indent=2, default=str) + "\n")
    print(f"\n{'scenario':<16} {'negotiated kex':<30} {'lvl':>3} {'Q_C B':>6} {'Q_S B':>6} {'hostkey':<12} {'sig B':>5} {'c2s B':>6} {'s2c B':>6} ok")
    for r in rows:
        print(f"{r['scenario']:<16} {r['negotiated_kex'] or '(none: failed)':<30} {r['quantum_level']:>3} "
              f"{r['client_ephemeral_bytes']:>6} {r['server_ephemeral_bytes']:>6} {r['negotiated_hostkey']:<12} "
              f"{r['signature_bytes']:>5} {r['client']['bytes_to_newkeys']:>6} {r['server']['bytes_to_newkeys']:>6} {'yes' if r['exit'] == 0 else 'no'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
