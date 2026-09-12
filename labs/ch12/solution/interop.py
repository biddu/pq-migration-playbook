"""Lab 12.1 solution -- the interoperability matrix: every TLS implementation you run, against
every other, for every hybrid group, with the result read from the wire.

Implementations (each can be server, client, or both):
  openssl   OpenSSL 3.5 s_server / s_client (OPENSSL_BIN, LD_LIBRARY_PATH as in Chapter 5)
  go        Go 1.24 crypto/tls, the small program in labs/ch12/gotls (X25519MLKEM768 only)
  pyssl     the system Python's ssl module, linked against whatever OpenSSL the OS ships
            (3.0 on the reference container: no post-quantum groups, and no API to set groups)

For each (server, client, group) the harness starts the server offering *only* that group, runs
the client through the Chapter 5 observer so the negotiated group and ClientHello size are read
from the bytes rather than from either implementation's own report, and records one of:
  OK <group>        the handshake completed and the observer saw that group selected
  FAIL <reason>     one side rejected (no common group, unknown group, ...)
  UNSUPPORTED       the implementation cannot be configured to offer the group at all

The matrix is the artefact the chapter's test plan asks for, and running it in CI on every
library upgrade is how "we support post-quantum" becomes a fact per pair rather than a claim.

Tested with: Python 3.12, OpenSSL 3.5.4, Go 1.24.7; Python ssl on OpenSSL 3.0.13 for the pyssl rows.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE.parent / "ch05" / "solution"))
from tlsobserve import observe_one  # noqa: E402

OPENSSL = os.environ.get("OPENSSL_BIN", shutil.which("openssl") or "openssl")
# The OpenSSL CLI may need its own LD_LIBRARY_PATH (e.g. /opt/openssl35/lib64) while this interpreter's ssl module
# should load the system libssl; OPENSSL_LD_LIBRARY_PATH keeps the two apart so both can be measured in one run.
OPENSSL_ENV = {**os.environ, "LD_LIBRARY_PATH": os.environ.get("OPENSSL_LD_LIBRARY_PATH", os.environ.get("LD_LIBRARY_PATH", ""))}
GOTLS = HERE / "gotls" / "gotls"
CA = HERE.parent / "ch07" / "ca" / "ecdsa"                     # Lab 7.1's ECDSA hierarchy (server.crt/key, root.crt)
HOST = "api.example.test"

GROUPS = ["X25519", "X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "MLKEM768"]
IMPLS = ["openssl", "go", "pyssl"]

GO_SUPPORTED = {"X25519", "X25519MLKEM768"}
PYSSL_CAN_SET_GROUPS = hasattr(ssl.SSLContext, "set_groups")   # Python 3.13+ only; 3.11/3.12 use the library default
PYSSL_LIB = ssl.OPENSSL_VERSION.split()[1]                       # the libssl this interpreter actually loaded (LD_LIBRARY_PATH decides!)


def certs_ok() -> bool:
    return all((CA / f).exists() for f in ("server.crt", "server.key", "root.crt", "issuing.crt", "chain.pem"))


def ensure_certs() -> None:
    if certs_ok():
        return
    pk = HERE.parent / "ch07" / "solution" / "pkilab.py"
    subprocess.run([sys.executable, str(pk), "ecdsa", "--crl-entries", "1"], check=True, capture_output=True, env=OPENSSL_ENV)


# ------------------------------------------------------------------ servers

def start_server(impl: str, port: int, group: str) -> subprocess.Popen | None:
    if impl == "openssl":
        return subprocess.Popen([OPENSSL, "s_server", "-accept", str(port), "-cert", str(CA / "server.crt"), "-key", str(CA / "server.key"),
                                 "-cert_chain", str(CA / "issuing.crt"), "-tls1_3", "-groups", group, "-quiet", "-naccept", "1"],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=OPENSSL_ENV)
    if impl == "go":
        if group not in GO_SUPPORTED:
            return None
        return subprocess.Popen([str(GOTLS), "-mode", "server", "-addr", f"127.0.0.1:{port}", "-groups", group,
                                 "-cert", str(CA / "chain.pem"), "-key", str(CA / "server.key")],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if impl == "pyssl":
        # Python's ssl module (before 3.13) cannot set groups: it serves whatever the loaded libssl offers by
        # default, whichever group the matrix asked for. The cell records what was actually negotiated.
        return subprocess.Popen([sys.executable, __file__, "--pyssl-server", str(port), group],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    raise KeyError(impl)


def pyssl_server(port: int, group: str) -> None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(str(CA / "chain.pem"), str(CA / "server.key"))            # leaf + issuing CA, so clients can verify
    if PYSSL_CAN_SET_GROUPS:
        ctx.set_groups(group)
    with socket.socket() as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("127.0.0.1", port)); s.listen(1); s.settimeout(15)
        conn, _ = s.accept()
        try:
            with ctx.wrap_socket(conn, server_side=True) as tls:
                print("OK", tls.version()); tls.sendall(b"hello from python\n")
        except ssl.SSLError as e:
            print("FAIL", e.reason or str(e))


# ------------------------------------------------------------------ clients

def run_client(impl: str, port: int, group: str) -> tuple[str, str]:
    """Returns (status, detail) where status is OK | FAIL | UNSUPPORTED."""
    if impl == "openssl":
        r = subprocess.run([OPENSSL, "s_client", "-connect", f"127.0.0.1:{port}", "-tls1_3", "-groups", group, "-brief",
                            "-CAfile", str(CA / "root.crt"), "-verify_return_error", "-servername", HOST],
                           input=b"", capture_output=True, timeout=20, env=OPENSSL_ENV)
        out = (r.stderr + r.stdout).decode(errors="replace")
        if "Verification: OK" in out or "CONNECTION ESTABLISHED" in out:
            return "OK", ""
        return "FAIL", next((l for l in out.splitlines() if "alert" in l or "error" in l.lower()), out.strip()[-120:])
    if impl == "go":
        if group not in GO_SUPPORTED:
            return "UNSUPPORTED", "group not in Go 1.24 crypto/tls"
        r = subprocess.run([str(GOTLS), "-mode", "client", "-addr", f"127.0.0.1:{port}", "-groups", group, "-ca", str(CA / "root.crt")],
                           capture_output=True, text=True, timeout=20)
        return ("OK", "") if r.stdout.startswith("OK") else ("FAIL", (r.stdout + r.stderr).strip()[-120:])
    if impl == "pyssl":
        ctx = ssl.create_default_context(cafile=str(CA / "root.crt"))                # no set_groups: library defaults
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        if PYSSL_CAN_SET_GROUPS:
            ctx.set_groups(group)
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=10) as s, ctx.wrap_socket(s, server_hostname=HOST) as tls:
                return "OK", f"library default (OpenSSL {PYSSL_LIB})"
        except ssl.SSLError as e:
            return "FAIL", e.reason or str(e)
        except OSError as e:
            return "FAIL", str(e)
    raise KeyError(impl)


# ------------------------------------------------------------------ one cell

def client_supports(impl: str, group: str) -> bool:
    return not (impl == "go" and group not in GO_SUPPORTED)


def cell(server: str, client: str, group: str, server_port: int = 4470, relay_port: int = 4471) -> dict:
    if not client_supports(client, group):
        return {"server": server, "client": client, "group": group, "status": "UNSUPPORTED", "detail": f"{client} cannot offer {group}"}
    srv = start_server(server, server_port, group)
    if srv is None:
        return {"server": server, "client": client, "group": group, "status": "UNSUPPORTED", "detail": f"{server} cannot serve {group}"}
    time.sleep(0.5)
    box: dict = {}
    t = threading.Thread(target=lambda: box.setdefault("s", observe_one(relay_port, ("127.0.0.1", server_port), timeout=12)))
    t.start(); time.sleep(0.2)
    status, detail = run_client(client, relay_port, group)
    t.join(timeout=15)
    try:
        srv.wait(timeout=5)
    except subprocess.TimeoutExpired:
        srv.kill()
    s = box.get("s")
    negotiated = (s.hrr_selected_group or s.server_selected_group) if s else ""
    if "pyssl" in (server, client):
        detail = (detail + "; " if detail else "") + f"pyssl uses libssl defaults (OpenSSL {PYSSL_LIB}); requested group not enforceable"
    return {"server": server, "client": client, "group": group, "status": status, "detail": detail,
            "negotiated": negotiated, "client_hello_bytes": s.client_hello_bytes if s else None,
            "hrr": s.hello_retry_request if s else None}


def matrix() -> list[dict]:
    ensure_certs()
    rows = []
    for g in GROUPS:
        for server in IMPLS:
            for client in IMPLS:
                r = cell(server, client, g)
                rows.append(r)
                mark = r["status"] if r["status"] != "OK" else f"OK {r['negotiated']}"
                print(f"{g:<20} {server:>7} <- {client:<7} {mark:<28} CH {r.get('client_hello_bytes') or '-'}")
    return rows


def render(rows: list[dict]) -> str:
    out = []
    for g in GROUPS:
        out.append(f"\n{g}")
        head = "server / client"
        out.append(f"{head:<18}" + "".join(f"{c:>20}" for c in IMPLS))
        for s in IMPLS:
            cells = []
            for c in IMPLS:
                r = next(x for x in rows if x["group"] == g and x["server"] == s and x["client"] == c)
                cells.append("OK" if r["status"] == "OK" and r.get("negotiated") == g else
                             (f"OK({r['negotiated']})" if r["status"] == "OK" else ("n/s" if r["status"] == "UNSUPPORTED" else "FAIL")))
            out.append(f"{s:<18}" + "".join(f"{x:>20}" for x in cells))
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["--pyssl-server"]:
        pyssl_server(int(argv[1]), argv[2]); return 0
    print(f"pyssl = {sys.executable} ssl module on OpenSSL {PYSSL_LIB} (set LD_LIBRARY_PATH to change which libssl it loads)\n")
    rows = matrix()
    print(render(rows))
    (HERE / "results").mkdir(exist_ok=True)
    out = HERE / "results" / (argv[0] if argv else "interop.json")
    out.write_text(json.dumps({"pyssl_openssl": PYSSL_LIB, "go": "1.24", "openssl_bin": OPENSSL, "rows": rows}, indent=2) + "\n")
    print(f"\nwritten {out}  (n/s = cannot be configured for that group; OK(g) = handshake completed but negotiated g instead)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
