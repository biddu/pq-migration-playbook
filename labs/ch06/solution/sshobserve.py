"""Lab 6.1 solution -- an SSH key-exchange observer and fleet auditor.

Relay mode: sits between an SSH client and server, forwards bytes unchanged, and
parses the plaintext part of the SSH transport (RFC 4253): the identification
strings, both KEXINIT messages (the algorithm name-lists), the client's key
exchange init (ephemeral public value, 1,216 bytes for mlkem768x25519) and the
server's reply (host key, ephemeral value, signature). Everything after NEWKEYS is
encrypted and only counted.

Audit mode: connects to each host in a list, reads the server's identification
string and KEXINIT, and reports which key-exchange methods it offers, whether a
post-quantum one is among them and first, and the host-key algorithms. No login is
attempted; the connection is closed after the server's KEXINIT.

Tested with: Python 3.12, OpenSSH 10.1 client and server.
"""
from __future__ import annotations

import argparse
import json
import socket
import struct
import sys
import threading
from dataclasses import dataclass, field, asdict
from pathlib import Path

PQ_KEX = {"mlkem768x25519-sha256": 3, "sntrup761x25519-sha512": 3, "sntrup761x25519-sha512@openssh.com": 3,
          "mlkem768-sha256": 3, "mlkem1024-sha384": 5}
MSG = {20: "KEXINIT", 21: "NEWKEYS", 30: "KEX_ECDH_INIT", 31: "KEX_ECDH_REPLY", 7: "EXT_INFO"}
EXPECTED_EPHEMERAL = {"mlkem768x25519-sha256": (1216, 1120), "sntrup761x25519-sha512": (1190, 1071),
                      "sntrup761x25519-sha512@openssh.com": (1190, 1071), "curve25519-sha256": (32, 32),
                      "curve25519-sha256@libssh.org": (32, 32), "ecdh-sha2-nistp256": (65, 65)}


@dataclass
class Side:
    ident: str = ""
    kex: list[str] = field(default_factory=list)
    hostkey_algs: list[str] = field(default_factory=list)
    ciphers: list[str] = field(default_factory=list)
    macs: list[str] = field(default_factory=list)
    bytes_to_newkeys: int = 0
    packets: list[tuple[str, int]] = field(default_factory=list)


@dataclass
class Summary:
    client: Side = field(default_factory=Side)
    server: Side = field(default_factory=Side)
    negotiated_kex: str = ""
    negotiated_hostkey: str = ""
    quantum_level: int = 0
    client_ephemeral_bytes: int = 0
    server_ephemeral_bytes: int = 0
    host_key_bytes: int = 0
    signature_alg: str = ""
    signature_bytes: int = 0
    strict_kex: bool = False


# ------------------------------------------------------------------ parsing

def read_string(buf: bytes, i: int) -> tuple[bytes, int]:
    n = struct.unpack("!I", buf[i:i + 4])[0]
    return buf[i + 4:i + 4 + n], i + 4 + n


def read_namelist(buf: bytes, i: int) -> tuple[list[str], int]:
    s, i = read_string(buf, i)
    return ([x for x in s.decode().split(",") if x], i)


def parse_kexinit(payload: bytes, side: Side) -> None:
    i = 1 + 16                                         # msg type, cookie
    side.kex, i = read_namelist(payload, i)
    side.hostkey_algs, i = read_namelist(payload, i)
    enc_c2s, i = read_namelist(payload, i); enc_s2c, i = read_namelist(payload, i)
    mac_c2s, i = read_namelist(payload, i); mac_s2c, i = read_namelist(payload, i)
    side.ciphers, side.macs = enc_c2s, mac_c2s


def negotiate(client: list[str], server: list[str]) -> str:
    """RFC 4253 section 7.1: the first client algorithm that the server also supports."""
    for a in client:
        if a in server and not a.startswith(("ext-info", "kex-strict")):
            return a
    return ""


class SshParser:
    def __init__(self, direction: str, summary: Summary):
        self.direction, self.s = direction, summary
        self.side = summary.client if direction == "c2s" else summary.server
        self.buf = b""
        self.ident_done = False
        self.encrypted = False

    def feed(self, data: bytes) -> None:
        if self.encrypted:
            return
        self.buf += data
        if not self.ident_done:
            nl = self.buf.find(b"\n")
            if nl < 0:
                return
            line = self.buf[:nl].rstrip(b"\r").decode(errors="replace")
            if line.startswith("SSH-"):
                self.side.ident = line
                self.ident_done = True
                self.buf = self.buf[nl + 1:]
            else:                                      # pre-banner lines are allowed from the server
                self.buf = self.buf[nl + 1:]
                return
        while len(self.buf) >= 5 and not self.encrypted:
            pkt_len = struct.unpack("!I", self.buf[:4])[0]
            if len(self.buf) < 4 + pkt_len:
                return
            pad = self.buf[4]
            payload = self.buf[5:4 + pkt_len - pad]
            self.buf = self.buf[4 + pkt_len:]
            self.side.bytes_to_newkeys += 4 + pkt_len
            self.packet(payload)

    def packet(self, payload: bytes) -> None:
        if not payload:
            return
        t = payload[0]
        self.side.packets.append((MSG.get(t, str(t)), len(payload)))
        s = self.s
        if t == 20:
            parse_kexinit(payload, self.side)
            if s.client.kex and s.server.kex:
                s.negotiated_kex = negotiate(s.client.kex, s.server.kex)
                s.negotiated_hostkey = negotiate(s.client.hostkey_algs, s.server.hostkey_algs)
                s.quantum_level = PQ_KEX.get(s.negotiated_kex, 0)
                s.strict_kex = ("kex-strict-c-v00@openssh.com" in s.client.kex
                                and "kex-strict-s-v00@openssh.com" in s.server.kex)
        elif t == 30:
            q_c, _ = read_string(payload, 1)
            s.client_ephemeral_bytes = len(q_c)
        elif t == 31:
            k_s, i = read_string(payload, 1)
            q_s, i = read_string(payload, i)
            sig, i = read_string(payload, i)
            s.host_key_bytes, s.server_ephemeral_bytes, s.signature_bytes = len(k_s), len(q_s), len(sig)
            alg, _ = read_string(sig, 0)
            s.signature_alg = alg.decode(errors="replace")
        elif t == 21:
            self.encrypted = True


# ------------------------------------------------------------------ relay

def pump(src: socket.socket, dst: socket.socket, parser: SshParser) -> None:
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            parser.feed(data)
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def observe_one(listen_port: int, upstream: tuple[str, int], timeout: float = 20.0) -> Summary:
    s = Summary()
    with socket.socket() as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", listen_port)); srv.listen(1); srv.settimeout(timeout)
        client, _ = srv.accept()
    with client, socket.create_connection(upstream, timeout=timeout) as server:
        client.settimeout(timeout); server.settimeout(timeout)
        t1 = threading.Thread(target=pump, args=(client, server, SshParser("c2s", s)))
        t2 = threading.Thread(target=pump, args=(server, client, SshParser("s2c", s)))
        t1.start(); t2.start(); t1.join(); t2.join()
    return s


def report(s: Summary) -> str:
    exp = EXPECTED_EPHEMERAL.get(s.negotiated_kex)
    lines = [f"client: {s.client.ident}", f"server: {s.server.ident}",
             f"client kex offer : {', '.join(s.client.kex[:4])}{', ...' if len(s.client.kex) > 4 else ''}",
             f"server kex offer : {', '.join(s.server.kex[:4])}{', ...' if len(s.server.kex) > 4 else ''}",
             f"negotiated kex   : {s.negotiated_kex}  (quantum level {s.quantum_level})"
             f"{'  strict-kex' if s.strict_kex else ''}",
             f"host key         : {s.negotiated_hostkey} ({s.host_key_bytes} B blob), signature {s.signature_alg} ({s.signature_bytes} B)",
             f"ephemeral values : client {s.client_ephemeral_bytes} B, server {s.server_ephemeral_bytes} B"
             + (f"  (expected {exp[0]}/{exp[1]})" if exp else ""),
             f"bytes to NEWKEYS : client->server {s.client.bytes_to_newkeys}, server->client {s.server.bytes_to_newkeys}"]
    return "\n".join(lines)


# ------------------------------------------------------------------ audit

def audit_host(host: str, port: int = 22, timeout: float = 5.0) -> dict:
    """Read the server identification and KEXINIT without authenticating."""
    side = Side()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(b"SSH-2.0-pqm-audit_0.1\r\n")
            parser = SshParser("s2c", Summary())
            parser.side = side
            deadline = 0
            while not side.kex and deadline < 50:
                data = sock.recv(65536)
                if not data:
                    break
                parser.feed(data)
                deadline += 1
    except OSError as e:
        return {"host": f"{host}:{port}", "error": str(e)}
    pq = [k for k in side.kex if k in PQ_KEX]
    return {"host": f"{host}:{port}", "ident": side.ident, "kex": side.kex, "hostkey_algs": side.hostkey_algs,
            "pq_kex_offered": pq, "pq_first": bool(side.kex) and side.kex[0] in PQ_KEX,
            "classical_only_kex": [k for k in side.kex if k not in PQ_KEX and not k.startswith(("ext-info", "kex-strict"))],
            "quantum_level": max((PQ_KEX[k] for k in pq), default=0)}


def audit_table(rows: list[dict]) -> str:
    head = f"{'host':<28} {'server':<26} {'PQ kex':<8} {'first?':<6} {'level':<5} classical fallbacks"
    out = [head, "-" * len(head)]
    for r in rows:
        if "error" in r:
            out.append(f"{r['host']:<28} ERROR {r['error']}")
            continue
        out.append(f"{r['host']:<28} {r['ident'][:26]:<26} {('yes' if r['pq_kex_offered'] else 'no'):<8} "
                   f"{('yes' if r['pq_first'] else 'no'):<6} {r['quantum_level']:<5} {len(r['classical_only_kex'])}")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Observe an SSH key exchange, or audit a list of SSH servers.")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("relay"); r.add_argument("--listen", type=int, default=2223); r.add_argument("--upstream", default="127.0.0.1:2222"); r.add_argument("--json")
    a = sub.add_parser("audit"); a.add_argument("hosts", help="file with HOST[:PORT] per line"); a.add_argument("--json")
    args = p.parse_args(argv)
    if args.cmd == "relay":
        host, _, port = args.upstream.partition(":")
        s = observe_one(args.listen, (host, int(port or 22)))
        print(report(s))
        if args.json:
            Path(args.json).write_text(json.dumps(asdict(s), indent=2) + "\n")
    else:
        rows = []
        for line in Path(args.hosts).read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            h, _, prt = line.partition(":")
            rows.append(audit_host(h, int(prt or 22)))
        print(audit_table(rows))
        if args.json:
            Path(args.json).write_text(json.dumps(rows, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
