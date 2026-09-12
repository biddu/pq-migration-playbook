"""Lab 5.1 solution -- a TLS record observer.

A TCP relay that sits between a client and a server, forwards bytes unchanged,
and records every TLS record header it sees in each direction: content type,
length, and for the plaintext handshake messages (ClientHello, ServerHello,
HelloRetryRequest) the fields that matter for the migration: the offered groups,
the key shares and their sizes, the selected group. Everything after the
ServerHello is encrypted in TLS 1.3, so for those records only the size is known,
which is exactly what the byte budget needs.

No packet capture privileges, no tshark, no dependencies. Run it, point a client
at it, read the summary.

Tested with: Python 3.12; OpenSSL 3.5.4 client and server.
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

HRR_RANDOM = bytes.fromhex("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")

GROUPS = {
    0x0017: "secp256r1", 0x0018: "secp384r1", 0x0019: "secp521r1", 0x001D: "X25519", 0x001E: "X448",
    0x0100: "ffdhe2048", 0x0101: "ffdhe3072",
    0x0200: "MLKEM512", 0x0201: "MLKEM768", 0x0202: "MLKEM1024",
    0x11EB: "SecP256r1MLKEM768", 0x11EC: "X25519MLKEM768", 0x11ED: "SecP384r1MLKEM1024",
}
CONTENT = {20: "change_cipher_spec", 21: "alert", 22: "handshake", 23: "application_data"}
HANDSHAKE = {1: "ClientHello", 2: "ServerHello", 4: "NewSessionTicket", 8: "EncryptedExtensions",
             11: "Certificate", 13: "CertificateRequest", 15: "CertificateVerify", 20: "Finished"}


def gname(g: int) -> str:
    return GROUPS.get(g, f"0x{g:04x}")


@dataclass
class Record:
    direction: str            # c2s | s2c
    content_type: str
    length: int               # payload length (header adds 5)
    handshake: str = ""       # message type if plaintext handshake
    detail: dict = field(default_factory=dict)


@dataclass
class Summary:
    records: list[Record] = field(default_factory=list)
    bytes_c2s: int = 0
    bytes_s2c: int = 0
    client_hello_bytes: int = 0
    client_key_shares: list[dict] = field(default_factory=list)
    client_supported_groups: list[str] = field(default_factory=list)
    hello_retry_request: bool = False
    hrr_selected_group: str = ""
    server_selected_group: str = ""
    server_key_share_bytes: int = 0
    server_hello_bytes: int = 0
    server_first_flight_bytes: int = 0    # ServerHello .. Finished, before any client reply
    round_trips: int = 1                  # 1 without HRR, 2 with

    def segments(self, nbytes: int, mss: int) -> int:
        return -(-nbytes // mss)


# ------------------------------------------------------------------ parsing

def parse_extensions(buf: bytes) -> dict[int, bytes]:
    exts, i = {}, 0
    while i + 4 <= len(buf):
        t, ln = struct.unpack("!HH", buf[i:i + 4])
        exts[t] = buf[i + 4:i + 4 + ln]
        i += 4 + ln
    return exts


def parse_client_hello(body: bytes, s: Summary) -> dict:
    i = 2 + 32                                  # legacy_version, random
    sid_len = body[i]; i += 1 + sid_len
    cs_len = struct.unpack("!H", body[i:i + 2])[0]; i += 2 + cs_len
    comp_len = body[i]; i += 1 + comp_len
    ext_len = struct.unpack("!H", body[i:i + 2])[0]; i += 2
    exts = parse_extensions(body[i:i + ext_len])
    detail: dict = {}
    if 10 in exts:                              # supported_groups
        n = struct.unpack("!H", exts[10][:2])[0]
        groups = [gname(struct.unpack("!H", exts[10][2 + 2 * k:4 + 2 * k])[0]) for k in range(n // 2)]
        detail["supported_groups"] = groups
        s.client_supported_groups = groups
    if 51 in exts:                              # key_share
        n = struct.unpack("!H", exts[51][:2])[0]
        j, shares = 2, []
        while j < 2 + n:
            g, ln = struct.unpack("!HH", exts[51][j:j + 4])
            shares.append({"group": gname(g), "bytes": ln})
            j += 4 + ln
        detail["key_shares"] = shares
        s.client_key_shares = shares
    return detail


def parse_server_hello(body: bytes, s: Summary) -> dict:
    random = body[2:34]
    i = 34
    sid_len = body[i]; i += 1 + sid_len
    i += 2 + 1                                   # cipher suite, compression
    ext_len = struct.unpack("!H", body[i:i + 2])[0]; i += 2
    exts = parse_extensions(body[i:i + ext_len])
    detail: dict = {}
    if random == HRR_RANDOM:
        detail["hello_retry_request"] = True
        s.hello_retry_request = True
        s.round_trips = 2
        if 51 in exts:
            g = struct.unpack("!H", exts[51][:2])[0]
            detail["selected_group"] = gname(g)
            s.hrr_selected_group = gname(g)
    elif 51 in exts:
        g, ln = struct.unpack("!HH", exts[51][:4])
        detail["selected_group"] = gname(g)
        detail["key_share_bytes"] = ln
        s.server_selected_group = gname(g)
        s.server_key_share_bytes = ln
    return detail


class RecordParser:
    """Reassembles TLS records from a byte stream and reports each one."""

    def __init__(self, direction: str, summary: Summary, lock: threading.Lock):
        self.direction, self.summary, self.lock = direction, summary, lock
        self.buf = b""
        self.server_hello_seen = False
        self.client_replied_after_sh = False

    def feed(self, data: bytes) -> None:
        self.buf += data
        while len(self.buf) >= 5:
            ct, ver, ln = struct.unpack("!BHH", self.buf[:5])
            if len(self.buf) < 5 + ln:
                return
            payload = self.buf[5:5 + ln]
            self.buf = self.buf[5 + ln:]
            self.record(ct, payload)

    def record(self, ct: int, payload: bytes) -> None:
        rec = Record(self.direction, CONTENT.get(ct, str(ct)), len(payload))
        s = self.summary
        if ct == 22 and payload:
            ht = payload[0]
            rec.handshake = HANDSHAKE.get(ht, str(ht))
            body = payload[4:]
            try:
                if ht == 1:
                    rec.detail = parse_client_hello(body, s)
                    if not s.client_hello_bytes:
                        s.client_hello_bytes = len(payload) + 5
                elif ht == 2:
                    rec.detail = parse_server_hello(body, s)
                    s.server_hello_bytes = len(payload) + 5
            except (struct.error, IndexError):
                rec.detail = {"parse_error": True}
        with self.lock:
            s.records.append(rec)
            if self.direction == "c2s":
                s.bytes_c2s += len(payload) + 5
            else:
                s.bytes_s2c += len(payload) + 5


# ------------------------------------------------------------------ relay

def pump(src: socket.socket, dst: socket.socket, parser: RecordParser) -> None:
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


def observe_one(listen_port: int, upstream: tuple[str, int], timeout: float = 15.0) -> Summary:
    """Accept one connection, relay it to upstream, return the summary when both sides close."""
    summary, lock = Summary(), threading.Lock()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", listen_port))
        srv.listen(1)
        srv.settimeout(timeout)
        client, _ = srv.accept()
    with client, socket.create_connection(upstream, timeout=timeout) as server:
        client.settimeout(timeout); server.settimeout(timeout)
        t1 = threading.Thread(target=pump, args=(client, server, RecordParser("c2s", summary, lock)))
        t2 = threading.Thread(target=pump, args=(server, client, RecordParser("s2c", summary, lock)))
        t1.start(); t2.start(); t1.join(); t2.join()
    # server first flight: everything s2c from ServerHello until the first c2s record after it
    seen_sh, flight = False, 0
    for r in summary.records:
        if r.direction == "s2c" and r.handshake == "ServerHello" and not r.detail.get("hello_retry_request"):
            seen_sh = True
        if seen_sh and r.direction == "s2c":
            flight += r.length + 5
        elif seen_sh and r.direction == "c2s":
            break
    summary.server_first_flight_bytes = flight
    return summary


def report(s: Summary) -> str:
    lines = [f"ClientHello: {s.client_hello_bytes} bytes; key shares: "
             + ", ".join(f"{k['group']} ({k['bytes']} B)" for k in s.client_key_shares),
             f"supported_groups offered: {', '.join(s.client_supported_groups)}"]
    if s.hello_retry_request:
        lines.append(f"HelloRetryRequest: server asked for {s.hrr_selected_group} (extra round trip)")
    lines.append(f"ServerHello: {s.server_hello_bytes} bytes; selected {s.server_selected_group} "
                 f"(server key share {s.server_key_share_bytes} B)")
    lines.append(f"server first flight (ServerHello..Finished): {s.server_first_flight_bytes} bytes = "
                 f"{s.segments(s.server_first_flight_bytes, 1460)} segments at MSS 1460")
    lines.append(f"ClientHello record needs {s.segments(s.client_hello_bytes, 1460)} segment(s) at MSS 1460, "
                 f"{s.segments(s.client_hello_bytes, 1360)} at MSS 1360, {s.segments(s.client_hello_bytes, 1200)} at MSS 1200")
    lines.append(f"total handshake+close bytes: client->server {s.bytes_c2s}, server->client {s.bytes_s2c}; "
                 f"round trips to keys: {s.round_trips}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Observe one TLS handshake passing through a relay.")
    p.add_argument("--listen", type=int, default=4434)
    p.add_argument("--upstream", default="127.0.0.1:4433")
    p.add_argument("--json", help="write the summary as JSON here")
    args = p.parse_args(argv)
    host, _, port = args.upstream.partition(":")
    s = observe_one(args.listen, (host, int(port or 443)))
    print(report(s))
    if args.json:
        Path(args.json).write_text(json.dumps(asdict(s), indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
