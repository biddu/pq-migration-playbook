"""Lab 6.1 starter -- SSH key-exchange observer. Fill in every TODO; run  pytest labs/ch06/tests.
Reference: solution/sshobserve.py (relay plumbing and audit are reused from it)."""
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "solution"))
from sshobserve import (PQ_KEX, MSG, EXPECTED_EPHEMERAL, Side, Summary, observe_one,  # noqa: F401
                        report, audit_host, audit_table)


def read_string(buf: bytes, i: int) -> tuple[bytes, int]:
    """uint32 length followed by bytes (RFC 4251)."""
    raise NotImplementedError  # TODO


def read_namelist(buf: bytes, i: int) -> tuple[list[str], int]:
    """A string containing comma-separated names."""
    raise NotImplementedError  # TODO


def parse_kexinit(payload: bytes, side: Side) -> None:
    """Skip type + 16-byte cookie; read kex, host-key, cipher and MAC name-lists into side."""
    raise NotImplementedError  # TODO


def negotiate(client: list[str], server: list[str]) -> str:
    """First client algorithm the server also lists, ignoring ext-info-* and kex-strict-* markers."""
    raise NotImplementedError  # TODO


class SshParser:
    def __init__(self, direction: str, summary: Summary):
        self.direction, self.s = direction, summary
        self.side = summary.client if direction == "c2s" else summary.server
        self.buf = b""
        self.ident_done = False
        self.encrypted = False

    def feed(self, data: bytes) -> None:
        """Consume the identification line, then binary packets (uint32 len, byte padlen, payload,
        padding) until NEWKEYS; count bytes into side.bytes_to_newkeys."""
        raise NotImplementedError  # TODO

    def packet(self, payload: bytes) -> None:
        """KEXINIT -> parse and negotiate once both sides seen; 30 -> client ephemeral size;
        31 -> host key, server ephemeral and signature sizes (+ signature algorithm); 21 -> encrypted."""
        raise NotImplementedError  # TODO
