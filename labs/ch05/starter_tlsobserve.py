"""Lab 5.1 starter -- TLS record observer. Fill in every TODO; run  pytest labs/ch05/tests.
Reference: solution/tlsobserve.py. The relay plumbing and data classes are reused from it;
your work is the record and handshake parsing."""
from __future__ import annotations

import struct
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "solution"))
from tlsobserve import (GROUPS, CONTENT, HANDSHAKE, HRR_RANDOM, Record, Summary, gname,  # noqa: F401
                        observe_one, report, pump)


def parse_extensions(buf: bytes) -> dict[int, bytes]:
    """type(2) length(2) data ... -> {type: data}"""
    raise NotImplementedError  # TODO


def parse_client_hello(body: bytes, s: Summary) -> dict:
    """Skip legacy_version, random, session_id, cipher_suites, compression; parse extensions;
    fill s.client_supported_groups (ext 10) and s.client_key_shares (ext 51: group, bytes)."""
    raise NotImplementedError  # TODO


def parse_server_hello(body: bytes, s: Summary) -> dict:
    """Detect HelloRetryRequest by the fixed random; record selected group and server share size."""
    raise NotImplementedError  # TODO


class RecordParser:
    def __init__(self, direction: str, summary: Summary, lock: threading.Lock):
        self.direction, self.summary, self.lock = direction, summary, lock
        self.buf = b""

    def feed(self, data: bytes) -> None:
        """Reassemble 5-byte-header TLS records from the stream and call self.record for each."""
        raise NotImplementedError  # TODO

    def record(self, ct: int, payload: bytes) -> None:
        """Append a Record; for plaintext handshake records parse ClientHello / ServerHello;
        keep byte totals per direction and client_hello_bytes / server_hello_bytes (payload + 5)."""
        raise NotImplementedError  # TODO
