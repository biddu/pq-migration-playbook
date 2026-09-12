"""Lab 2.1 starter -- the size and speed table. Fill in every TODO, then run
    pytest labs/ch02/tests
Specification: Chapter 2, Lab 2.1. Reference solution: solution/sizes.py."""
from __future__ import annotations

import statistics
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa, mlkem, x25519

try:
    import oqs
except ImportError:
    oqs = None

MSG = b"post-quantum migration"
N = 200


def median_us(fn, n: int = N) -> float:
    """Median wall-clock time of fn() over n runs, in microseconds."""
    raise NotImplementedError  # TODO


@dataclass
class Row:
    alg: str
    kind: str
    category: str
    pk: int
    sk: int
    payload: int
    op1_us: float
    op2_us: float
    op3_us: float
    source: str


def x25519_row() -> Row:
    """Wrap X25519 as a KEM: encapsulate = fresh ephemeral key; ciphertext = its public key."""
    raise NotImplementedError  # TODO


def ed25519_row() -> Row:
    raise NotImplementedError  # TODO


def mlkem_row(name: str, cls, category: str) -> Row:
    """cls is e.g. mlkem.MLKEM768PrivateKey. pk.encapsulate() returns (shared_secret, ciphertext)."""
    raise NotImplementedError  # TODO


def mldsa_row(name: str, cls, category: str) -> Row:
    raise NotImplementedError  # TODO


def build_rows(include_oqs: bool = True) -> list[Row]:
    """X25519, ML-KEM-768, ML-KEM-1024, Ed25519, ML-DSA-44/65/87; add liboqs rows if available."""
    raise NotImplementedError  # TODO


def to_markdown(rows: list[Row]) -> str:
    """A Markdown table starting with '| Algorithm'."""
    raise NotImplementedError  # TODO
