"""Acceptance tests for Labs 5.1-5.3.
Parser tests run offline against captured byte streams in fixtures/. Live tests need an
OpenSSL 3.5+ binary (OPENSSL_BIN, LD_LIBRARY_PATH) and are skipped otherwise."""
import importlib
import os
import shutil
import subprocess
import sys
import threading
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent.parent
use_solution = os.environ.get("PQ_LAB_IMPL", "starter") == "solution"
sys.path.insert(0, str(HERE / "solution"))
if not use_solution:
    sys.path.insert(0, str(HERE))
try:
    obs = importlib.import_module("tlsobserve" if use_solution else "starter_tlsobserve")
except ModuleNotFoundError:
    obs = importlib.import_module("tlsobserve")


def replay(name):
    s, lock = obs.Summary(), threading.Lock()
    obs.RecordParser("c2s", s, lock).feed((HERE / "fixtures" / f"{name}_c2s.bin").read_bytes())
    obs.RecordParser("s2c", s, lock).feed((HERE / "fixtures" / f"{name}_s2c.bin").read_bytes())
    return s


def test_hybrid_client_hello_key_shares():
    s = replay("hybrid")
    shares = {k["group"]: k["bytes"] for k in s.client_key_shares}
    assert shares == {"X25519MLKEM768": 1216}   # OpenSSL sends a share for the first group only; Chapter 2's 1,216 B
    assert s.client_hello_bytes == 1403
    assert s.client_supported_groups[:2] == ["X25519MLKEM768", "X25519"]


def test_hybrid_server_hello_and_flight():
    s = replay("hybrid")
    assert s.server_selected_group == "X25519MLKEM768" and s.server_key_share_bytes == 1120
    assert not s.hello_retry_request and s.round_trips == 1
    assert 1100 < s.server_hello_bytes < 1300


def test_hrr_is_detected():
    s = replay("hrr")
    assert s.hello_retry_request and s.round_trips == 2
    assert s.hrr_selected_group == "X25519MLKEM768"
    hellos = [r for r in s.records if r.handshake == "ClientHello"]
    assert len(hellos) == 2                                              # second ClientHello after the HRR
    assert hellos[0].detail["key_shares"][0]["group"] == "secp256r1"
    assert hellos[1].detail["key_shares"][0]["group"] == "X25519MLKEM768"


def test_classical_baseline_is_small():
    s = replay("classical")
    assert s.client_hello_bytes < 300 and s.server_key_share_bytes == 32
    assert s.segments(s.client_hello_bytes, 1460) == 1


def test_segment_arithmetic():
    s = obs.Summary()
    assert s.segments(1403, 1460) == 1 and s.segments(1403, 1360) == 2 and s.segments(1842, 1460) == 2


# ---------------------------------------------------------------- live (needs OpenSSL 3.5+)

def openssl35():
    binary = os.environ.get("OPENSSL_BIN", shutil.which("openssl"))
    if not binary:
        return None
    v = subprocess.run([binary, "version"], capture_output=True, text=True).stdout.split("(")[0]   # the binary, not the library
    try:
        major, minor = (int(x) for x in v.split()[1].split(".")[:2])
    except (IndexError, ValueError):
        return None
    return binary if (major, minor) >= (3, 5) else None


@pytest.mark.skipif(openssl35() is None, reason="needs OpenSSL 3.5+ (set OPENSSL_BIN)")
def test_live_hybrid_handshake_through_relay():
    hs = importlib.import_module("handshakes")
    s, brief = hs.run_scenario("hybrid", "X25519MLKEM768:X25519", "X25519MLKEM768:X25519", "ecdsa", 4481, 4482)
    assert s.server_selected_group == "X25519MLKEM768" and hs.negotiated(brief) == "X25519MLKEM768"
    assert s.client_hello_bytes == 1403
