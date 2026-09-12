"""Acceptance tests for Labs 6.1 and 6.2. SSH parser tests run offline against fixtures/;
the live test needs OpenSSH 10 at OPENSSH_PREFIX (default /opt/openssh10)."""
import base64
import importlib
import os
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent.parent
use_solution = os.environ.get("PQ_LAB_IMPL", "starter") == "solution"
sys.path.insert(0, str(HERE / "solution"))
if not use_solution:
    sys.path.insert(0, str(HERE))
try:
    so = importlib.import_module("sshobserve" if use_solution else "starter_sshobserve")
except ModuleNotFoundError:
    so = importlib.import_module("sshobserve")
wg = importlib.import_module("wgpsk")


def replay(name):
    s = so.Summary()
    so.SshParser("c2s", s).feed((HERE / "fixtures" / f"{name}_c2s.bin").read_bytes())
    so.SshParser("s2c", s).feed((HERE / "fixtures" / f"{name}_s2c.bin").read_bytes())
    return s


# ---------------------------------------------------------------- Lab 6.1

def test_default_negotiates_mlkem_with_expected_sizes():
    s = replay("default")
    assert s.negotiated_kex == "mlkem768x25519-sha256" and s.quantum_level == 3
    assert s.client_ephemeral_bytes == 1216 and s.server_ephemeral_bytes == 1120     # Chapter 2's numbers again
    assert s.negotiated_hostkey == "ssh-ed25519" and s.signature_alg == "ssh-ed25519" and s.signature_bytes == 83
    assert s.strict_kex
    assert s.client.ident.startswith("SSH-2.0-OpenSSH_10")


def test_legacy_client_falls_back_to_x25519():
    s = replay("legacy-client")
    assert s.negotiated_kex == "curve25519-sha256" and s.quantum_level == 0
    assert s.client_ephemeral_bytes == 32 and s.server_ephemeral_bytes == 32


def test_sntrup_sizes():
    s = replay("sntrup")
    assert s.negotiated_kex == "sntrup761x25519-sha512"
    assert (s.client_ephemeral_bytes, s.server_ephemeral_bytes) == (1190, 1071)


def test_mismatch_has_no_common_kex():
    s = replay("mismatch")
    assert s.negotiated_kex == "" and s.client_ephemeral_bytes == 0          # SSH has no HelloRetryRequest


def test_negotiation_rule_is_client_order():
    assert so.negotiate(["a", "b", "ext-info-c"], ["b", "a"]) == "a"
    assert so.negotiate(["ext-info-c", "b"], ["b"]) == "b"
    assert so.negotiate(["a"], ["b"]) == ""


def test_audit_classifies_offers():
    s = replay("legacy-server")
    pq = [k for k in s.server.kex if k in so.PQ_KEX]
    assert pq == [] and "curve25519-sha256" in s.server.kex


# ---------------------------------------------------------------- Lab 6.2

def test_psk_agrees_and_is_bound_to_identities_and_epoch(tmp_path):
    ek = wg.responder_keygen(tmp_path / "resp.key")
    assert len(ek) == 1184
    ss_i, ct = wg.initiator_encapsulate(ek)
    assert len(ct) == 1088
    ss_r = wg.responder_decapsulate((tmp_path / "resp.key").read_bytes(), ct)
    assert ss_i == ss_r
    a, b = bytes(range(32)), bytes(range(32, 64))
    psk = wg.derive_psk(ss_i, a, b, 1)
    assert len(psk) == 32
    assert wg.derive_psk(ss_r, b, a, 1) == psk                 # order-independent
    assert wg.derive_psk(ss_i, a, b, 2) != psk                 # rotation changes the key
    assert wg.derive_psk(ss_i, a, bytes(32), 1) != psk         # bound to the peer identity
    cmd = wg.wg_command("wg0", base64.b64encode(b).decode(), psk)
    assert cmd.startswith("wg set wg0 peer ") and "preshared-key" in cmd


# ---------------------------------------------------------------- live

@pytest.mark.skipif(not (Path(os.environ.get("OPENSSH_PREFIX", "/opt/openssh10")) / "sbin" / "sshd").exists(),
                    reason="needs an OpenSSH 10 build at OPENSSH_PREFIX")
def test_live_default_kex():
    kl = importlib.import_module("kexlab")
    s, rc = kl.run_scenario("live", None, None, port=2322, relay=2323, save_fixture=False)
    assert rc == 0 and s.negotiated_kex == "mlkem768x25519-sha256"
