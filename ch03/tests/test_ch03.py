"""Acceptance tests for Labs 3.1-3.3. Run:  pytest labs/ch03/tests
PQ_LAB_IMPL=solution tests the reference solutions; the default tests your starter_cbomscan.py
(Labs 3.2 and 3.3 always use the reference tlsmerge/cbomdiff unless you add starters)."""
import importlib
import json
import os
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent.parent
use_solution = os.environ.get("PQ_LAB_IMPL", "starter") == "solution"
sys.path.insert(0, str(HERE / "solution"))
sys.path.insert(0, str(HERE)) if not use_solution else None

try:
    scan = importlib.import_module("cbomscan" if use_solution else "starter_cbomscan")
except ModuleNotFoundError:
    scan = importlib.import_module("cbomscan")
tlsmerge = importlib.import_module("tlsmerge")
cbomdiff = importlib.import_module("cbomdiff")
validate = importlib.import_module("validate")

SAMPLE = HERE / "sample_service"
RULES = HERE / "rules.yaml"


@pytest.fixture(scope="module")
def cbom():
    inv = scan.Inventory()
    scan.scan_tree(SAMPLE, scan.load_rules(RULES), inv)
    return scan.build_cbom(inv, "payments-gateway", SAMPLE)


def assets(cbom, asset_type=None):
    out = {}
    for c in cbom["components"]:
        if c["type"] != "cryptographic-asset":
            continue
        cp = c["cryptoProperties"]
        if asset_type and cp["assetType"] != asset_type:
            continue
        ps = cp.get("algorithmProperties", {}).get("parameterSetIdentifier", "") or cp.get("protocolProperties", {}).get("version", "")
        out[(c["name"], ps)] = c
    return out


# ---------------------------------------------------------------- Lab 3.1

def test_cbom_is_valid_cyclonedx_16(cbom):
    assert cbom["bomFormat"] == "CycloneDX" and cbom["specVersion"] == "1.6"
    assert validate.validate(cbom) == []


def test_finds_the_planted_algorithms(cbom):
    a = assets(cbom, "algorithm")
    assert ("RSA", "RSA-2048") in a                  # auth.py keygen and the certificate
    assert ("RSA-OAEP", "RSA-OAEP") in a             # key wrapping
    assert ("JWS RS256", "RS256") in a               # token signing
    assert ("SHA-1", "SHA-1") in a                   # weak hash
    assert ("AES-GCM", "AES-GCM") in a               # symmetric, fine
    assert ("ECDSA", "P-256") in a                   # Go gateway, normalised curve name
    assert ("TLS group X25519", "X25519") in a
    assert ("SSH KEX curve25519-sha256", "curve25519-sha256") in a
    assert ("SSH host key rsa", "rsa") in a


def test_quantum_levels_are_set(cbom):
    a = assets(cbom, "algorithm")
    q = lambda k: a[k]["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"]
    assert q(("RSA", "RSA-2048")) == 0
    assert q(("ECDSA", "P-256")) == 0
    assert q(("AES-GCM", "AES-GCM")) >= 1


def test_rsa_has_two_evidence_sites_and_an_oid(cbom):
    rsa = assets(cbom, "algorithm")[("RSA", "RSA-2048")]
    locs = {o["location"] for o in rsa["evidence"]["occurrences"]}
    assert locs == {"app/auth.py", "certs/server.crt"}
    assert rsa["cryptoProperties"]["oid"] == "1.2.840.113549.1.1.1"


def test_certificate_component_links_to_its_algorithms(cbom):
    certs = assets(cbom, "certificate")
    assert len(certs) == 1
    props = next(iter(certs.values()))["cryptoProperties"]["certificateProperties"]
    refs = {c["bom-ref"] for c in cbom["components"]}
    assert props["signatureAlgorithmRef"] in refs and props["subjectPublicKeyRef"] in refs
    assert "api.payments.example" in props["subjectName"]


def test_protocols_and_cipher_suites(cbom):
    p = assets(cbom, "protocol")
    assert ("TLS", "1.2") in p and ("TLS", "1.3") in p
    suites = {s["name"] for s in p[("TLS", "1.2")]["cryptoProperties"]["protocolProperties"].get("cipherSuites", [])}
    assert "ECDHE-RSA-AES128-GCM-SHA256" in suites


def test_library_component_and_dependencies(cbom):
    libs = {(c["name"], c["version"]) for c in cbom["components"] if c["type"] == "library"}
    assert ("cryptography", "46.0.7") in libs
    dep = cbom["dependencies"][0]
    assert dep["ref"] == "app/payments-gateway" and len(dep["dependsOn"]) == len(cbom["components"])


# ---------------------------------------------------------------- Lab 3.2

def test_parse_brief_new_and_old_wording():
    new = tlsmerge.parse_brief((HERE / "fixtures" / "edge.payments.example_443.txt").read_text())
    old = tlsmerge.parse_brief((HERE / "fixtures" / "api.payments.example_443.txt").read_text())
    assert new["group"] == "X25519MLKEM768" and new["version"] == "TLSv1.3" and len(new["certs"]) == 1
    assert old["group"] == "X25519" and old["cipher"] == "ECDHE-RSA-AES128-GCM-SHA256"


def test_merge_deduplicates_against_repo_scan(cbom, tmp_path):
    inv = tlsmerge.load_into_inventory(cbom)
    for host, port in [("edge.payments.example", 443), ("api.payments.example", 443), ("legacy.payments.example", 8443)]:
        text = (HERE / "fixtures" / f"{host}_{port}.txt").read_text()
        tlsmerge.merge_endpoint(inv, host, port, tlsmerge.parse_brief(text))
    merged = scan.build_cbom(inv, "payments-gateway", SAMPLE)
    assert validate.validate(merged) == []
    a = assets(merged, "algorithm")
    assert a[("TLS group X25519MLKEM768", "X25519MLKEM768")]["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 3
    rsa_locs = {o["location"] for o in a[("RSA", "RSA-2048")]["evidence"]["occurrences"]}
    assert rsa_locs == {"app/auth.py", "certs/server.crt", "tls://api.payments.example:443"}
    assert ("TLS", "unreachable") in assets(merged, "protocol")


# ---------------------------------------------------------------- Lab 3.3

def test_diff_reports_added_changed_and_vulnerable(cbom):
    inv = tlsmerge.load_into_inventory(cbom)
    text = (HERE / "fixtures" / "edge.payments.example_443.txt").read_text()
    tlsmerge.merge_endpoint(inv, "edge.payments.example", 443, tlsmerge.parse_brief(text))
    merged = scan.build_cbom(inv, "payments-gateway", SAMPLE)
    d = cbomdiff.diff(cbom, merged)
    added = {k[:2] for k, _ in d["added"]}
    assert ("algorithm", "TLS group X25519MLKEM768") in added
    assert not d["removed"]
    assert any(k[1] == "TLS" and k[2] == "1.3" for k, *_ in d["changed"])
    assert ("algorithm", "RSA", "RSA-2048") in d["still_vulnerable"]
    md = cbomdiff.to_markdown(d, "before", "after")
    assert md.startswith("# CBOM change report") and "X25519MLKEM768" in md
