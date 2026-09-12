"""Lab 3.2 solution -- scan TLS endpoints and merge what they negotiate into a CBOM.

For each host:port the tool runs

    openssl s_client -connect HOST:PORT -servername HOST -brief -showcerts </dev/null

and parses the negotiated protocol version, cipher suite, key-exchange group and
signature type, plus the leaf certificate. Each becomes a cryptographic asset with
evidence at tls://HOST:PORT, merged into an existing CBOM (or a new one).

Offline mode (--fixtures DIR) reads saved s_client output from DIR/HOST_PORT.txt
instead of connecting, which is how the acceptance tests run and how you scan
hosts you can only reach from a jump box: capture there, merge here.

Requires OpenSSL 3.5+ on the scanning machine to observe hybrid groups; an older
OpenSSL will simply never negotiate them and the CBOM will say so truthfully.

Tested with: Python 3.12, cryptography 50.0, OpenSSL 3.5.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

from cryptography import x509

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cbomscan import Asset, Inventory, Occurrence, build_cbom, group_asset, public_key_asset, CERT_SIG_OIDS  # noqa: E402

BRIEF_FIELDS = {
    "Protocol version": "version", "Ciphersuite": "cipher", "Negotiated TLS1.3 group": "group",
    "Server Temp Key": "tempkey", "Peer Temp Key": "tempkey", "Signature type": "sigtype", "Peer certificate": "peer",
    "Verification": "verification",
}


def run_s_client(host: str, port: int, timeout: float = 10.0) -> str:
    cmd = ["openssl", "s_client", "-connect", f"{host}:{port}", "-servername", host, "-brief", "-showcerts"]
    try:
        r = subprocess.run(cmd, input=b"", capture_output=True, timeout=timeout)
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return f"ERROR: {e}"
    return (r.stderr + r.stdout).decode("utf-8", errors="replace")


def parse_brief(text: str) -> dict:
    """Pull the fields s_client -brief prints, and any PEM certificates that follow."""
    out: dict = {"raw_error": None}
    if text.startswith("ERROR") or "CONNECTION ESTABLISHED" not in text:
        out["raw_error"] = text.strip().splitlines()[0] if text.strip() else "no response"
    for line in text.splitlines():
        for label, key in BRIEF_FIELDS.items():
            if line.startswith(label + ":"):
                out[key] = line.split(":", 1)[1].strip()
    if "tempkey" in out and "group" not in out:                      # classical groups: "Peer Temp Key" (3.5) / "Server Temp Key" (older)
        out["group"] = out["tempkey"].split(",")[0].strip()
    pems = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", text, re.S)
    out["certs"] = pems
    return out


def merge_endpoint(inv: Inventory, host: str, port: int, parsed: dict) -> None:
    loc = f"tls://{host}:{port}"
    occ = Occurrence(location=loc, line=0, symbol=parsed.get("peer", ""))
    if parsed.get("raw_error"):
        inv.add(Asset("protocol", "TLS", protocol_type="tls", protocol_version="unreachable",
                      notes=[f"{loc}: {parsed['raw_error']}"]), occ)
        return
    version = parsed.get("version", "unknown").replace("TLSv", "")
    proto = inv.add(Asset("protocol", "TLS", protocol_type="tls", protocol_version=version), occ)
    if parsed.get("cipher") and parsed["cipher"] not in proto.cipher_suites:
        proto.cipher_suites.append(parsed["cipher"])
    if parsed.get("group"):
        g = inv.add(group_asset(parsed["group"]), occ)
        if g.bom_ref not in proto.refs:
            proto.refs.append(g.bom_ref)
    if parsed.get("sigtype"):
        st = parsed["sigtype"]
        q = 3 if "mldsa65" in st.lower() else 5 if "mldsa87" in st.lower() else 2 if "mldsa44" in st.lower() else 0
        s = inv.add(Asset("algorithm", f"TLS signature {st}", st, "signature", functions=["sign", "verify"], quantum=q), occ)
        if s.bom_ref not in proto.refs:
            proto.refs.append(s.bom_ref)
    for pem in parsed.get("certs", [])[:1]:                            # leaf only; the chain is Chapter 7's problem
        cert = x509.load_pem_x509_certificate(pem.encode())
        sig_name = cert.signature_algorithm_oid._name
        disp, prim, q = CERT_SIG_OIDS.get(sig_name, (sig_name, "signature", 0))
        sig = inv.add(Asset("algorithm", disp, disp, prim, functions=["sign", "verify"],
                            oid=cert.signature_algorithm_oid.dotted_string, quantum=q), occ)
        key = inv.add(public_key_asset(cert.public_key()), occ)
        inv.add(Asset("certificate", cert.subject.rfc4514_string(), format(cert.serial_number, "x")[:16],
                      cert=dict(subjectName=cert.subject.rfc4514_string(), issuerName=cert.issuer.rfc4514_string(),
                                notValidBefore=cert.not_valid_before_utc.isoformat(),
                                notValidAfter=cert.not_valid_after_utc.isoformat(),
                                signatureAlgorithmRef=sig.bom_ref, subjectPublicKeyRef=key.bom_ref,
                                certificateFormat="X.509"),
                      refs=[sig.bom_ref, key.bom_ref]), occ)


def load_into_inventory(cbom: dict) -> Inventory:
    """Rebuild an Inventory from an existing CBOM so new endpoints merge rather than duplicate."""
    inv = Inventory()
    for c in cbom.get("components", []):
        if c.get("type") != "cryptographic-asset":
            continue
        cp = c["cryptoProperties"]
        occs = [Occurrence(o["location"], o.get("line", 0), o.get("symbol", "")) for o in c.get("evidence", {}).get("occurrences", [])]
        notes = [p["value"] for p in c.get("properties", []) if p["name"] == "pqm:note"]
        if cp["assetType"] == "algorithm":
            ap = cp.get("algorithmProperties", {})
            a = Asset("algorithm", c["name"], ap.get("parameterSetIdentifier", ""), ap.get("primitive", ""),
                      ap.get("curve", ""), ap.get("mode", ""), list(ap.get("cryptoFunctions", [])), cp.get("oid", ""),
                      ap.get("nistQuantumSecurityLevel"), ap.get("classicalSecurityLevel"), notes=notes)
        elif cp["assetType"] == "protocol":
            pp = cp["protocolProperties"]
            a = Asset("protocol", c["name"], protocol_type=pp["type"], protocol_version=pp.get("version", ""),
                      cipher_suites=[s["name"] for s in pp.get("cipherSuites", [])], refs=list(pp.get("cryptoRefArray", [])), notes=notes)
        elif cp["assetType"] == "certificate":
            props = cp["certificateProperties"]
            a = Asset("certificate", c["name"], _serial_from_ref(c["bom-ref"], ""), cert=props,
                      refs=[props.get("signatureAlgorithmRef", ""), props.get("subjectPublicKeyRef", "")])
        else:
            continue
        inv.add(a)
        inv.assets[a.key].occurrences.extend(occs)
    return inv


def _serial_from_ref(ref: str, fallback: str) -> str:
    m = re.search(r"-([0-9a-f]{1,16})@", ref)
    return m.group(1) if m else fallback


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Scan TLS endpoints and merge into a CBOM.")
    p.add_argument("hosts", help="file with one HOST:PORT per line")
    p.add_argument("--cbom", help="existing CBOM to merge into (default: new)")
    p.add_argument("--fixtures", help="directory of saved s_client output, HOST_PORT.txt (offline mode)")
    p.add_argument("--name", default="tls-scan")
    p.add_argument("-o", "--out", required=True)
    args = p.parse_args(argv)

    inv = load_into_inventory(json.loads(Path(args.cbom).read_text())) if args.cbom else Inventory()
    for line in Path(args.hosts).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        host, _, port = line.partition(":")
        port_i = int(port or 443)
        if args.fixtures:
            fx = Path(args.fixtures) / f"{host}_{port_i}.txt"
            text = fx.read_text() if fx.exists() else "ERROR: no fixture"
        else:
            text = run_s_client(host, port_i)
        merge_endpoint(inv, host, port_i, parse_brief(text))
    app_name = json.loads(Path(args.cbom).read_text())["metadata"]["component"]["name"] if args.cbom else args.name
    cbom = build_cbom(inv, app_name, Path(args.hosts).parent)
    Path(args.out).write_text(json.dumps(cbom, indent=2) + "\n")
    print(f"{len(inv.assets)} assets -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
