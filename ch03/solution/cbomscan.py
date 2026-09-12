"""Lab 3.1 solution -- a repository scanner that emits a CycloneDX 1.6 CBOM.

Walks a source tree, applies the regular-expression rules in rules.yaml to the
files each rule covers, parses any X.509 certificates it finds, and writes a
Cryptography Bill of Materials: one `cryptographic-asset` component per distinct
algorithm, protocol or certificate, with every place it was seen recorded as
evidence. The application component depends on all of them.

This is deliberately a regex scanner. It finds the call sites a grep would find,
which is most of them, and it misses what a grep misses: algorithms chosen at run
time, defaults inside frameworks, and anything in a binary. Chapter 3 says what to
do about those. The value of this tool is that it is auditable and repeatable, and
that its output is in the format regulators and downstream tools expect.

Tested with: Python 3.12, PyYAML 6.0, cryptography 50.0, jsonschema 4.26.
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import yaml
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa

HERE = Path(__file__).resolve().parent
DEFAULT_RULES = HERE.parent / "rules.yaml"
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "build", "dist", ".pytest_cache"}

# Post-processing knowledge the rules file keeps out of its regexes.
PQ_GROUPS = {"X25519MLKEM768": 3, "SecP256r1MLKEM768": 3, "SecP384r1MLKEM1024": 5,
             "mlkem768x25519-sha256": 3, "sntrup761x25519-sha256": 3, "mlkem768-sha256": 3}
CLASSICAL_GROUP_OIDS = {"X25519": "1.3.101.110", "prime256v1": "1.2.840.10045.3.1.7", "P256": "1.2.840.10045.3.1.7",
                        "CurveP256": "1.2.840.10045.3.1.7", "secp384r1": "1.3.132.0.34", "CurveP384": "1.3.132.0.34"}
CURVE_ALIASES = {"P256": "P-256", "CurveP256": "P-256", "prime256v1": "P-256", "secp256r1": "P-256", "SECP256R1": "P-256",
                 "P384": "P-384", "CurveP384": "P-384", "secp384r1": "P-384", "SECP384R1": "P-384",
                 "P521": "P-521", "secp521r1": "P-521", "SECP521R1": "P-521"}
CERT_SIG_OIDS = {  # OpenSSL name -> (display name, primitive, quantum level)
    "sha256WithRSAEncryption": ("RSA-SHA256", "signature", 0), "sha384WithRSAEncryption": ("RSA-SHA384", "signature", 0),
    "ecdsa-with-SHA256": ("ECDSA-SHA256", "signature", 0), "ecdsa-with-SHA384": ("ECDSA-SHA384", "signature", 0),
    "ED25519": ("Ed25519", "signature", 0), "ML-DSA-44": ("ML-DSA-44", "signature", 2),
    "ML-DSA-65": ("ML-DSA-65", "signature", 3), "ML-DSA-87": ("ML-DSA-87", "signature", 5),
}


# ------------------------------------------------------------------ data model

@dataclass
class Occurrence:
    location: str
    line: int
    symbol: str = ""


@dataclass
class Asset:
    """One distinct cryptographic asset. Identity is (asset_type, name, parameter_set)."""
    asset_type: str                         # algorithm | protocol | certificate | related-crypto-material
    name: str
    parameter_set: str = ""
    primitive: str = ""
    curve: str = ""
    mode: str = ""
    functions: list[str] = field(default_factory=list)
    oid: str = ""
    quantum: int | None = None
    classical: int | None = None
    protocol_type: str = ""
    protocol_version: str = ""
    cipher_suites: list[str] = field(default_factory=list)
    refs: list[str] = field(default_factory=list)     # bom-refs of algorithms this protocol/cert uses
    cert: dict = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    occurrences: list[Occurrence] = field(default_factory=list)

    @property
    def key(self) -> tuple:
        return (self.asset_type, self.name, self.parameter_set, self.protocol_version)

    @property
    def bom_ref(self) -> str:
        h = hashlib.sha1("|".join(map(str, self.key)).encode()).hexdigest()[:10]
        slug = re.sub(r"[^A-Za-z0-9.-]+", "-", f"{self.name}-{self.parameter_set or self.protocol_version}").strip("-")
        return f"crypto/{self.asset_type}/{slug}@{h}"


class Inventory:
    def __init__(self) -> None:
        self.assets: dict[tuple, Asset] = {}
        self.libraries: dict[tuple, list[Occurrence]] = defaultdict(list)

    def add(self, asset: Asset, occ: Occurrence | None = None) -> Asset:
        existing = self.assets.setdefault(asset.key, asset)
        if occ is not None:
            existing.occurrences.append(occ)
        for n in asset.notes:
            if n not in existing.notes:
                existing.notes.append(n)
        for r in asset.refs:
            if r not in existing.refs:
                existing.refs.append(r)
        return existing


# ------------------------------------------------------------------ rules

def load_rules(path: Path) -> dict:
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def file_class_of(path: Path, classes: dict[str, list[str]]) -> str | None:
    rel = path.as_posix()
    for cls, globs in classes.items():
        for g in globs:
            if fnmatch.fnmatch(path.name, g) or fnmatch.fnmatch(rel, f"*{g}"):
                return cls
    return None


def fill(template, groups: tuple) -> str:
    out = str(template)
    for i, g in enumerate(groups, start=1):
        out = out.replace(f"{{{i}}}", g or "")
    return out


def algorithm_from_rule(spec: dict, groups: tuple, note: str | None) -> Asset:
    a = Asset(asset_type="algorithm",
              name=fill(spec["name"], groups),
              parameter_set=fill(spec.get("parameter_set", ""), groups),
              primitive=spec.get("primitive", "unknown"),
              curve=fill(spec.get("curve", ""), groups),
              mode=spec.get("mode", ""),
              functions=list(spec.get("functions", [])),
              oid=spec.get("oid", ""),
              quantum=spec.get("quantum"),
              classical=spec.get("classical"))
    if a.name == "ECDSA":                                  # one name per curve, whatever the language calls it
        a.curve = CURVE_ALIASES.get(a.curve, a.curve)
        a.parameter_set = CURVE_ALIASES.get(a.parameter_set, a.parameter_set)
    if a.parameter_set in PQ_GROUPS:                       # hybrid groups are post-quantum
        a.quantum = PQ_GROUPS[a.parameter_set]
    if not a.oid and a.parameter_set in CLASSICAL_GROUP_OIDS:
        a.oid = CLASSICAL_GROUP_OIDS[a.parameter_set]
    if note:
        a.notes.append(note)
    return a


def group_asset(name: str) -> Asset:
    name = name.strip()
    return Asset(asset_type="algorithm", name=f"TLS group {name}", parameter_set=name, primitive="key-agree",
                 functions=["keygen"], oid=CLASSICAL_GROUP_OIDS.get(name, ""),
                 quantum=PQ_GROUPS.get(name, 0), classical=128 if name not in PQ_GROUPS else None)


def kex_asset(name: str) -> Asset:
    name = name.strip()
    return Asset(asset_type="algorithm", name=f"SSH KEX {name}", parameter_set=name, primitive="key-agree",
                 functions=["keygen"], quantum=PQ_GROUPS.get(name, 0), classical=128 if name not in PQ_GROUPS else None)


# ------------------------------------------------------------------ scanning

def scan_text_file(path: Path, rel: str, cls: str, rules: list[dict], inv: Inventory) -> None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    lines = text.splitlines()
    for rule in rules:
        if rule["file_class"] != cls:
            continue
        rx = re.compile(rule["pattern"], re.MULTILINE)
        for m in rx.finditer(text):
            line_no = text.count("\n", 0, m.start()) + 1
            occ = Occurrence(location=rel, line=line_no, symbol=lines[line_no - 1].strip()[:120])
            groups = m.groups()
            note = rule.get("note")
            if "asset" in rule:
                inv.add(algorithm_from_rule(rule["asset"], groups, note), occ)
            if "protocol" in rule:
                p = rule["protocol"]
                for ver in re.split(r"[\s,]+", fill(p["version"], groups).strip()):
                    ver = ver.replace("TLSv", "")
                    inv.add(Asset(asset_type="protocol", name=p["type"].upper(), protocol_type=p["type"],
                                  protocol_version=ver, quantum=None), occ)
            if "group_list" in rule:
                for g in fill(rule["group_list"], groups).split(":"):
                    inv.add(group_asset(g), occ)
            if "kex_list" in rule:
                for k in fill(rule["kex_list"], groups).split(","):
                    inv.add(kex_asset(k), occ)
            if "cipher_list" in rule:
                suites = [s.strip() for s in fill(rule["cipher_list"], groups).split(":") if s.strip()]
                proto = inv.add(Asset(asset_type="protocol", name="TLS", protocol_type="tls", protocol_version="1.2"), occ)
                for s in suites:
                    if s not in proto.cipher_suites:
                        proto.cipher_suites.append(s)
            if "library" in rule:
                lib = rule["library"]
                inv.libraries[(fill(lib["name"], groups), fill(lib["version"], groups))].append(occ)


def public_key_asset(pub) -> Asset:
    if isinstance(pub, rsa.RSAPublicKey):
        return Asset("algorithm", "RSA", f"RSA-{pub.key_size}", "pke", functions=["verify"],
                     oid="1.2.840.113549.1.1.1", quantum=0, classical=112 if pub.key_size < 3072 else 128)
    if isinstance(pub, ec.EllipticCurvePublicKey):
        curve = CURVE_ALIASES.get(pub.curve.name, pub.curve.name)
        return Asset("algorithm", "ECDSA", curve, "signature", curve=curve, functions=["verify"],
                     oid="1.2.840.10045.2.1", quantum=0, classical=pub.curve.key_size // 2)
    if isinstance(pub, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        return Asset("algorithm", "EdDSA", type(pub).__name__.replace("PublicKey", ""), "signature",
                     functions=["verify"], oid="1.3.101.112", quantum=0, classical=128)
    name = type(pub).__name__.replace("PublicKey", "")          # ML-DSA keys land here
    q = {"MLDSA44": 2, "MLDSA65": 3, "MLDSA87": 5}.get(name)
    return Asset("algorithm", name, name, "signature", functions=["verify"], quantum=q)


def scan_certificate(path: Path, rel: str, inv: Inventory) -> None:
    data = path.read_bytes()
    certs = []
    try:
        certs = x509.load_pem_x509_certificates(data)
    except ValueError:
        try:
            certs = [x509.load_der_x509_certificate(data)]
        except ValueError:
            return
    for cert in certs:
        occ = Occurrence(location=rel, line=1, symbol=cert.subject.rfc4514_string())
        sig_name = cert.signature_algorithm_oid._name
        disp, prim, q = CERT_SIG_OIDS.get(sig_name, (sig_name, "signature", 0))
        sig = inv.add(Asset("algorithm", disp, disp, prim, functions=["sign", "verify"],
                            oid=cert.signature_algorithm_oid.dotted_string, quantum=q), occ)
        key = inv.add(public_key_asset(cert.public_key()), occ)
        c = Asset(asset_type="certificate", name=cert.subject.rfc4514_string(),
                  parameter_set=format(cert.serial_number, "x")[:16],
                  cert=dict(subjectName=cert.subject.rfc4514_string(), issuerName=cert.issuer.rfc4514_string(),
                            notValidBefore=cert.not_valid_before_utc.isoformat(),
                            notValidAfter=cert.not_valid_after_utc.isoformat(),
                            signatureAlgorithmRef=sig.bom_ref, subjectPublicKeyRef=key.bom_ref,
                            certificateFormat="X.509"),
                  refs=[sig.bom_ref, key.bom_ref])
        inv.add(c, occ)


def scan_tree(root: Path, rules_doc: dict, inv: Inventory) -> int:
    classes = rules_doc["file_classes"]
    rules = rules_doc["rules"]
    n = 0
    for path in sorted(root.rglob("*")):
        if not path.is_file() or any(part in SKIP_DIRS for part in path.parts):
            continue
        rel = path.relative_to(root).as_posix()
        n += 1
        if path.suffix.lower() in {".crt", ".pem", ".cer", ".der"}:
            scan_certificate(path, rel, inv)
            continue
        cls = file_class_of(path, classes)
        if cls:
            scan_text_file(path, rel, cls, rules, inv)
    return n


# ------------------------------------------------------------------ CBOM output

def component_for(a: Asset) -> dict:
    cp: dict = {"assetType": a.asset_type}
    if a.oid:
        cp["oid"] = a.oid
    if a.asset_type == "algorithm":
        ap: dict = {"primitive": a.primitive or "unknown"}
        if a.parameter_set:
            ap["parameterSetIdentifier"] = a.parameter_set
        if a.curve:
            ap["curve"] = a.curve
        if a.mode:
            ap["mode"] = a.mode
        if a.functions:
            ap["cryptoFunctions"] = a.functions
        if a.classical is not None:
            ap["classicalSecurityLevel"] = a.classical
        if a.quantum is not None:
            ap["nistQuantumSecurityLevel"] = a.quantum
        cp["algorithmProperties"] = ap
    elif a.asset_type == "protocol":
        pp: dict = {"type": a.protocol_type, "version": a.protocol_version}
        if a.cipher_suites:
            pp["cipherSuites"] = [{"name": s} for s in a.cipher_suites]
        if a.refs:
            pp["cryptoRefArray"] = a.refs
        cp["protocolProperties"] = pp
    elif a.asset_type == "certificate":
        cp["certificateProperties"] = a.cert
    comp = {"type": "cryptographic-asset", "bom-ref": a.bom_ref, "name": a.name, "cryptoProperties": cp}
    if a.occurrences:
        comp["evidence"] = {"occurrences": [
            {"location": o.location, "line": o.line, **({"symbol": o.symbol} if o.symbol else {})}
            for o in a.occurrences]}
    if a.notes:
        comp["properties"] = [{"name": "pqm:note", "value": n} for n in a.notes]
    return comp


def build_cbom(inv: Inventory, app_name: str, root: Path) -> dict:
    app_ref = f"app/{app_name}"
    components = [component_for(a) for a in sorted(inv.assets.values(), key=lambda a: a.key)]
    for (name, version), occs in sorted(inv.libraries.items()):
        components.append({"type": "library", "bom-ref": f"lib/{name}@{version}", "name": name, "version": version,
                           "evidence": {"occurrences": [{"location": o.location, "line": o.line} for o in occs]}})
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "tools": {"components": [{"type": "application", "name": "cbomscan", "version": "0.1"}]},
            "component": {"type": "application", "bom-ref": app_ref, "name": app_name,
                          "description": f"Scanned from {root.name}"},
        },
        "components": components,
        "dependencies": [{"ref": app_ref, "dependsOn": [c["bom-ref"] for c in components]}],
    }


def summary(inv: Inventory) -> str:
    rows = []
    for a in sorted(inv.assets.values(), key=lambda a: (a.asset_type, a.name)):
        verdict = {None: "-", 0: "quantum-vulnerable"}.get(a.quantum, f"category {a.quantum}")
        where = f"{len(a.occurrences)} site(s)"
        rows.append(f"{a.asset_type:<12} {a.name[:34]:<34} {(a.parameter_set or a.protocol_version)[:18]:<18} {verdict:<18} {where}")
    head = f"{'type':<12} {'asset':<34} {'parameters':<18} {'quantum':<18} evidence"
    return "\n".join([head, "-" * len(head), *rows])


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Scan a source tree and emit a CycloneDX 1.6 CBOM.")
    p.add_argument("root")
    p.add_argument("--rules", default=str(DEFAULT_RULES))
    p.add_argument("--name", default=None, help="application name (default: folder name)")
    p.add_argument("-o", "--out", default=None)
    args = p.parse_args(argv)
    root = Path(args.root).resolve()
    inv = Inventory()
    n = scan_tree(root, load_rules(Path(args.rules)), inv)
    cbom = build_cbom(inv, args.name or root.name, root)
    out = Path(args.out) if args.out else HERE.parent / "results" / f"{root.name}.cbom.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(cbom, indent=2) + "\n", encoding="utf-8")
    print(f"scanned {n} files; {len(inv.assets)} cryptographic assets, {len(inv.libraries)} libraries -> {out}")
    print(summary(inv))
    return 0


if __name__ == "__main__":
    sys.exit(main())
