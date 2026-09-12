"""Lab 10.1 solution -- audit a PKCS#11 module for post-quantum readiness, and write the
requirements line from what you find.

PKCS#11 3.2 (OASIS Standard, 3 June 2026) is the first version of the HSM interface with
post-quantum mechanisms: CKM_ML_KEM / CKM_ML_KEM_KEY_PAIR_GEN with the new C_EncapsulateKey
and C_DecapsulateKey functions (flags CKF_ENCAPSULATE / CKF_DECAPSULATE), CKM_ML_DSA and
CKM_HASH_ML_DSA_*, CKM_SLH_DSA and its hash variants, CKM_HSS and CKM_XMSS / CKM_XMSSMT, the
key types CKK_ML_KEM / CKK_ML_DSA / CKK_SLH_DSA / CKK_HSS / CKK_XMSS, the attribute
CKA_PARAMETER_SET with CKP_* values, and CKA_SEED for seed-form private keys. Before 3.2,
every vendor exposed post-quantum algorithms under vendor-defined mechanism numbers
(>= CKM_VENDOR_DEFINED, 0x80000000), which is why the same firmware can be "PQ-capable" and
still fail a portable audit.

This tool:
  * parses the 3.2 header (fixtures/pkcs11t-v3.2.h) into name<->value tables, so mechanism
    numbers a token reports can be named without guessing
  * loads any PKCS#11 module with python-pkcs11, enumerates its tokens and mechanisms, and
    resolves each mechanism to its 3.2 name (or marks it vendor-defined / unknown)
  * checks the token against the REQUIRED and RECOMMENDED sets below and prints a gap report
  * --mock runs the same audit against MockPqToken, a stand-in for a 3.2-capable HSM, so you
    can see what a passing report looks like and test the tool without hardware
  * --requirements prints the procurement requirements line generated from the gap report

Tested with: Python 3.12, python-pkcs11 0.8, SoftHSM 2.6.1 (which reports Cryptoki 2.40 and no
post-quantum mechanisms, as expected).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
HEADER = HERE / "fixtures" / "pkcs11t-v3.2.h"
CKM_VENDOR_DEFINED = 0x80000000

REQUIRED = {                                     # what a post-quantum-ready token must offer
    "CKM_ML_KEM_KEY_PAIR_GEN": [],
    "CKM_ML_KEM": ["CKF_ENCAPSULATE", "CKF_DECAPSULATE"],
    "CKM_ML_DSA_KEY_PAIR_GEN": [],
    "CKM_ML_DSA": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_HKDF_DERIVE": ["CKF_DERIVE"],           # to turn a KEM secret into a wrapping key inside the module
    "CKM_AES_KEY_WRAP_KWP": ["CKF_WRAP", "CKF_UNWRAP"],
}
RECOMMENDED = {
    "CKM_HASH_ML_DSA_SHA512": ["CKF_SIGN"],      # pre-hash variant for large artefacts (Chapter 8)
    "CKM_SLH_DSA_KEY_PAIR_GEN": [], "CKM_SLH_DSA": ["CKF_SIGN", "CKF_VERIFY"],
    "CKM_HSS_KEY_PAIR_GEN": [], "CKM_HSS": ["CKF_SIGN", "CKF_VERIFY"],     # stateful signing with state inside the module
}


# ------------------------------------------------------------------ the 3.2 header

def parse_header(path: Path = HEADER) -> dict[str, dict]:
    """Return {'CKM': {name: value}, 'CKK': ..., 'CKP': ..., 'CKF': ..., 'CKA': ...} from pkcs11t.h."""
    tables: dict[str, dict[str, int]] = {"CKM": {}, "CKK": {}, "CKP": {}, "CKF": {}, "CKA": {}}
    for m in re.finditer(r"#define\s+(CK[MKPFA]_[A-Z0-9_]+)\s+(?:\(?\s*)(0x[0-9a-fA-F]+|\d+)", path.read_text()):
        name, val = m.group(1), int(m.group(2), 0)
        tables[name[:3]].setdefault(name, val)
    return tables


def names_by_value(table: dict[str, int]) -> dict[int, str]:
    out: dict[int, str] = {}
    for n, v in table.items():
        out.setdefault(v, n)                     # first definition wins (aliases follow in the header)
    return out


def flag_names(flags: int, ckf: dict[str, int]) -> list[str]:
    wanted = ["CKF_HW", "CKF_ENCRYPT", "CKF_DECRYPT", "CKF_DIGEST", "CKF_SIGN", "CKF_VERIFY", "CKF_GENERATE",
              "CKF_GENERATE_KEY_PAIR", "CKF_WRAP", "CKF_UNWRAP", "CKF_DERIVE", "CKF_ENCAPSULATE", "CKF_DECAPSULATE"]
    return [n for n in wanted if n in ckf and flags & ckf[n]]


# ------------------------------------------------------------------ tokens: real and mock

@dataclass
class MechRow:
    value: int
    name: str
    flags: list[str]
    min_key: int | None = None
    max_key: int | None = None
    vendor_defined: bool = False


@dataclass
class TokenReport:
    module: str
    manufacturer: str
    description: str
    library_version: str
    cryptoki_version: str
    token_label: str
    firmware_version: str
    mechanisms: list[MechRow] = field(default_factory=list)
    required_missing: dict[str, list[str]] = field(default_factory=dict)
    recommended_missing: dict[str, list[str]] = field(default_factory=dict)
    verdict: str = ""


def audit_real(module_path: str, token_label: str | None, tables) -> TokenReport:
    import pkcs11
    lib = pkcs11.lib(module_path)
    tok = lib.get_token(token_label=token_label) if token_label else next(iter(lib.get_tokens()))
    slot = tok.slot
    rep = TokenReport(module_path, lib.manufacturer_id.strip(), lib.library_description.strip(),
                      ".".join(map(str, lib.library_version)), ".".join(map(str, lib.cryptoki_version)),
                      tok.label.strip(), ".".join(map(str, tok.firmware_version)))
    ckm_names, ckf = names_by_value(tables["CKM"]), tables["CKF"]
    for mech in slot.get_mechanisms():
        v = int(mech)
        try:
            info = slot.get_mechanism_info(mech)
            fl, lo, hi = int(info.flags), info.min_key_length, info.max_key_length
        except Exception:
            fl, lo, hi = 0, None, None
        rep.mechanisms.append(MechRow(v, ckm_names.get(v, f"vendor-defined 0x{v:08x}" if v >= CKM_VENDOR_DEFINED else f"unknown 0x{v:08x}"),
                                      flag_names(fl, ckf), lo, hi, v >= CKM_VENDOR_DEFINED))
    return finish(rep)


class MockPqToken:
    """What a PKCS#11 3.2 HSM firmware reports. Mechanism numbers are the real 3.2 constants; the
    flags are what the specification's mechanism table says each supports. Nothing is signed here:
    the mock exists so the audit tool can be tested and so a passing report can be seen."""
    def __init__(self, tables):
        ckm, ckf = tables["CKM"], tables["CKF"]
        f = lambda *names: sum(ckf[n] for n in names)
        self.info = dict(manufacturer="PQM Labs (mock)", description="Mock PKCS#11 3.2 token", library_version="3.2",
                         cryptoki_version="3.2", token_label="mock-pq", firmware_version="1.0")
        self.table = {
            ckm["CKM_AES_KEY_GEN"]: f("CKF_GENERATE"), ckm["CKM_AES_GCM"]: f("CKF_ENCRYPT", "CKF_DECRYPT"),
            ckm["CKM_AES_KEY_WRAP_KWP"]: f("CKF_WRAP", "CKF_UNWRAP"), ckm["CKM_HKDF_DERIVE"]: f("CKF_DERIVE"),
            ckm["CKM_SHA256"]: f("CKF_DIGEST"), ckm["CKM_SHA3_256"]: f("CKF_DIGEST"),
            ckm["CKM_EC_KEY_PAIR_GEN"]: f("CKF_GENERATE_KEY_PAIR"), ckm["CKM_ECDSA"]: f("CKF_SIGN", "CKF_VERIFY"),
            ckm["CKM_ML_KEM_KEY_PAIR_GEN"]: f("CKF_GENERATE_KEY_PAIR"),
            ckm["CKM_ML_KEM"]: f("CKF_ENCAPSULATE", "CKF_DECAPSULATE"),
            ckm["CKM_ML_DSA_KEY_PAIR_GEN"]: f("CKF_GENERATE_KEY_PAIR"),
            ckm["CKM_ML_DSA"]: f("CKF_SIGN", "CKF_VERIFY"),
            ckm["CKM_HASH_ML_DSA_SHA512"]: f("CKF_SIGN", "CKF_VERIFY"),
            ckm["CKM_SLH_DSA_KEY_PAIR_GEN"]: f("CKF_GENERATE_KEY_PAIR"), ckm["CKM_SLH_DSA"]: f("CKF_SIGN", "CKF_VERIFY"),
            ckm["CKM_HSS_KEY_PAIR_GEN"]: f("CKF_GENERATE_KEY_PAIR"), ckm["CKM_HSS"]: f("CKF_SIGN", "CKF_VERIFY"),
        }


def audit_mock(tables) -> TokenReport:
    m = MockPqToken(tables)
    rep = TokenReport("mock", m.info["manufacturer"], m.info["description"], m.info["library_version"],
                      m.info["cryptoki_version"], m.info["token_label"], m.info["firmware_version"])
    ckm_names, ckf = names_by_value(tables["CKM"]), tables["CKF"]
    for v, fl in sorted(m.table.items()):
        rep.mechanisms.append(MechRow(v, ckm_names[v], flag_names(fl, ckf)))
    return finish(rep)


def finish(rep: TokenReport) -> TokenReport:
    have = {r.name: set(r.flags) for r in rep.mechanisms}

    def missing(spec):
        out = {}
        for name, flags in spec.items():
            if name not in have:
                out[name] = ["absent"]
            else:
                lack = [f for f in flags if f not in have[name]]
                if lack:
                    out[name] = lack
        return out

    rep.required_missing, rep.recommended_missing = missing(REQUIRED), missing(RECOMMENDED)
    n_vendor = sum(1 for r in rep.mechanisms if r.vendor_defined)
    if not rep.required_missing:
        rep.verdict = "READY: all required post-quantum mechanisms present with the right capabilities"
    elif n_vendor:
        rep.verdict = (f"NOT PORTABLE: {len(rep.required_missing)} required 3.2 mechanisms missing; "
                       f"{n_vendor} vendor-defined mechanisms present (ask the vendor which are post-quantum and when they move to 3.2 numbers)")
    else:
        rep.verdict = f"NOT READY: {len(rep.required_missing)} of {len(REQUIRED)} required mechanisms missing; Cryptoki {rep.cryptoki_version}"
    return rep


# ------------------------------------------------------------------ output

def report_text(rep: TokenReport) -> str:
    lines = [f"module      : {rep.module}", f"library     : {rep.manufacturer} / {rep.description} v{rep.library_version}, Cryptoki {rep.cryptoki_version}",
             f"token       : {rep.token_label!r}, firmware {rep.firmware_version}", f"mechanisms  : {len(rep.mechanisms)}"]
    pq = [r for r in rep.mechanisms if any(k in r.name for k in ("ML_KEM", "ML_DSA", "SLH_DSA", "HSS", "XMSS"))]
    lines.append("post-quantum: " + (", ".join(f"{r.name}[{'|'.join(x[4:] for x in r.flags)}]" for r in pq) if pq else "none"))
    vend = [r for r in rep.mechanisms if r.vendor_defined]
    if vend:
        lines.append(f"vendor-def. : {len(vend)} mechanisms ({', '.join(f'0x{r.value:08x}' for r in vend[:6])}{', ...' if len(vend) > 6 else ''})")
    lines.append("required    : " + ("all present" if not rep.required_missing else "; ".join(f"{k}: {','.join(v)}" for k, v in rep.required_missing.items())))
    lines.append("recommended : " + ("all present" if not rep.recommended_missing else "; ".join(f"{k}: {','.join(v)}" for k, v in rep.recommended_missing.items())))
    lines.append(f"verdict     : {rep.verdict}")
    return "\n".join(lines)


def requirements_line(rep: TokenReport) -> str:
    """The sentence for the RFP or the vendor questionnaire, generated from the gap."""
    req = ", ".join(REQUIRED)
    rec = ", ".join(RECOMMENDED)
    return (f"The HSM shall implement PKCS#11 v3.2 (OASIS Standard, June 2026) and expose, under their 3.2 mechanism numbers and not "
            f"vendor-defined values, at least: {req}; with C_EncapsulateKey/C_DecapsulateKey for CKM_ML_KEM, CKA_PARAMETER_SET "
            f"for ML-KEM-768/1024 and ML-DSA-65/87, and CKA_SEED import/export policy for seed-form keys. Recommended: {rec}. "
            f"The firmware containing these mechanisms shall hold, or have been submitted for, FIPS 140-3 Level 3 validation with "
            f"ML-KEM and ML-DSA inside the module boundary (CMVP certificate number or submission date to be stated). "
            f"Current gap on the audited module ({rep.description} {rep.library_version}, Cryptoki {rep.cryptoki_version}): "
            f"{', '.join(rep.required_missing) if rep.required_missing else 'none'}.")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Audit a PKCS#11 module for post-quantum mechanisms (PKCS#11 3.2).")
    p.add_argument("--module", default="/usr/lib/softhsm/libsofthsm2.so")
    p.add_argument("--token", default=None, help="token label (default: first token)")
    p.add_argument("--mock", action="store_true", help="audit the built-in mock 3.2 token instead of a module")
    p.add_argument("--requirements", action="store_true", help="print the procurement requirements line")
    p.add_argument("--json")
    a = p.parse_args(argv)
    tables = parse_header()
    rep = audit_mock(tables) if a.mock else audit_real(a.module, a.token, tables)
    print(report_text(rep))
    if a.requirements:
        print("\n" + requirements_line(rep))
    if a.json:
        Path(a.json).write_text(json.dumps(asdict(rep), indent=2) + "\n")
    return 0 if not rep.required_missing else 1


if __name__ == "__main__":
    sys.exit(main())
