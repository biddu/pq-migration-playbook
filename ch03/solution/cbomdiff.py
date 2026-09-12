"""Lab 3.3 solution -- diff two CBOMs and report what changed.

Assets are matched on (assetType, name, parameter set / protocol version), not on
bom-ref, so two scans of the same tree produced by different tool versions still
compare. Output is Markdown you can paste into a change ticket.

Tested with: Python 3.12.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def index(cbom: dict) -> dict[tuple, dict]:
    out = {}
    for c in cbom.get("components", []):
        if c.get("type") != "cryptographic-asset":
            continue
        cp = c["cryptoProperties"]
        if cp["assetType"] == "algorithm":
            k = ("algorithm", c["name"], cp.get("algorithmProperties", {}).get("parameterSetIdentifier", ""))
        elif cp["assetType"] == "protocol":
            k = ("protocol", c["name"], cp["protocolProperties"].get("version", ""))
        else:
            k = (cp["assetType"], c["name"], "")
        out[k] = c
    return out


def locations(c: dict) -> set[str]:
    return {f"{o['location']}:{o.get('line', 0)}" for o in c.get("evidence", {}).get("occurrences", [])}


def quantum(c: dict):
    return c["cryptoProperties"].get("algorithmProperties", {}).get("nistQuantumSecurityLevel")


def diff(old: dict, new: dict) -> dict:
    a, b = index(old), index(new)
    added = sorted(set(b) - set(a))
    removed = sorted(set(a) - set(b))
    changed = []
    for k in sorted(set(a) & set(b)):
        la, lb = locations(a[k]), locations(b[k])
        if la != lb or quantum(a[k]) != quantum(b[k]):
            changed.append((k, sorted(lb - la), sorted(la - lb), quantum(a[k]), quantum(b[k])))
    still_vulnerable = sorted(k for k, c in b.items() if quantum(c) == 0)
    return {"added": [(k, sorted(locations(b[k]))) for k in added],
            "removed": [(k, sorted(locations(a[k]))) for k in removed],
            "changed": changed, "still_vulnerable": still_vulnerable}


def to_markdown(d: dict, old_name: str, new_name: str) -> str:
    def fmt(k): return f"`{k[1]}`" + (f" ({k[2]})" if k[2] else "")
    lines = [f"# CBOM change report: {old_name} -> {new_name}", ""]
    lines += [f"**Added ({len(d['added'])})**", ""] + [f"- {fmt(k)}: {', '.join(l)}" for k, l in d["added"]] + [""]
    lines += [f"**Removed ({len(d['removed'])})**", ""] + [f"- {fmt(k)}: {', '.join(l)}" for k, l in d["removed"]] + [""]
    lines += [f"**Changed ({len(d['changed'])})**", ""]
    for k, plus, minus, q0, q1 in d["changed"]:
        bits = []
        if plus: bits.append("new sites " + ", ".join(plus))
        if minus: bits.append("gone from " + ", ".join(minus))
        if q0 != q1: bits.append(f"quantum level {q0} -> {q1}")
        lines.append(f"- {fmt(k)}: " + "; ".join(bits))
    lines += ["", f"**Still quantum-vulnerable in {new_name} ({len(d['still_vulnerable'])})**", ""]
    lines += [f"- {fmt(k)}" for k in d["still_vulnerable"]]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    argv = argv or sys.argv[1:]
    if len(argv) < 2:
        print("usage: cbomdiff.py OLD.cbom.json NEW.cbom.json [-o report.md]"); return 2
    old, new = (json.loads(Path(p).read_text()) for p in argv[:2])
    md = to_markdown(diff(old, new), Path(argv[0]).name, Path(argv[1]).name)
    if "-o" in argv:
        Path(argv[argv.index("-o") + 1]).write_text(md)
    print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
