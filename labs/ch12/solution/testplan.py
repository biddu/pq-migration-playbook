"""Lab 12.3 solution -- the migration test plan as an executable, run against the book's lab estate.

The plan in templates/migration_test_plan.md has seven sections. This runner executes the parts of
it that the lab estate can answer and writes a report with one line per check, so that the plan is a
thing that passes or fails rather than a document that is read once:

  1  Correctness       every chapter's acceptance tests (PQ_LAB_IMPL=solution pytest labs/chNN/tests)
  2  Known-answer      the standards' own vectors: RFC 8554 TC1 (Lab 8.2), X-Wing draft vector (Lab 9.1),
                       FIPS 203/204 sizes (Labs 2.1, 8.1)
  3  Interoperability  the Lab 12.1 matrix: every pair that must work does, every n/s is known
  4  Side channels     the Lab 12.2 detector: no leak found in the library targets; leaks found in the toys
  5  Performance       Lab 5.3 and Lab 8.1 numbers against the budgets in the plan (ratios, not absolutes)
  6  Agility           the Lab 11.2 drill passes and the property tests pass
  7  Rollback          the drill's rollback step restored the policy digest

Anything the estate cannot answer (CAVP/CMVP evidence, production canaries) is reported as
"manual", with the template section that says what evidence to attach.

Tested with: Python 3.12; runs the other labs' test suites, so needs their toolchains.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
LABS = HERE.parent
ROOT = LABS.parent

BUDGETS = {  # from the test plan: acceptable ratios relative to the classical baseline
    "tls_hybrid_handshake_time_ratio_max": 1.10,      # Lab 5.3: hybrid KEX vs classical
    "tls_mldsa_cert_handshake_time_ratio_max": 2.50,  # Lab 5.3: ML-DSA-65 cert vs ECDSA
    "mldsa65_verify_4M_ratio_max": 2.5,               # Lab 8.1: verify time vs Ed25519 on a 4 MiB image
}


def run(cmd: list[str], cwd: Path = ROOT, timeout: int = 900, env: dict | None = None) -> tuple[int, str]:
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, env={**os.environ, **(env or {})})
    return r.returncode, r.stdout + r.stderr


def pytest_summary(out: str) -> str:
    m = re.search(r"(\d+ passed.*?)(?: in [\d.]+s)?\s*$", out.strip().splitlines()[-1] if out.strip() else "")
    return m.group(1) if m else out.strip().splitlines()[-1][:80] if out.strip() else "no output"


def section_1_correctness(report: list) -> None:
    env = {"PQ_LAB_IMPL": "solution"}
    for ch in sorted(p.name for p in LABS.iterdir() if p.is_dir() and re.fullmatch(r"ch\d\d", p.name) and (p / "tests").exists()):
        if ch == "ch12":
            continue
        t0 = time.perf_counter()
        code, out = run([sys.executable, "-m", "pytest", "-q", f"labs/{ch}/tests"], env=env)
        report.append({"section": "1 correctness", "check": f"{ch} acceptance tests", "status": "PASS" if code == 0 else "FAIL",
                       "detail": pytest_summary(out), "seconds": round(time.perf_counter() - t0, 1)})


def section_2_known_answer(report: list) -> None:
    checks = [
        ("RFC 8554 Test Case 1 verifies (LMS/HSS)", "labs/ch08/tests/test_ch08.py::test_rfc8554_test_case_1_verifies"),
        ("X-Wing keygen matches draft vector", "labs/ch09/tests/test_ch09.py::test_xwing_keygen_matches_draft_test_vector"),
        ("X-Wing decapsulation matches draft vector", "labs/ch09/tests/test_ch09.py::test_xwing_decapsulation_matches_draft_test_vector"),
        ("FIPS 204 ML-DSA-65 sizes", "labs/ch08/tests/test_ch08.py::test_ml_dsa_sizes_are_fips204"),
    ]
    for name, node in checks:
        code, out = run([sys.executable, "-m", "pytest", "-q", node], env={"PQ_LAB_IMPL": "solution"})
        report.append({"section": "2 known-answer", "check": name, "status": "PASS" if code == 0 else "FAIL", "detail": pytest_summary(out)})
    report.append({"section": "2 known-answer", "check": "CAVP/ACVP vectors for the production library", "status": "MANUAL",
                   "detail": "attach the CAVP certificate numbers or ACVP run for the library versions in the CBOM (plan section 2.3)"})


def section_3_interop(report: list) -> None:
    f = HERE / "results" / "interop.json"
    if not f.exists():
        report.append({"section": "3 interoperability", "check": "Lab 12.1 matrix", "status": "SKIP", "detail": "run solution/interop.py first"}); return
    data = json.loads(f.read_text()); rows = data["rows"]
    must = [("openssl", "openssl", "X25519MLKEM768"), ("openssl", "go", "X25519MLKEM768"), ("go", "openssl", "X25519MLKEM768"), ("go", "go", "X25519MLKEM768")]
    for s, c, g in must:
        r = next(x for x in rows if (x["server"], x["client"], x["group"]) == (s, c, g))
        ok = r["status"] == "OK" and r.get("negotiated") == g
        report.append({"section": "3 interoperability", "check": f"{s} server <- {c} client, {g}", "status": "PASS" if ok else "FAIL",
                       "detail": f"negotiated {r.get('negotiated')}, ClientHello {r.get('client_hello_bytes')} B"})
    ns = sum(1 for x in rows if x["status"] == "UNSUPPORTED"); fails = [x for x in rows if x["status"] == "FAIL"]
    report.append({"section": "3 interoperability", "check": "known gaps are known", "status": "INFO",
                   "detail": f"{ns} cells not configurable, {len(fails)} handshake failures; pyssl on OpenSSL {data['pyssl_openssl']} "
                             f"({'no' if data['pyssl_openssl'].startswith('3.0') else 'has'} post-quantum groups)"})


def section_4_side_channels(report: list) -> None:
    f = HERE / "results" / "timing.json"
    if not f.exists():
        report.append({"section": "4 side channels", "check": "Lab 12.2 detector", "status": "SKIP", "detail": "run solution/timing.py first"}); return
    for r in json.loads(f.read_text()):
        toy = "toy" in r["target"] or "early-exit" in r["target"]
        expected_leak = "leaky" in r["target"] or "early-exit" in r["target"]
        ok = r["leak"] == expected_leak
        report.append({"section": "4 side channels", "check": r["target"], "status": "PASS" if ok else "FAIL",
                       "detail": f"t = {r['t']}, {'leak' if r['leak'] else 'no leak'} ({'expected' if ok else 'UNEXPECTED'}); "
                                 f"{'detector sanity check' if toy else 'library under test'}"})
    report.append({"section": "4 side channels", "check": "constant-time claims of the production library", "status": "MANUAL",
                   "detail": "the detector cannot prove absence; attach the vendor's/library's constant-time statement and CAVP/CMVP status (plan 4.2)"})


def section_5_performance(report: list) -> None:
    lt = LABS / "ch05" / "results" / "loadtest.json"
    if lt.exists():
        rows = json.loads(lt.read_text()); base = rows[0]["mean_ms"]
        hyb = next(r for r in rows if r["config"] == "X25519MLKEM768 / ECDSA")["mean_ms"] / base
        cert = next(r for r in rows if r["config"] == "X25519 / ML-DSA-65")["mean_ms"] / base
        report.append({"section": "5 performance", "check": "hybrid KEX handshake time ratio", "status": "PASS" if hyb <= BUDGETS["tls_hybrid_handshake_time_ratio_max"] else "FAIL",
                       "detail": f"{hyb:.2f}x vs budget {BUDGETS['tls_hybrid_handshake_time_ratio_max']}x (Lab 5.3)"})
        report.append({"section": "5 performance", "check": "ML-DSA-65 certificate handshake time ratio", "status": "PASS" if cert <= BUDGETS["tls_mldsa_cert_handshake_time_ratio_max"] else "FAIL",
                       "detail": f"{cert:.2f}x vs budget {BUDGETS['tls_mldsa_cert_handshake_time_ratio_max']}x (Lab 5.3)"})
    sb = LABS / "ch08" / "results" / "signbench.json"
    if sb.exists():
        rows = json.loads(sb.read_text())
        ed = next(r for r in rows if r["name"] == "Ed25519")["verify_ms_4M"]; ml = next(r for r in rows if r["name"] == "ML-DSA-65")["verify_ms_4M"]
        report.append({"section": "5 performance", "check": "ML-DSA-65 verify on 4 MiB vs Ed25519", "status": "PASS" if ml / ed <= BUDGETS["mldsa65_verify_4M_ratio_max"] else "FAIL",
                       "detail": f"{ml / ed:.2f}x vs budget {BUDGETS['mldsa65_verify_4M_ratio_max']}x (Lab 8.1)"})
    report.append({"section": "5 performance", "check": "production p99 handshake latency on the canary", "status": "MANUAL",
                   "detail": "measure on the real path; the loopback ratios above do not include the extra round trip (plan 5.2)"})


def section_6_7_agility_rollback(report: list) -> None:
    code, out = run([sys.executable, "labs/ch11/solution/drill.py"], timeout=300)
    report.append({"section": "6 agility", "check": "kill-switch drill", "status": "PASS" if code == 0 else "FAIL",
                   "detail": (out.strip().splitlines() or ["?"])[-1][:100]})
    d = LABS / "ch11" / "results" / "drill.json"
    if d.exists():
        r = json.loads(d.read_text())
        rb = r["steps"][-1]
        report.append({"section": "7 rollback", "check": "rollback restored policy digest and choices", "status": "PASS" if rb.get("restored") else "FAIL",
                       "detail": f"{rb['seconds']} s; {r['downgrades_flagged']} downgrades flagged during drill"})
    report.append({"section": "7 rollback", "check": "production rollback rehearsed within the last quarter", "status": "MANUAL",
                   "detail": "date and duration of the last rehearsal against production configuration (runbook section R3)"})


def render(report: list) -> str:
    lines = ["# Migration test plan -- run report", "", f"Generated {time.strftime('%Y-%m-%d %H:%M:%S')} on the lab estate.", "",
             "| Section | Check | Status | Detail |", "|---|---|---|---|"]
    for r in report:
        lines.append(f"| {r['section']} | {r['check']} | {r['status']} | {r['detail']} |")
    counts = {}
    for r in report:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    lines += ["", "Summary: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items()))]
    return "\n".join(lines) + "\n"


def main() -> int:
    report: list[dict] = []
    section_1_correctness(report)
    section_2_known_answer(report)
    section_3_interop(report)
    section_4_side_channels(report)
    section_5_performance(report)
    section_6_7_agility_rollback(report)
    md = render(report)
    (HERE / "results").mkdir(exist_ok=True)
    (HERE / "results" / "testplan_report.md").write_text(md)
    (HERE / "results" / "testplan_report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(md)
    return 0 if not any(r["status"] == "FAIL" for r in report) else 1


if __name__ == "__main__":
    sys.exit(main())
