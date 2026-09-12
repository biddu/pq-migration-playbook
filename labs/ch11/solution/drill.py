"""Lab 11.2 (part 1) -- the kill-switch drill: rehearse the rollback path on a schedule.

A rollback path that has never been exercised is a hope, not a control. This drill:
  1. establishes N channels under the current policy and records what they negotiated
  2. "discovers" that the preferred KEM is broken, adds it to the kill switch, writes the new
     policy version to disk, reloads, and re-establishes the N channels
  3. asserts that nothing chose the killed algorithm and nothing fell below the policy floor
  4. rolls back, re-establishes, and asserts the original choice is restored
  5. reports the time each step took and the telemetry counts, which is the drill's evidence

Run it in CI on a schedule. If step 2 ever chooses X25519 because ML-KEM-768 was also unavailable,
the drill has found the day the estate had no post-quantum path, which is exactly what a drill is
for. Tested with: Python 3.12.
"""
from __future__ import annotations

import datetime as dt
import json
import shutil
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import agile  # noqa: E402

HERE = Path(__file__).resolve().parents[1]


def establish(policy: agile.Policy, peer: agile.Policy, n: int, now: dt.date) -> Counter:
    c = Counter()
    for _ in range(n):
        ch = agile.Channel(policy, peer, now)
        c[(ch.kem_event.chosen, ch.sig_event.chosen)] += 1
    return c


def run(policy_path: Path, n: int = 50, victim: str | None = None, now: dt.date | None = None) -> dict:
    now = now or dt.date.today()
    work = Path(tempfile.mkdtemp()) / "policy.yaml"
    shutil.copy(policy_path, work)
    report = {"steps": []}

    t0 = time.perf_counter()
    p = agile.Policy.load(work)
    victim = victim or p.usable("kem", now)[0]
    base = establish(p, p, n, now)
    report["steps"].append({"step": "baseline", "version": p.version, "choices": {f"{k[0]}+{k[1]}": v for k, v in base.items()},
                            "seconds": round(time.perf_counter() - t0, 3)})

    t0 = time.perf_counter()
    killed = p.with_kill(victim)
    work.write_text(yaml.safe_dump(killed.to_dict(), sort_keys=False))          # the change is a file write ...
    reloaded = agile.Policy.load(work); reloaded.previous = p                    # ... and a reload
    after = establish(reloaded, reloaded, n, now)
    ok_kill = all(k[0] != victim for k in after) and all(agile.providers.get(k[0]).meta.quantum_level >= reloaded.kem_floor for k in after)
    report["steps"].append({"step": f"kill {victim}", "version": reloaded.version, "choices": {f"{k[0]}+{k[1]}": v for k, v in after.items()},
                            "victim_absent": ok_kill, "seconds": round(time.perf_counter() - t0, 3)})

    t0 = time.perf_counter()
    back = reloaded.rollback()
    work.write_text(yaml.safe_dump(back.to_dict(), sort_keys=False))
    restored = agile.Policy.load(work)
    again = establish(restored, restored, n, now)
    report["steps"].append({"step": "rollback", "version": restored.version, "choices": {f"{k[0]}+{k[1]}": v for k, v in again.items()},
                            "restored": again == base and restored.digest() == p.digest(), "seconds": round(time.perf_counter() - t0, 3)})
    report["telemetry_events"] = len(agile.TELEMETRY)
    report["downgrades_flagged"] = sum(e.downgrade for e in agile.TELEMETRY)
    report["passed"] = ok_kill and report["steps"][-1]["restored"]
    return report


def main() -> int:
    r = run(HERE / "policies" / "policy-v3.yaml")
    for s in r["steps"]:
        extra = {k: v for k, v in s.items() if k not in ("step", "version", "choices", "seconds")}
        print(f"{s['step']:<16} v{s['version']}  {s['choices']}  {s['seconds']:.2f}s  {extra if extra else ''}")
    print(f"telemetry events: {r['telemetry_events']}, downgrades flagged: {r['downgrades_flagged']}, drill {'PASSED' if r['passed'] else 'FAILED'}")
    (HERE / "results").mkdir(exist_ok=True)
    (HERE / "results" / "drill.json").write_text(json.dumps(r, indent=2) + "\n")
    return 0 if r["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
