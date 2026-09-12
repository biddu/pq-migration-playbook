"""Lab 7.3 (part 2) -- the renewal arithmetic behind the 47-day lifetime.

Given a fleet size and the CA/Browser Forum SC-081v3 schedule, compute the renewals per
day the fleet generates at each stage, the renewal point and the repair window that a
"renew at two-thirds of lifetime" policy leaves, and the CA capacity the measured ACME
issuance time from acmeclient.py implies. The numbers are the case for automation: the
point at which a person can no longer be in the loop is a date you can compute.

Tested with: Python 3.12.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]

# SC-081v3 (CA/Browser Forum, passed 11 April 2025): maximum certificate validity by issuance date
SCHEDULE = [
    (date(2025, 1, 1), 398, 398),        # (from, max validity days, max domain-validation reuse days)
    (date(2026, 3, 15), 200, 200),
    (date(2027, 3, 15), 100, 100),
    (date(2029, 3, 15), 47, 10),
]


def stage_for(d: date) -> tuple[int, int]:
    v, r = SCHEDULE[0][1], SCHEDULE[0][2]
    for start, val, reuse in SCHEDULE:
        if d >= start:
            v, r = val, reuse
    return v, r


def renewal_point(validity_days: int, fraction: float = 2 / 3) -> tuple[int, int]:
    """Day of lifetime at which to renew, and the days left to repair a failed renewal."""
    at = int(validity_days * fraction)
    return at, validity_days - at


def fleet_table(certs: int, issue_ms: float | None) -> str:
    head = f"{'from':<12} {'max life':>8} {'renew at':>8} {'repair':>7} {'renewals/yr':>11} {'per day':>8} {'CA busy/day':>12} {'DV reuse':>8}"
    out = [head, "-" * len(head)]
    for start, val, reuse in SCHEDULE:
        at, repair = renewal_point(val)
        per_year = certs * 365 / at
        per_day = per_year / 365
        busy = f"{per_day * issue_ms / 1000:.1f} s" if issue_ms else "-"
        out.append(f"{start.isoformat():<12} {val:>8} {at:>8} {repair:>7} {per_year:>11.0f} {per_day:>8.1f} {busy:>12} {reuse:>8}")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Renewal load under the SC-081v3 lifetime schedule.")
    p.add_argument("--certs", type=int, default=1200, help="number of public TLS certificates in the estate")
    p.add_argument("--acme-json", default=str(HERE / "results" / "acme_p256.json"), help="acmeclient.py output for the measured issuance time")
    p.add_argument("--today", default=None, help="YYYY-MM-DD (default: today)")
    a = p.parse_args(argv)
    today = date.fromisoformat(a.today) if a.today else date.today()
    issue_ms = None
    pth = Path(a.acme_json)
    if pth.exists():
        rows = [r for r in json.loads(pth.read_text()) if "ms" in r]
        if rows:
            issue_ms = sum(r["ms"] for r in rows) / len(rows)
    val, reuse = stage_for(today)
    at, repair = renewal_point(val)
    print(f"today {today}: certificates issued now may live {val} days; renew on day {at}, leaving {repair} days to repair a failure; "
          f"domain validation reusable for {reuse} days")
    if issue_ms:
        print(f"measured ACME issuance (Pebble, http-01, P-256 CSR): {issue_ms:.0f} ms per certificate")
    print(f"\nfleet of {a.certs} certificates, renewing at two-thirds of lifetime:\n")
    print(fleet_table(a.certs, issue_ms))
    last_per_day = a.certs * 365 / renewal_point(SCHEDULE[-1][1])[0] / 365
    print(f"\nAt ten minutes of human attention per renewal, the last row is {last_per_day * 10 / 60:.1f} hours of work every day, "
          f"weekends included.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
