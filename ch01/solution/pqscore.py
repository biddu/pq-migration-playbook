"""Lab 1.1 solution -- a migration priority scorer built on the regulatory calendar.

Given an asset (what it protects, how long that must stay secret, how long it
will take to migrate, and whose rules it falls under) and the calendar in
deadlines.yaml, the scorer answers three questions:

  1. Which instrument binds this asset, and on what date?
  2. By when must the migration actually finish, once Mosca's inequality is
     applied to the data's shelf life?
  3. How much slack is left after the estimated migration time, and therefore
     what priority band does the asset fall into?

Tested with: Python 3.12, PyYAML 6.0.
"""
from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path

import yaml

DAYS_PER_YEAR = 365.25
BINDING_KINDS = {"procurement", "deadline", "deprecation", "disallow"}
FUNCTIONS = ("confidentiality", "authentication", "signing")


@dataclass
class Asset:
    name: str
    functions: list[str]
    shelf_life_years: float          # x: how long the protected data must stay secret
    migration_years: float           # y: how long the migration will take
    jurisdictions: list[str] = field(default_factory=lambda: ["GLOBAL"])
    sectors: list[str] = field(default_factory=lambda: ["all"])


@dataclass
class Verdict:
    asset: str
    function: str
    instrument: str | None
    regulatory_date: date | None
    physics_date: date | None
    must_finish: date
    driver: str                      # what set must_finish: the instrument id, or 'physics'
    remaining_years: float
    slack_years: float
    priority: str


# ---------------------------------------------------------------- calendar

def load_calendar(path: str | Path) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    instruments = data["instruments"]
    for inst in instruments:                       # YAML gives dates as date objects
        if not isinstance(inst["date"], date):
            inst["date"] = date.fromisoformat(str(inst["date"]))
    return instruments


def applies(inst: dict, asset: Asset) -> bool:
    in_jurisdiction = inst["jurisdiction"] == "GLOBAL" or inst["jurisdiction"] in asset.jurisdictions
    in_sector = "all" in inst["sectors"] or bool(set(inst["sectors"]) & set(asset.sectors))
    return in_jurisdiction and in_sector


def binding(asset: Asset, calendar: list[dict], function: str) -> dict | None:
    """The earliest dated obligation that constrains this function for this asset."""
    candidates = [
        inst for inst in calendar
        if inst["function"] == function and inst["kind"] in BINDING_KINDS and applies(inst, asset)
    ]
    return min(candidates, key=lambda i: i["date"]) if candidates else None


# ---------------------------------------------------------------- Mosca

def mosca_margin(x: float, y: float, z: float) -> float:
    """Mosca's inequality as a number: positive means you finish before the data is exposed."""
    return z - (x + y)


def exposure_date(shelf_life_years: float, crqc_year: int) -> date:
    """Data encrypted after this date is still sensitive when the CRQC arrives."""
    days = int(round(shelf_life_years * DAYS_PER_YEAR))
    return date(crqc_year, 1, 1) - timedelta(days=days)


# ---------------------------------------------------------------- scoring

def priority_band(slack_years: float) -> str:
    if slack_years < 0:
        return "P0 late"
    if slack_years < 1:
        return "P1 now"
    if slack_years < 3:
        return "P2 plan"
    return "P3 schedule"


def score(asset: Asset, calendar: list[dict], crqc_year: int, today: date) -> list[Verdict]:
    verdicts = []
    for fn in asset.functions:
        if fn not in FUNCTIONS:
            raise ValueError(f"unknown function {fn!r}; expected one of {FUNCTIONS}")
        inst = binding(asset, calendar, fn)
        regulatory = inst["date"] if inst else None

        # Physics: confidentiality is exposed shelf-life years before the CRQC;
        # authentication and signing only once the CRQC exists.
        if fn == "confidentiality":
            physics = exposure_date(asset.shelf_life_years, crqc_year)
        else:
            physics = date(crqc_year, 1, 1)

        must_finish = min(d for d in (regulatory, physics) if d is not None)
        driver = inst["id"] if (regulatory is not None and regulatory <= physics) else "physics"
        remaining = (must_finish - today).days / DAYS_PER_YEAR
        slack = remaining - asset.migration_years
        verdicts.append(Verdict(
            asset=asset.name, function=fn,
            instrument=inst["id"] if inst else None,
            regulatory_date=regulatory, physics_date=physics,
            must_finish=must_finish, driver=driver, remaining_years=round(remaining, 2),
            slack_years=round(slack, 2), priority=priority_band(slack),
        ))
    return verdicts


# ---------------------------------------------------------------- CLI

def load_assets(path: str | Path) -> list[Asset]:
    with open(path, encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)
    return [Asset(**a) for a in raw["assets"]]


def format_table(verdicts: list[Verdict]) -> str:
    """Fixed-width table with columns sized to the content, narrowest first."""
    rows = [(v.asset, v.function, v.driver, v.must_finish.isoformat(), f"{v.slack_years:.1f}", v.priority)
            for v in sorted(verdicts, key=lambda v: v.slack_years)]
    head = ("asset", "function", "driver", "finish by", "slack", "priority")
    widths = [max(len(r[k]) for r in [head, *rows]) for k in range(6)]
    def line(r):
        return (f"{r[0]:<{widths[0]}} {r[1]:<{widths[1]}} {r[2]:<{widths[2]}} "
                f"{r[3]:<{widths[3]}} {r[4]:>{widths[4]}}  {r[5]}")
    return "\n".join([line(head), "-" * len(line(head)), *map(line, rows)])


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Score assets against the PQC regulatory calendar.")
    p.add_argument("assets", help="YAML file with an 'assets' list")
    p.add_argument("--calendar", default=str(Path(__file__).resolve().parents[3] / "calendar" / "deadlines.yaml"))
    p.add_argument("--crqc", type=int, default=2032, help="assumed year a CRQC exists (planning value)")
    p.add_argument("--today", default=date.today().isoformat())
    args = p.parse_args(argv)

    calendar = load_calendar(args.calendar)
    today = date.fromisoformat(args.today)
    verdicts = [v for a in load_assets(args.assets) for v in score(a, calendar, args.crqc, today)]
    print(format_table(verdicts))
    return 0


if __name__ == "__main__":
    sys.exit(main())
