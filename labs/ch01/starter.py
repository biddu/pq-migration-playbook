"""Lab 1.1 starter -- a migration priority scorer built on the regulatory calendar.

Fill in every function marked TODO. Run the acceptance tests with

    pytest labs/ch01/tests

You are done when they pass. The specification is in Chapter 1, Lab 1.1;
the full solution is in solution/pqscore.py (read it after you have tried).
"""
from __future__ import annotations

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
    shelf_life_years: float          # x
    migration_years: float           # y
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
    driver: str
    remaining_years: float
    slack_years: float
    priority: str


def load_calendar(path: str | Path) -> list[dict]:
    """Read deadlines.yaml and return the list of instruments, dates as date objects."""
    raise NotImplementedError  # TODO


def applies(inst: dict, asset: Asset) -> bool:
    """True if the instrument's jurisdiction and sectors cover this asset.
    GLOBAL covers every jurisdiction; the sector 'all' covers every sector."""
    raise NotImplementedError  # TODO


def binding(asset: Asset, calendar: list[dict], function: str) -> dict | None:
    """The earliest dated obligation of kind in BINDING_KINDS for this function and asset."""
    raise NotImplementedError  # TODO


def mosca_margin(x: float, y: float, z: float) -> float:
    """z - (x + y). Positive means the migration finishes before the data is exposed."""
    raise NotImplementedError  # TODO


def exposure_date(shelf_life_years: float, crqc_year: int) -> date:
    """1 January of crqc_year, moved back by the shelf life (use DAYS_PER_YEAR, round to days)."""
    raise NotImplementedError  # TODO


def priority_band(slack_years: float) -> str:
    """'P0 late' below 0, 'P1 now' below 1, 'P2 plan' below 3, else 'P3 schedule'."""
    raise NotImplementedError  # TODO


def score(asset: Asset, calendar: list[dict], crqc_year: int, today: date) -> list[Verdict]:
    """One Verdict per function. Confidentiality is exposed shelf-life years before the
    CRQC; authentication and signing only when the CRQC exists. must_finish is the
    earlier of the regulatory date and the physics date; driver names which one won."""
    raise NotImplementedError  # TODO
