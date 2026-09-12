"""Lab 4.1 starter -- from a scored inventory to a scheduled migration backlog.
Fill in every TODO; run  pytest labs/ch04/tests.  Reference: solution/backlog.py."""
from __future__ import annotations

import sys
from datetime import date, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "labs" / "ch01" / "solution"))
sys.path.insert(0, str(Path(__file__).resolve().parent / "solution"))
import pqscore  # noqa: E402
from backlog import FAR_FUTURE, DAYS, Node, load, score, dependents_of, write_csv, table  # noqa: E402,F401


def topological_order(nodes: dict[str, Node]) -> tuple[list[str], list[str]]:
    """Kahn's algorithm. Return (order, names left with unresolved dependencies = in cycles)."""
    raise NotImplementedError  # TODO


def find_cycle(nodes: dict[str, Node], stuck: list[str]) -> list[str]:
    """Follow depends_on among stuck nodes from stuck[0] until a repeat; return the cycle."""
    raise NotImplementedError  # TODO


def propose_cut(nodes: dict[str, Node], cycle: list[str]) -> tuple[str, str]:
    """Return the (from, to) edge to cut: the one whose target has the latest own must_finish."""
    raise NotImplementedError  # TODO


def backward_pass(nodes: dict[str, Node], order: list[str], today: date) -> None:
    """deadline(v) = min(must_finish(v), min over dependents u of deadline(u) - duration(u));
    latest_start = deadline - duration; slack_years = (latest_start - today) in years."""
    raise NotImplementedError  # TODO


def critical_path(nodes: dict[str, Node], order: list[str]) -> list[str]:
    """Least-slack node, extended backwards and forwards through least-slack neighbours."""
    raise NotImplementedError  # TODO


def list_schedule(nodes: dict[str, Node], order: list[str], today: date, capacity: int) -> None:
    """Least-slack-first list scheduling on `capacity` streams; set start, finish, stream on each node."""
    raise NotImplementedError  # TODO


def run(path: Path, calendar_path: Path, capacity: int | None = None):
    import yaml
    doc, nodes = load(path)
    today = date.fromisoformat(str(doc["today"]))
    calendar = pqscore.load_calendar(calendar_path)
    score(nodes, calendar, int(doc["crqc_year"]), today)
    order, stuck = topological_order(nodes)
    backward_pass(nodes, order, today)
    list_schedule(nodes, order, today, capacity or int(doc.get("team_capacity", 1)))
    return doc, nodes, order, stuck
