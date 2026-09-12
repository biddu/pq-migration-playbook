"""Lab 4.1 solution -- from a scored inventory to a scheduled migration backlog.

Input: backlog.yaml, a list of nodes. Cryptographic assets carry the Chapter 1
fields and are scored with the Chapter 1 scorer for a must-finish date. Enabling
work (HSM firmware, trust-store distribution, an SDK release) has no date of its
own and inherits one from whatever depends on it.

Four steps, each a classic scheduling idea applied plainly:

  1. Score.       must_finish(asset) from Chapter 1 (regulator vs physics).
  2. Cycles.      Kahn's algorithm; anything left over is in a cycle. Report it and
                  propose the edge to cut with a dual-stack or hybrid step.
  3. Backward.    deadline(v) = min(must_finish(v), min over dependents u of
                  deadline(u) - duration(u)). Latest start = deadline - duration.
                  Slack = latest start - today. Zero or negative slack = critical.
  4. Forward.     List scheduling with k parallel streams, least slack first,
                  respecting dependencies. Reports start, finish and lateness.

Tested with: Python 3.12, PyYAML 6.0. Imports the Chapter 1 scorer.
"""
from __future__ import annotations

import argparse
import csv
import sys
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "labs" / "ch01" / "solution"))
import pqscore  # noqa: E402  (Chapter 1)

DAYS = 365.25
FAR_FUTURE = date(2099, 12, 31)


@dataclass
class Node:
    name: str
    kind: str                                  # asset | enabler
    owner: str
    duration_years: float
    depends_on: list[str] = field(default_factory=list)
    asset: pqscore.Asset | None = None
    must_finish: date = FAR_FUTURE             # own constraint (assets only)
    driver: str = "-"
    deadline: date = FAR_FUTURE                # after backward pass
    latest_start: date = FAR_FUTURE
    slack_years: float = 0.0
    start: date | None = None                  # after forward pass
    finish: date | None = None
    stream: int | None = None
    note: str = ""

    @property
    def duration(self) -> timedelta:
        return timedelta(days=round(self.duration_years * DAYS))


# ------------------------------------------------------------------ load and score

def load(path: Path) -> tuple[dict, dict[str, Node]]:
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    nodes: dict[str, Node] = {}
    for n in doc["nodes"]:
        node = Node(n["name"], n["kind"], n.get("owner", "unassigned"), float(n["migration_years"]),
                    list(n.get("depends_on", [])), note=n.get("note", ""))
        if n["kind"] == "asset":
            node.asset = pqscore.Asset(n["name"], n["functions"], n["shelf_life_years"], n["migration_years"],
                                       n.get("jurisdictions", ["GLOBAL"]), n.get("sectors", ["all"]))
        nodes[node.name] = node
    for node in nodes.values():
        for d in node.depends_on:
            if d not in nodes:
                raise ValueError(f"{node.name} depends on unknown node {d!r}")
    return doc, nodes


def score(nodes: dict[str, Node], calendar: list[dict], crqc_year: int, today: date) -> None:
    for node in nodes.values():
        if node.asset is None:
            continue
        verdicts = pqscore.score(node.asset, calendar, crqc_year, today)
        worst = min(verdicts, key=lambda v: v.must_finish)
        node.must_finish, node.driver = worst.must_finish, f"{worst.function}:{worst.driver}"


# ------------------------------------------------------------------ cycles

def dependents_of(nodes: dict[str, Node]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {n: [] for n in nodes}
    for node in nodes.values():
        for d in node.depends_on:
            out[d].append(node.name)
    return out


def topological_order(nodes: dict[str, Node]) -> tuple[list[str], list[str]]:
    """Kahn's algorithm. Returns (order, names stuck in cycles)."""
    indeg = {n: len(node.depends_on) for n, node in nodes.items()}
    deps = dependents_of(nodes)
    ready = sorted(n for n, k in indeg.items() if k == 0)
    order: list[str] = []
    while ready:
        n = ready.pop(0)
        order.append(n)
        for u in deps[n]:
            indeg[u] -= 1
            if indeg[u] == 0:
                ready.append(u)
        ready.sort()
    stuck = sorted(n for n, k in indeg.items() if k > 0)
    return order, stuck


def find_cycle(nodes: dict[str, Node], stuck: list[str]) -> list[str]:
    """Walk depends_on from a stuck node until a repeat; return the cycle as a list."""
    if not stuck:
        return []
    path, seen, cur = [], {}, stuck[0]
    while cur not in seen:
        seen[cur] = len(path)
        path.append(cur)
        nxt = [d for d in nodes[cur].depends_on if d in stuck]
        if not nxt:
            return []
        cur = nxt[0]
    return path[seen[cur]:]


def propose_cut(nodes: dict[str, Node], cycle: list[str]) -> tuple[str, str]:
    """Cut the edge whose target has the latest own deadline: that side can run dual-stack longest."""
    edges = [(cycle[i], cycle[(i + 1) % len(cycle)]) for i in range(len(cycle))]
    return max(edges, key=lambda e: nodes[e[1]].must_finish)


# ------------------------------------------------------------------ backward pass

def backward_pass(nodes: dict[str, Node], order: list[str], today: date) -> None:
    deps = dependents_of(nodes)
    for name in reversed(order):                       # dependents are processed before their dependencies
        node = nodes[name]
        inherited = [nodes[u].deadline - nodes[u].duration for u in deps[name]]
        node.deadline = min([node.must_finish, *inherited])
        node.latest_start = node.deadline - node.duration
        node.slack_years = round((node.latest_start - today).days / DAYS, 2)


def critical_path(nodes: dict[str, Node], order: list[str]) -> list[str]:
    """The tightest chain: start at the least-slack node, extend backwards through the least-slack
    dependency and forwards through the least-slack dependent."""
    if not order:
        return []
    deps = dependents_of(nodes)
    start = min((nodes[n] for n in order), key=lambda x: (x.slack_years, x.name)).name
    back, cur = [], start
    while nodes[cur].depends_on:
        cur = min(nodes[cur].depends_on, key=lambda d: (nodes[d].slack_years, d))
        back.append(cur)
    fwd, cur = [], start
    while [u for u in deps[cur] if u in order]:
        cur = min((u for u in deps[cur] if u in order), key=lambda u: (nodes[u].slack_years, u))
        fwd.append(cur)
    return list(reversed(back)) + [start] + fwd


# ------------------------------------------------------------------ forward pass

def list_schedule(nodes: dict[str, Node], order: list[str], today: date, capacity: int) -> None:
    free_at = [today] * capacity
    done: set[str] = set()
    pending = set(order)
    while pending:
        ready = [n for n in pending if set(nodes[n].depends_on) <= done]
        ready.sort(key=lambda n: (nodes[n].latest_start, n))     # least slack first
        n = ready[0]
        node = nodes[n]
        k = min(range(capacity), key=lambda i: free_at[i])
        earliest = max([today, free_at[k], *[nodes[d].finish for d in node.depends_on]])  # type: ignore[list-item]
        node.start, node.finish, node.stream = earliest, earliest + node.duration, k + 1
        free_at[k] = node.finish
        done.add(n)
        pending.discard(n)


# ------------------------------------------------------------------ output

def table(nodes: dict[str, Node], order: list[str]) -> str:
    rows = sorted((nodes[n] for n in order), key=lambda x: (x.start or FAR_FUTURE, x.name))
    head = f"{'node':<24} {'kind':<7} {'owner':<19} {'deadline':<10} {'slack':>6} {'start':<10} {'finish':<10} {'late':>6} st"
    out = [head, "-" * len(head)]
    for x in rows:
        late = (x.finish - x.deadline).days / DAYS if x.finish and x.deadline != FAR_FUTURE else 0.0
        dl = x.deadline.isoformat() if x.deadline != FAR_FUTURE else "-"
        out.append(f"{x.name:<24} {x.kind:<7} {x.owner:<19} {dl:<10} {x.slack_years:>6.1f} "
                   f"{x.start.isoformat() if x.start else '-':<10} {x.finish.isoformat() if x.finish else '-':<10} "
                   f"{late:>6.1f} {x.stream or '-'}")
    return "\n".join(out)


def write_csv(nodes: dict[str, Node], order: list[str], path: Path) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["node", "kind", "owner", "depends_on", "must_finish", "driver", "deadline", "latest_start",
                    "slack_years", "start", "finish", "stream"])
        for n in order:
            x = nodes[n]
            w.writerow([x.name, x.kind, x.owner, ";".join(x.depends_on),
                        x.must_finish.isoformat() if x.must_finish != FAR_FUTURE else "",
                        x.driver, x.deadline.isoformat() if x.deadline != FAR_FUTURE else "",
                        x.latest_start.isoformat() if x.latest_start != FAR_FUTURE else "",
                        x.slack_years, x.start.isoformat() if x.start else "", x.finish.isoformat() if x.finish else "", x.stream])


def run(path: Path, calendar_path: Path, capacity: int | None = None) -> tuple[dict, dict[str, Node], list[str], list[str]]:
    doc, nodes = load(path)
    today = date.fromisoformat(str(doc["today"]))
    calendar = pqscore.load_calendar(calendar_path)
    score(nodes, calendar, int(doc["crqc_year"]), today)
    order, stuck = topological_order(nodes)
    backward_pass(nodes, order, today)
    list_schedule(nodes, order, today, capacity or int(doc.get("team_capacity", 1)))
    return doc, nodes, order, stuck


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Schedule a post-quantum migration backlog.")
    p.add_argument("backlog", nargs="?", default=str(Path(__file__).resolve().parents[1] / "backlog.yaml"))
    p.add_argument("--calendar", default=str(ROOT / "calendar" / "deadlines.yaml"))
    p.add_argument("--capacity", type=int, default=None)
    p.add_argument("--csv", default=str(Path(__file__).resolve().parents[1] / "results" / "schedule.csv"))
    args = p.parse_args(argv)

    doc, nodes, order, stuck = run(Path(args.backlog), Path(args.calendar), args.capacity)
    if stuck:
        cyc = find_cycle(nodes, stuck)
        a, b = propose_cut(nodes, cyc)
        print(f"CYCLE: {' -> '.join(cyc + [cyc[0]])}")
        print(f"  {len(stuck)} node(s) cannot be scheduled. Proposed cut: make '{a}' not wait for '{b}' "
              f"by running '{b}' dual-stack (accept both old and new) during the transition.\n")
    print(table(nodes, order))
    print("\ncritical path:", " -> ".join(critical_path(nodes, order)))
    Path(args.csv).parent.mkdir(parents=True, exist_ok=True)
    write_csv(nodes, order, Path(args.csv))
    print(f"schedule written to {args.csv}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
