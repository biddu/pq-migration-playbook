"""Acceptance tests for Lab 4.1. Run: pytest labs/ch04/tests  (PQ_LAB_IMPL=solution for the reference)."""
import importlib
import os
import sys
from datetime import date
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent.parent
ROOT = HERE.parents[1]
use_solution = os.environ.get("PQ_LAB_IMPL", "starter") == "solution"
sys.path.insert(0, str(HERE / "solution"))
if not use_solution:
    sys.path.insert(0, str(HERE))
try:
    bl = importlib.import_module("backlog" if use_solution else "starter_backlog")
except ModuleNotFoundError:
    bl = importlib.import_module("backlog")

CAL = ROOT / "calendar" / "deadlines.yaml"


@pytest.fixture(scope="module")
def result():
    return bl.run(HERE / "backlog.yaml", CAL, capacity=2)


def test_loads_twelve_nodes_and_scores_assets(result):
    doc, nodes, order, stuck = result
    assert len(nodes) == 12
    assert nodes["archive-backups"].must_finish == date(2016, 12, 31)      # physics, Chapter 1
    assert nodes["firmware-signing-pos"].must_finish == date(2027, 1, 1)   # CNSA 2.0 acquisition gate
    assert nodes["hsm-firmware-upgrade"].must_finish == bl.FAR_FUTURE      # enablers have no own date


def test_cycle_detected_and_everything_else_ordered(result):
    doc, nodes, order, stuck = result
    assert set(stuck) == {"acquirer-gateway-mtls", "partner-gateway-mtls"}
    assert len(order) == 10
    assert order.index("hsm-firmware-upgrade") < order.index("payment-hsm-keywrap") < order.index("archive-backups")
    cyc = bl.find_cycle(nodes, stuck)
    assert set(cyc) == set(stuck)
    a, b = bl.propose_cut(nodes, cyc)
    assert {a, b} == set(stuck)


def test_backward_pass_inherits_deadlines(result):
    doc, nodes, order, stuck = result
    hsm, kw, arc = nodes["hsm-firmware-upgrade"], nodes["payment-hsm-keywrap"], nodes["archive-backups"]
    assert kw.deadline == arc.deadline - arc.duration            # keywrap must finish before the archive starts
    assert hsm.deadline == min(kw.deadline - kw.duration, nodes["internal-ca-mldsa"].deadline - nodes["internal-ca-mldsa"].duration,
                               nodes["firmware-signing-pos"].deadline - nodes["firmware-signing-pos"].duration)
    assert hsm.slack_years < 0 and nodes["service-mesh-mtls"].slack_years > 0


def test_critical_path_is_the_archive_chain(result):
    doc, nodes, order, stuck = result
    assert bl.critical_path(nodes, order) == ["hsm-firmware-upgrade", "payment-hsm-keywrap", "archive-backups"]


def test_schedule_respects_dependencies_and_capacity(result):
    doc, nodes, order, stuck = result
    for n in order:
        x = nodes[n]
        assert x.start is not None and x.finish == x.start + x.duration
        for d in x.depends_on:
            assert nodes[d].finish <= x.start
    # no more than 2 nodes in flight at any start date
    for n in order:
        t = nodes[n].start
        in_flight = sum(1 for m in order if nodes[m].start <= t < nodes[m].finish)
        assert in_flight <= 2


def test_more_capacity_finishes_sooner():
    _, n2, o2, _ = bl.run(HERE / "backlog.yaml", CAL, capacity=2)
    _, n4, o4, _ = bl.run(HERE / "backlog.yaml", CAL, capacity=4)
    assert max(n4[n].finish for n in o4) < max(n2[n].finish for n in o2)
    assert n4["customer-api-tls"].finish <= n4["customer-api-tls"].deadline   # on time with four streams
