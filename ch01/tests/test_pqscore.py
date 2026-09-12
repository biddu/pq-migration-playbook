"""Acceptance tests for Lab 1.1. Run:  pytest labs/ch01/tests
They import from the reader's own file (starter.py) if it exists and is complete,
otherwise from the solution. Set PQ_LAB_IMPL=solution to force the solution."""
import importlib
import os
import sys
from datetime import date
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent.parent
ROOT = HERE.parents[1]
impl_dir = HERE / ("solution" if os.environ.get("PQ_LAB_IMPL", "starter") == "solution" else ".")
sys.path.insert(0, str(impl_dir))
try:
    pq = importlib.import_module("pqscore" if impl_dir.name == "solution" else "starter")
except ModuleNotFoundError:
    sys.path.insert(0, str(HERE / "solution"))
    pq = importlib.import_module("pqscore")

TODAY = date(2026, 10, 1)


@pytest.fixture(scope="module")
def CAL():
    return pq.load_calendar(ROOT / "calendar" / "deadlines.yaml")


def asset(**kw):
    base = dict(name="a", functions=["confidentiality"], shelf_life_years=1,
                migration_years=1, jurisdictions=["EU"], sectors=["all"])
    base.update(kw)
    return pq.Asset(**base)


def test_calendar_loads_with_dates(CAL):
    assert len(CAL) >= 15
    assert all(isinstance(i["date"], date) for i in CAL)


def test_mosca_margin_sign():
    assert pq.mosca_margin(x=25, y=6, z=2032 - 2026) < 0     # health records: already late
    assert pq.mosca_margin(x=0.1, y=1, z=6) > 0               # payment tokens: fine


def test_exposure_date_moves_back_by_shelf_life():
    assert pq.exposure_date(2, 2032) == date(2030, 1, 1)
    assert pq.exposure_date(15, 2032) == date(2016, 12, 31)


def test_binding_picks_earliest_applicable(CAL):
    nss = asset(functions=["signing"], jurisdictions=["US"], sectors=["nss"])
    assert pq.binding(nss, CAL, "signing")["id"] == "cnsa2-procurement"
    eu_bank = asset(jurisdictions=["EU"], sectors=["finance"])
    assert pq.binding(eu_bank, CAL, "confidentiality")["id"] in {"eu-roadmap-highrisk", "nist-ir8547-deprecate"}
    assert pq.binding(eu_bank, CAL, "confidentiality")["date"] == date(2030, 12, 31)


def test_global_instruments_apply_everywhere(CAL):
    anywhere = asset(jurisdictions=["XX"], sectors=["nothing"])
    assert pq.binding(anywhere, CAL, "confidentiality")["id"] == "nist-ir8547-deprecate"


def test_physics_beats_regulator_for_long_lived_data(CAL):
    archive = asset(shelf_life_years=15, migration_years=3, sectors=["finance"])
    (v,) = pq.score(archive, CAL, crqc_year=2032, today=TODAY)
    assert v.driver == "physics"
    assert v.must_finish == date(2016, 12, 31)
    assert v.priority.startswith("P0")


def test_regulator_binds_short_lived_data(CAL):
    api = asset(shelf_life_years=0.5, migration_years=1, jurisdictions=["US"], sectors=["federal-contractor"])
    (v,) = pq.score(api, CAL, crqc_year=2040, today=TODAY)
    assert v.driver == "us-eo-2026-contractors"
    assert v.must_finish == date(2030, 12, 31)


def test_priority_bands():
    assert pq.priority_band(-0.1).startswith("P0")
    assert pq.priority_band(0.5).startswith("P1")
    assert pq.priority_band(2.0).startswith("P2")
    assert pq.priority_band(3.0).startswith("P3")


def test_unknown_function_rejected(CAL):
    with pytest.raises(ValueError):
        pq.score(asset(functions=["integrity"]), CAL, 2032, TODAY)
