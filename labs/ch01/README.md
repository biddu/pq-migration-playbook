# Lab 1.1 — The regulatory calendar as a priority scorer

**Chapter 1, Lab 1.1.** Encode the post-quantum regulatory calendar as data and
write a scorer that tells you, for each asset, which deadline binds it, when the
migration must actually finish once the data's shelf life is taken into account,
and how much slack you have left.

## Files

| File | What it is |
|---|---|
| `../../calendar/deadlines.yaml` | The calendar. One entry per dated obligation. |
| `starter.py` | Your file. Every `TODO` is a function to write. |
| `assets_example.yaml` | Five assets from a fictional Irish payments company. |
| `tests/test_pqscore.py` | Acceptance tests. You are done when they pass. |
| `solution/pqscore.py` | Reference solution, with a command-line interface. |

## Run

```bash
pip install pyyaml pytest
pytest labs/ch01/tests                       # tests your starter.py
PQ_LAB_IMPL=solution pytest labs/ch01/tests  # tests the reference solution
python labs/ch01/solution/pqscore.py labs/ch01/assets_example.yaml --today 2026-10-01 --crqc 2032
```

## Acceptance criteria

1. `load_calendar` returns at least 15 instruments, every `date` a `datetime.date`.
2. `binding` returns the earliest applicable instrument; GLOBAL instruments apply to every asset.
3. `exposure_date(2, 2032)` is 2030-01-01; `exposure_date(15, 2032)` is 2016-12-31.
4. For a 15-year archive under a 2032 CRQC assumption, the physics date wins and the priority is P0.
5. For a six-month-shelf-life API under a 2040 assumption, the regulator wins (`us-eo-2026-contractors`).

Tested with: Python 3.12, PyYAML 6.0, pytest 9.
