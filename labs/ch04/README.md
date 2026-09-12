# Lab 4.1 — The migration backlog as a scheduled graph

Takes `backlog.yaml` (cryptographic assets with Chapter 1 fields, plus enabling
work such as HSM firmware and trust-store distribution, with `depends_on` edges),
scores every asset with the Chapter 1 scorer, detects dependency cycles and
proposes where to cut them, back-propagates deadlines through the graph, finds
the critical path, and list-schedules the work onto `team_capacity` streams.

| File | What it is |
|---|---|
| `backlog.yaml` | The payments company's backlog: 12 nodes, one deliberate cycle. |
| `starter_backlog.py` | Your file. |
| `solution/backlog.py` | Reference solution. Imports `labs/ch01/solution/pqscore.py`. |
| `tests/test_ch04.py` | Acceptance tests. |
| `results/schedule.csv` | Output of the reference run (capacity 2). |
| `../../templates/vendor_questionnaire.md` | The vendor PQC questionnaire from Section 4.3. |

```bash
pip install pyyaml pytest
pytest labs/ch04/tests
PQ_LAB_IMPL=solution pytest labs/ch04/tests
python labs/ch04/solution/backlog.py                # capacity from the file (2)
python labs/ch04/solution/backlog.py --capacity 4   # what a bigger team buys
```

Tested with: Python 3.12, PyYAML 6.0, pytest 9.
