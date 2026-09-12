# Labs 2.1 and 2.2 — Sizes, speeds, and the hybrid KEM

**Lab 2.1** measures byte sizes and median operation times for the classical
algorithms being replaced and the post-quantum algorithms replacing them, and
writes `results/table.md`. **Lab 2.2** builds the X25519 + ML-KEM-768 hybrid
KEM that TLS 1.3 uses, so the key-share sizes and the combiner are visible.

| File | What it is |
|---|---|
| `starter_sizes.py`, `starter_hybrid.py` | Your files. Every `TODO` is a function to write. |
| `tests/test_ch02.py` | Acceptance tests. You are done when they pass. |
| `solution/sizes.py`, `solution/hybrid.py` | Reference solutions. |
| `results/table.md` | The table measured on the reference machine (regenerate with `python solution/sizes.py`). |

```bash
pip install "cryptography>=48" pytest
pip install liboqs-python          # optional: adds ML-KEM-512, SLH-DSA, FN-DSA (draft), HQC; builds liboqs on first import
pytest labs/ch02/tests                       # tests your starters
PQ_LAB_IMPL=solution pytest labs/ch02/tests  # tests the reference solutions
python labs/ch02/solution/sizes.py
python labs/ch02/solution/hybrid.py
```

Note: `cryptography` deliberately does not expose ML-KEM-512; the lab takes it from liboqs.

Tested with: Python 3.12, cryptography 50.0, liboqs 0.16, pytest 9.
