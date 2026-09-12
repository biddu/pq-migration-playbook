"""Lab 3.1 starter -- repository scanner emitting a CycloneDX 1.6 CBOM.

Fill in every TODO. The data model (Occurrence, Asset, Inventory) and the CBOM
writer are given; your work is the discovery: matching files to rules, applying
rules, parsing certificates, and walking the tree. Run:
    pytest labs/ch03/tests
Reference solution: solution/cbomscan.py (read it after you have tried)."""
from __future__ import annotations

import fnmatch
import re
from pathlib import Path

import yaml
from cryptography import x509

# Reuse the data model and the writer from the solution so that your output is comparable.
from solution.cbomscan import (Asset, Inventory, Occurrence, SKIP_DIRS, algorithm_from_rule,  # noqa: F401
                               build_cbom, group_asset, kex_asset, public_key_asset, CERT_SIG_OIDS)


def load_rules(path: Path) -> dict:
    """Read rules.yaml."""
    raise NotImplementedError  # TODO


def file_class_of(path: Path, classes: dict[str, list[str]]) -> str | None:
    """Return the file class whose globs match this path (by name or by relative path), else None."""
    raise NotImplementedError  # TODO


def fill(template, groups: tuple) -> str:
    """Replace {1}, {2}, ... in template with the regex capture groups."""
    raise NotImplementedError  # TODO


def scan_text_file(path: Path, rel: str, cls: str, rules: list[dict], inv: Inventory) -> None:
    """Apply every rule of this file class. For each match record an Occurrence (location, line, symbol)
    and add the asset / protocol / group list / kex list / cipher list / library the rule describes."""
    raise NotImplementedError  # TODO


def scan_certificate(path: Path, rel: str, inv: Inventory) -> None:
    """Parse PEM or DER certificates; add the signature algorithm, the public-key algorithm,
    and a certificate asset whose certificateProperties reference both."""
    raise NotImplementedError  # TODO


def scan_tree(root: Path, rules_doc: dict, inv: Inventory) -> int:
    """Walk root (skipping SKIP_DIRS), route certificates and classified files, return files seen."""
    raise NotImplementedError  # TODO
