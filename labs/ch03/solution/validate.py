"""Validate a CBOM against the CycloneDX 1.6 JSON schema shipped in labs/ch03/schema/."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from jsonschema import Draft7Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7

SCHEMA_DIR = Path(__file__).resolve().parents[1] / "schema"


def validator() -> Draft7Validator:
    main = json.loads((SCHEMA_DIR / "bom-1.6.schema.json").read_text())
    registry = Registry()
    for name in ("spdx.schema.json", "jsf-0.82.schema.json"):
        doc = json.loads((SCHEMA_DIR / name).read_text())
        registry = registry.with_resource(name, Resource.from_contents(doc, default_specification=DRAFT7))
    return Draft7Validator(main, registry=registry)


def validate(cbom: dict) -> list[str]:
    return [f"{'/'.join(map(str, e.absolute_path))}: {e.message}" for e in validator().iter_errors(cbom)]


if __name__ == "__main__":
    errors = validate(json.loads(Path(sys.argv[1]).read_text()))
    print("valid CycloneDX 1.6" if not errors else "\n".join(errors[:20]))
    sys.exit(1 if errors else 0)
