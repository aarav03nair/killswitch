"""Generate the JSON Schema files in ``schema/`` from the models (``python -m ks.contracts.schema_gen``).

Post-processing: draft 2020-12, ``$id``, and every property is ``required`` (canonical output always
contains every field, nulls included) except v1.4 ``additive`` fields, omitted at their default. tests/contracts/test_schema.py fails if the files drift.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

SCHEMA_DIR = Path(__file__).with_name("schema")


def _require_all(node: Any) -> None:
    if isinstance(node, dict):
        if node.get("type") == "object" and "properties" in node:
            from ._base import OMIT_DEFAULT_KEY
            props = node["properties"]
            node["required"] = sorted(k for k, v in props.items()
                                      if not (isinstance(v, dict) and v.pop(OMIT_DEFAULT_KEY, False)))
        for v in node.values():
            _require_all(v)
    elif isinstance(node, list):
        for v in node:
            _require_all(v)


def generate() -> dict[str, dict[str, Any]]:
    from . import CONTRACTS_VERSION, DOCUMENTS

    out: dict[str, dict[str, Any]] = {}
    for name, typ in DOCUMENTS.items():
        s = typ.model_json_schema(mode="validation")
        _require_all(s)
        s = {"$schema": "https://json-schema.org/draft/2020-12/schema",
             "$id": f"https://killswitch.local/schema/{CONTRACTS_VERSION}/{name}.schema.json", **s}
        out[name] = s
    return out


def render(schema: dict[str, Any]) -> str:
    """Pretty JSON for humans. Schema files are documentation, never hashed or signed."""
    return json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def write(directory: Path = SCHEMA_DIR) -> list[Path]:
    directory.mkdir(exist_ok=True)
    paths = []
    for name, s in generate().items():
        p = directory / f"{name}.schema.json"
        p.write_text(render(s), encoding="utf-8")
        paths.append(p)
    return paths


if __name__ == "__main__":
    for p in write():
        print(p)
