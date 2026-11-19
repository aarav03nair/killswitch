"""Acceptance: one canonical serializer. No ad-hoc JSON encoding anywhere else in src/ks."""

import re
from pathlib import Path

import ks.contracts as C

SRC = Path(C.__file__).resolve().parents[1]
ALLOWED = {"contracts/canonical.py", "contracts/schema_gen.py"}  # schema_gen: human-readable docs, never hashed
PATTERN = re.compile(r"\bjson\.dumps?\(|\bjson\.JSONEncoder\b|\bmodel_dump_json\(|\borjson\b|\bujson\b")


def test_no_adhoc_json_encoding():
    offenders = [str(p.relative_to(SRC)) for p in SRC.rglob("*.py")
                 if str(p.relative_to(SRC)) not in ALLOWED and PATTERN.search(p.read_text(encoding="utf-8"))]
    assert offenders == []


def test_only_one_serializer_exported():
    exported = [n for n in C.__all__ if re.search(r"dump|serial|encode|to_json", n, re.I)]
    assert exported == ["encode_frame"]  # frames delegate to canonical.dumps_line
    assert C.canonical.dumps is C.canonical.__dict__["dumps"]
