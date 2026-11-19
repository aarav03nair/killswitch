"""JSON Schema files: frozen (match the models) and every sample validates."""

import json
from functools import cache

import jsonschema
import pytest

from ks.contracts import DOCUMENTS, canonical
from ks.contracts.schema_gen import SCHEMA_DIR, generate, render

from samples import SCHEMA_OF, samples


@cache
def load_schema(name: str) -> dict:
    return json.loads((SCHEMA_DIR / f"{name}.schema.json").read_text(encoding="utf-8"))


def test_one_schema_file_per_document_and_per_contract():
    files = {p.name.removesuffix(".schema.json") for p in SCHEMA_DIR.glob("*.schema.json")}
    assert files == set(DOCUMENTS)
    assert {n.split(".")[0] for n in files} == {"c1", "c2", "c3", "c4", "c5", "c6"}


@pytest.mark.parametrize("name", sorted(DOCUMENTS))
def test_schema_files_frozen(name):
    """If this fails: run `python -m ks.contracts.schema_gen`, and bump CONTRACTS_VERSION if fields changed."""
    assert (SCHEMA_DIR / f"{name}.schema.json").read_text(encoding="utf-8") == render(generate()[name])


@pytest.mark.parametrize("name", sorted(DOCUMENTS))
def test_schema_is_valid_2020_12(name):
    jsonschema.Draft202012Validator.check_schema(load_schema(name))


@pytest.mark.parametrize("sample", sorted(SCHEMA_OF))
def test_samples_validate(sample):
    obj = samples()[sample]
    jsonschema.Draft202012Validator(load_schema(SCHEMA_OF[sample])).validate(canonical.loads(obj.to_canonical()))


def test_schema_rejects_missing_and_extra_fields():
    rec = canonical.loads(samples()["record_exec"].to_canonical())
    v = jsonschema.Draft202012Validator(load_schema("c2.record"))
    assert not v.is_valid({**rec, "extra": 1})
    r2 = dict(rec)
    r2.pop("prev_hash")
    assert not v.is_valid(r2)
