"""Every contract: obj -> canonical bytes -> obj identity; byte-stable across processes; hash-stable."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from ks.contracts import canonical, tagged_hash, value_hash, TOMBSTONE_HASH

from samples import samples

ALL = samples()
ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("name", sorted(ALL))
def test_roundtrip_identity(name):
    obj = ALL[name]
    b = obj.to_canonical()
    back = type(obj).from_canonical(b)
    assert back == obj
    assert back.to_canonical() == b
    assert canonical.dumps(canonical.loads(b)) == b


@pytest.mark.parametrize("name", sorted(ALL))
def test_rebuild_is_byte_equal(name):
    assert samples()[name].to_canonical() == ALL[name].to_canonical()


def _run(seed: str) -> str:
    env = {**os.environ, "PYTHONHASHSEED": seed,
           "PYTHONPATH": os.pathsep.join([str(ROOT / "src"), str(ROOT / "tests" / "contracts")])}
    return subprocess.run([sys.executable, str(ROOT / "tests/contracts/samples.py")], env=env, check=True,
                          capture_output=True, text=True).stdout


def test_bytes_stable_across_two_runs():
    a, b = _run("1"), _run("12345")
    assert a == b
    here = "".join(f"{n} {o.to_canonical().hex()}\n" for n, o in sorted(ALL.items()))
    assert a == here


@pytest.mark.parametrize("name", sorted(ALL))
def test_from_canonical_rejects_non_canonical(name):
    b = ALL[name].to_canonical()
    with pytest.raises(ValueError):
        type(ALL[name]).from_canonical(b + b" ")
    obj = canonical.loads(b)
    obj.pop(sorted(obj)[0])  # drop a field: must not be silently defaulted
    with pytest.raises(ValueError):
        type(ALL[name]).from_canonical(canonical.dumps(obj))


# Golden vectors: freeze the format. If one of these changes, CONTRACTS_VERSION must change too.
GOLDEN = {
    "value_hash({})": lambda: value_hash({}),
    "tombstone": lambda: TOMBSTONE_HASH,
    "tagged": lambda: tagged_hash(b"ks/test/v1", {"b": [1, "é"], "a": None}),
}


def test_hash_stability_golden(golden):
    for name, fn in GOLDEN.items():
        assert fn() == golden[name], name


@pytest.mark.parametrize("name", sorted(ALL))
def test_document_hash_stable(name, golden):
    obj = ALL[name]
    if hasattr(obj, "content_hash"):
        assert obj.content_hash() == golden["doc:" + name]
