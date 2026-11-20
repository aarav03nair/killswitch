"""RT7 log line edit (F6) on a real F2+ world run: the attacker holds no keys and edits ``record.jsonl`` or the side
store to make the culprit look innocent.

THREAT-MODEL claim defended: the record is "tamper-evident up to the last witnessed head": any edit, deletion,
garbling or truncation makes ``ks verify --head`` fail with the first bad seq, and recovery refuses a dead dir
(FROZEN). Variant f pins the redaction boundary: redacting a side-store value passes verify, by design.
"""

from __future__ import annotations

import json
import shutil

import pytest

from ks.contracts import Exit, Record, RunDir, SideEntry

from .conftest import ks, verify, world_run

IBAN = "suppliers:S-17.iban"


@pytest.fixture(scope="module")
def clean(base):
    return world_run(base, "rt7", fault="F2+", seed=2, ticks=30)


@pytest.fixture
def copy(clean, tmp_path):
    def make(name):
        d = tmp_path.parent / f"{tmp_path.name}-{name}"
        shutil.copytree(clean.dir, d, ignore=shutil.ignore_patterns("operator"))
        return d
    return make


def _k(run) -> Record:
    return next(r for r in RunDir(run).records() if any(w.obj == IBAN for w in r.write_set) and r.attributed_agent == "crm")


def _lines(run):
    return (run / "record.jsonl").read_bytes().splitlines(keepends=True)


def _put(run, lines):
    (run / "record.jsonl").write_bytes(b"".join(lines))


def test_rt7_clean_verifies(clean):
    code, rep = verify(clean.dir, clean.anchor)
    assert code == Exit.OK and rep["anchored"] is True


def test_rt7a_change_the_iban_hash(clean, copy):
    run = copy("a")
    k = _k(run)
    h = next(w.after.hash for w in k.write_set if w.obj == IBAN).encode()
    lines = _lines(run)
    assert lines[k.seq - 1].count(h) == 1
    lines[k.seq - 1] = lines[k.seq - 1].replace(h, b"0" * 64)
    _put(run, lines)
    code, rep = verify(run, clean.anchor)
    assert (code, rep["first_bad"]) == (Exit.TAMPER, k.seq), rep
    fr = ks("recover", run, "--dry-run")
    assert fr.returncode == Exit.FROZEN, fr.stdout + fr.stderr  # D7/F5: verify != OK -> FROZEN
    assert not (run / "plans").exists() or not list((run / "plans").iterdir())


def test_rt7b_side_store_value_edit(clean, copy):
    run = copy("b")
    k = _k(run)
    h = k.envelope.args_hash  # crm's args carry the attacker IBAN; edit it to a good one, record untouched
    p = run / "sidestore" / h[:2] / f"{h}.json"
    obj = json.loads(p.read_bytes())
    obj["value"]["set"]["iban"] = "DE89370400440532013000"
    p.write_bytes(json.dumps(obj, separators=(",", ":"), sort_keys=True).encode())
    code, rep = verify(run, clean.anchor)
    assert (code, rep["reason"]) == (Exit.TAMPER, "side_entry_mismatch"), rep


def test_rt7c_delete_the_line(clean, copy):
    run = copy("c")
    k = _k(run)
    lines = _lines(run)
    _put(run, lines[:k.seq - 1] + lines[k.seq:])
    code, rep = verify(run, clean.anchor)
    assert (code, rep["reason"], rep["first_bad"]) == (Exit.TAMPER, "seq_gap", k.seq), rep


def test_rt7d_truncate_below_the_last_checkpoint(clean, copy):
    run = copy("d")
    lines = _lines(run)
    n = len(lines) - 5
    _put(run, lines[:n])
    code, rep = verify(run, clean.anchor)
    assert code == Exit.WITNESS and rep["reason"] in ("truncated", "head_mismatch") and rep["first_bad"] == n + 1, rep


def test_rt7e_garble_the_line(clean, copy):
    run = copy("e")
    k = _k(run)
    lines = _lines(run)
    lines[k.seq - 1] = lines[k.seq - 1][:40] + b"\x00garbled" + lines[k.seq - 1][48:]
    _put(run, lines)
    code, rep = verify(run, clean.anchor)
    assert (code, rep["reason"], rep["first_bad"]) == (Exit.TAMPER, "parse_error", k.seq), rep


def test_rt7f_redaction_boundary_passes_by_design(clean, copy):
    """Recorded, not a bug: redact keeps the hash, so chain and signatures verify (SPEC RT7 f)."""
    run = copy("f")
    k = _k(run)
    h = k.envelope.args_hash
    p = run / "sidestore" / h[:2] / f"{h}.json"
    e = SideEntry.from_canonical(p.read_bytes())
    p.write_bytes(SideEntry(hash=e.hash, domain=e.domain, value=None, redacted=True).to_canonical())
    code, rep = verify(run, clean.anchor)
    assert code == Exit.OK and rep["anchored"] is True, rep


def test_rt7_edits_suspend_nobody(clean):
    """Verification is read-only: the statuses of the clean run are the only ones (nothing re-executes)."""
    before = [(c.op.value, c.target) for _, c in clean.controls() if c.target.startswith("agent:")]
    assert before == [("suspend", "agent:crm")]
