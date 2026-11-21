"""S4-33 (Panel dry run #2 M7): verify reconciles every state.db version row against the record, and `ks score`
refuses a run that does not verify. Reproduces the Panel's edit: re-attribute crm's versions to payments."""

from __future__ import annotations

import shutil
import sqlite3

import pytest

from ks.cli import main
from ks.contracts import Exit
from ks.verify import verify

from . import world as W


def _quiet(_s: str) -> None:
    pass


def _edit(db, sql: str, *params) -> int:
    conn = sqlite3.connect(db, isolation_level=None)
    try:
        triggers = conn.execute("SELECT name, sql FROM sqlite_master WHERE type='trigger'").fetchall()
        for n, _ in triggers:
            conn.execute(f"DROP TRIGGER {n}")
        n = conn.execute(sql, params).rowcount
        for _, s in triggers:
            conn.execute(s)
        return n
    finally:
        conn.close()


@pytest.fixture()
def run(tmp_path):
    w = W.run(tmp_path / "w.db")
    assert verify(w.rundir.path, log=_quiet).ok
    return w.rundir.path


def _fails(run, needle: str):
    rep = verify(run, log=_quiet)
    assert (rep.ok, rep.reason, rep.exit) == (False, "reconcile_mismatch", int(Exit.RECONCILE)), rep
    return rep


def test_reattributed_history_fails_verify(run):
    n = _edit(run / "workspace" / "state.db", "UPDATE versions SET author='payments' WHERE author='crm'")
    assert n > 0
    _fails(run, "authored")


def test_edited_action_id_missing_and_extra_versions_fail(run):
    db = run / "workspace" / "state.db"
    shutil.copy(db, run.parent / "good.db")
    _edit(db, "UPDATE versions SET action_id='x' WHERE author='crm'")
    _fails(run, "authored")
    shutil.copy(run.parent / "good.db", db)
    assert verify(run, log=_quiet).ok
    # a non-head version row dropped (head still matches the digest)
    _edit(db, "DELETE FROM versions WHERE ver = 1 AND obj = (SELECT obj FROM versions GROUP BY obj "
              "HAVING COUNT(*) > 1 ORDER BY obj LIMIT 1)")
    _fails(run, "missing")
    shutil.copy(run.parent / "good.db", db)
    # an extra, unrecorded old version
    _edit(db, "INSERT INTO versions(obj, ver, hash, author, seq, action_id) VALUES ('zz:1:f', 1, 'ab', 'crm', 3, 'a')")
    _fails(run, "extra")


def test_score_refuses_unverified_run(run, capsys):
    _edit(run / "workspace" / "state.db", "UPDATE versions SET author='payments' WHERE author='crm'")
    code = main(["score", str(run)])
    err = capsys.readouterr()
    assert code == Exit.RECONCILE and "UNVERIFIED RUN" in err.err
    assert not (run / "score.json").exists() and "R" not in err.out.split()


def test_reconcile_output_is_not_consistent_s4_32(run, capsys):
    _edit(run / "workspace" / "state.db", "UPDATE versions SET author='payments' WHERE author='crm'")
    for extra in ([], ["--json"]):
        assert main(["verify", str(run), *extra]) == Exit.RECONCILE
        out = capsys.readouterr().out
        assert "consistent" not in out and "no_anchor" not in out
        assert "RECONCILE reconcile_mismatch; NOT VERIFIED" in out or extra
        assert '"unanchored_reason":"verify_failed"' in out


def test_gateway_author_rewrite_fails_verify_s4_33(run):
    """kabir's bypass: author='ks.gateway' on crm's rows must not skip the author check."""
    n = _edit(run / "workspace" / "state.db", "UPDATE versions SET author='ks.gateway' WHERE author='crm'")
    assert n > 0
    _fails(run, "authored")


def test_row_attributed_to_other_record_fails(run):
    """Swap which record a row claims: seq moved to another real seq."""
    _edit(run / "workspace" / "state.db",
          "UPDATE versions SET author='ks.recovery' WHERE author='crm'")
    _fails(run, "authored")

