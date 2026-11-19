"""B3-22: S* run, ledger algebra, import lint."""

from __future__ import annotations

import subprocess
import sys

import pytest

from ks.inject import make_spec
from ks.oracle import (ORACLE_MARKER, OracleRunError, b_set, g_set, is_oracle_run, oracle_self_test, run_pure,
                       run_s_star, t0_of)

T = 50


@pytest.fixture(scope="module")
def spec():
    return make_spec("f2plus", 3, ticks=T)


def test_oracle_self(spec, tmp_path):
    assert oracle_self_test(spec, tmp_path) == set()


def test_deterministic_and_marked(spec, tmp_path):
    a, b = run_s_star(spec, tmp_path / "a"), run_s_star(spec, tmp_path / "b")
    assert a.ledger_bytes == b.ledger_bytes and a.effects
    assert is_oracle_run(a.path) and (a.path / ORACLE_MARKER).exists()
    assert "injected" not in a.ledger_bytes.decode()


def test_no_shared_run_dir(spec, tmp_path):
    (tmp_path / "record.jsonl").write_text("")
    with pytest.raises(OracleRunError):
        run_s_star(spec, tmp_path / "o")
    with pytest.raises(FileExistsError):
        (tmp_path / "x").mkdir()
        run_s_star(spec, tmp_path / "x")


def test_t0_ge_inject_and_ledger_per_field(spec, tmp_path):
    star = run_s_star(spec, tmp_path / "s").effects
    bad = run_pure(spec, tmp_path / "f", faulted=True).effects
    b = b_set(bad, star)
    assert "suppliers:S-17.iban" in b and "suppliers:S-22.price" in b
    # per field: the S-22 row's other fields, and the S-17 row object, are not in B
    assert "suppliers:S-22.name" not in b and "suppliers:S-22.iban" not in b
    t0 = t0_of(bad, b, spec.t_inject)
    assert t0 is not None and t0 >= spec.t_inject
    assert any(k.startswith("outbox:") for k in b)  # sink deliveries are keyed too
    assert not g_set(bad, b, spec.t_inject) & b
    assert b_set(bad, star, upto=spec.t_inject - 1) == set()  # faulty == S* before t_inject


def test_bypass_enters_B(spec, tmp_path):
    star = run_s_star(spec, tmp_path / "s").effects

    def rogue(store, t):
        if t == T - 1:
            with store.txn():
                store.put("customers:C-01", {"name": "x", "tier": "std", "email_hash": "h01"}, author="rogue",
                          seq=10**6, action_id="bypass")
    bad = run_pure(spec, tmp_path / "f", faulted=False, bypass=rogue).effects
    b = b_set(bad, star)
    assert "customers:C-01.name" in b and all(k.startswith("customers:C-01.") for k in b)
    assert [e["seq"] for e in bad if e["key"] == "customers:C-01.name" and e["tick"] == T - 1] == [None]


def test_culprit_stops_at_suspend(spec, tmp_path):
    s0 = run_s_star(spec, tmp_path / "a").effects
    sx = run_s_star(spec, tmp_path / "b", suspend_tick=spec.t_inject + 3).effects
    assert not [e for e in sx if e["agent"] == "crm" and e["tick"] >= spec.t_inject + 3]
    assert [e for e in s0 if e["agent"] == "crm" and e["tick"] >= spec.t_inject + 3]


def test_import_lint():
    code = ("import sys, ks.oracle; bad=[m for m in sys.modules if m.split('.')[:2] in "
            "(['ks','taint'],['ks','monitor'],['ks','policy'],['ks','recovery'],['ks','runtime'])]; print(bad)")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True).stdout.strip()
    assert out == "[]", out


# --- B3-22 review follow-ups ---------------------------------------------------------------------------------
def _outbox(effects):
    return [e for e in effects if e["key"].startswith("outbox:")]


def test_hold_window_dispatches_at_release_tick(spec, tmp_path):
    h0 = _outbox(run_s_star(spec, tmp_path / "h0", hold=0).effects)
    h6 = _outbox(run_s_star(spec, tmp_path / "h6", hold=6).effects)
    assert h0 and h6
    # H=0: dispatched the tick after creation; H=6: six ticks after. Same items, later, and fewer have left by T.
    assert min(e["tick"] for e in h6) == 12  # created t=2 reading the seed IBAN (v=0): G3 max(t+H, v+2H) = 12
    assert len(h6) < len(h0)
    assert {e["key"] for e in h6} <= {e["key"] for e in h0}
    # honest queued items do NOT land in B at t_rec: the faulty world with the same hold agrees with S* pre-fault
    star = run_s_star(spec, tmp_path / "s6", hold=6).effects
    bad = run_pure(spec, tmp_path / "f6", faulted=True, hold=6).effects
    assert not [k for k in b_set(bad, star, upto=spec.t_inject - 1) if k.startswith("outbox:")]
    # an item created inside the window is not in the S* fold at t_rec = creation + 1 (it has not landed)
    t_first = min(e["tick"] for e in h6)
    assert t_first > 0 and not _outbox(fold_upto(star, t_first - 1))  # nothing has left before the first release


def fold_upto(effects, upto):
    return [e for e in effects if e["tick"] <= upto]


def test_bypass_reusing_recorded_seq_is_not_recorded(spec, tmp_path):
    def rogue(store, t):
        if t == T - 1:
            with store.txn():  # the store's last seq is a recorded one: reuse it under a different author
                store.put("customers:C-02", {"name": "x", "tier": "std", "email_hash": "h02"}, author="rogue",
                          seq=store.last_seq(), action_id="bypass")
    bad = run_pure(spec, tmp_path / "f", faulted=False, bypass=rogue).effects
    assert [e["seq"] for e in bad if e["key"] == "customers:C-02.name" and e["tick"] == T - 1] == [None]


def test_outbox_key_is_gateway_idem_key(spec, tmp_path):
    from ks.oracle import outbox_key
    e = _outbox(run_s_star(spec, tmp_path / "s").effects)[0]
    assert e["key"] == outbox_key(e["idem_key"]) == f"outbox:{e['idem_key']}" and not e["key"].startswith("outbox:ob-")


def test_sstar_prefix_matches_real_gateway_run_h0_only(spec, tmp_path_factory):
    """H=0 ONLY (ks.runtime hardcodes hold_window_ticks=0, no holds): a real ``ks run --scenario world`` (fault off)
    past t_inject has a ledger equal to S* in full, in particular before t_inject; any drift of the pure world from the gateway world fails here."""
    import os
    import shutil
    import tempfile
    from pathlib import Path

    from ks.oracle import real_ledger
    from tests.skeleton.conftest import ks
    base = Path(tempfile.mkdtemp(prefix="ks-b322-", dir="/tmp"))
    os.chmod(base, 0o711)
    try:
        p = ks("run", "--scenario", "world", "--ticks", T, "--seed", spec.seed, "--out", base / "run")
        assert p.returncode == 0, p.stderr + p.stdout
        real = real_ledger(base / "run")
        star = run_s_star(spec, tmp_path_factory.mktemp("star") / "s").effects
        assert real and _outbox(real)
        assert spec.t_inject < T - 1
        assert b_set(real, star, upto=spec.t_inject - 1) == set()
        assert b_set(real, star) == set()  # fault off: the whole run agrees
        assert {e["key"] for e in _outbox(real)} == {e["key"] for e in _outbox(star)}  # idem-keyed on both sides
    finally:
        shutil.rmtree(base, ignore_errors=True)


# --- B3-22 re-review (round 3) -------------------------------------------------------------------------------
def _eff(tick, seq, key, vh, table="customers"):
    return {"eff": "e", "tick": tick, "seq": seq, "agent": "a", "kind": "row", "table": table, "pk": "p",
            "field": "f", "key": key, "value_hash": vh, "idem_key": None, "state": "present"}


def test_bypass_followed_by_honest_write_still_in_B():
    star = [_eff(1, 1, "customers:p.f", "good")]
    run = [_eff(1, 1, "customers:p.f", "good"), _eff(3, None, "customers:p.f", "evil"),
           _eff(6, 9, "customers:p.f", "good")]  # later recorded honest write restores the S* value
    assert "customers:p.f" in b_set(run, star)
    assert "customers:p.f" not in b_set(run, star, upto=2)  # not yet written at t_rec=2
    run[1]["value_hash"] = "good"  # a bypass that wrote exactly what S* holds is harmless
    assert b_set(run, star) == set()


def _real_run_dir(spec):
    import os
    import tempfile
    from pathlib import Path

    from tests.skeleton.conftest import ks
    base = Path(tempfile.mkdtemp(prefix="ks-b322-", dir="/tmp"))
    os.chmod(base, 0o711)
    p = ks("run", "--scenario", "world", "--ticks", T, "--seed", spec.seed, "--out", base / "run")
    assert p.returncode == 0, p.stderr + p.stdout
    return base


def test_real_ledger_bypass_keeps_position_and_enters_B(spec, tmp_path_factory):
    """Real-run side: a bypass version (reusing the store's last recorded seq under another author) has seq null and a
    non-zero tick (never tick 0) and lands in B."""
    import shutil

    from ks.oracle import real_ledger
    from ks.world.scenario import open_world_store
    base = _real_run_dir(spec)
    try:
        run = base / "run"
        st = open_world_store(run / "workspace" / "state.db")
        try:
            orig = st.value_at("customers:C-01", st.heads()["customers:C-01"].ver)
            with st.txn():
                st.put("customers:C-01", {**orig, "name": "evil"}, author="rogue", seq=st.last_seq(), action_id="bypass")
        finally:
            st.close()
        real = real_ledger(run)
        star = run_s_star(spec, tmp_path_factory.mktemp("star") / "s").effects
        byp = [e for e in real if e["key"] == "customers:C-01.name" and e["agent"] == "rogue"]
        assert byp and byp[0]["seq"] is None and byp[0]["tick"] > 0
        assert "customers:C-01.name" in b_set(real, star)
    finally:
        shutil.rmtree(base, ignore_errors=True)


def test_sstar_hold_h6_independent_of_runtime(spec, tmp_path):
    """S*-side H>0 (no ks.runtime): honest items first leave at the G3 release tick, a faulty world with the same H
    agrees with S* before t_inject, and the culprit's tainted payment is in B. (ks.runtime hardcodes
    hold_window_ticks=0 today; an H=6 real-run equality belongs to B3-23/maya once RunOptions.hold is served.)"""
    star = run_s_star(spec, tmp_path / "s", hold=6).effects
    bad = run_pure(spec, tmp_path / "f", faulted=True, hold=6).effects
    assert min(e["tick"] for e in _outbox(star)) == 12
    assert b_set(bad, star, upto=spec.t_inject - 1) == set()
    assert b_set(bad, star)


def test_fault_off_no_sensitive_write_after_tick0(spec, tmp_path):
    """Guard for the sensitive_moved reasoning: S* does not mirror the sensitive hold because in a fault-off run
    no sensitive field changes after tick 0, so an honest run never trips it."""
    from ks.world.registry import SENSITIVE_FIELDS
    for seed in (1, 2, 3):
        sp = make_spec("f2plus", seed, ticks=T)
        eff = run_s_star(sp, tmp_path / f"s{seed}").effects
        sens = [e for e in eff if e["key"].split(":")[0] + "." + e["key"].split(".")[-1] in SENSITIVE_FIELDS]
        assert sens and all(e["tick"] == 0 for e in sens), [e["key"] for e in sens if e["tick"] > 0]


def _last_record_with_write(run):
    import json
    for line in reversed((run / "record.jsonl").read_text().splitlines()):
        r = json.loads(line)
        if r.get("envelope") and r.get("write_set"):
            return r
    raise AssertionError("no exec record")


def test_real_ledger_spoofed_provenance_on_other_object_is_bypass(spec, tmp_path_factory):
    """A bypass on a DIFFERENT object copying a real record's (seq, agent, action_id) is not recorded (that record
    does not list this obj) and, even overwritten later, stays in B."""
    import shutil

    from ks.oracle import real_ledger
    from ks.world.scenario import open_world_store
    base = _real_run_dir(spec)
    try:
        run = base / "run"
        rec = _last_record_with_write(run)
        env = rec["envelope"]
        st = open_world_store(run / "workspace" / "state.db")
        try:
            orig = st.value_at("customers:C-03", st.heads()["customers:C-03"].ver)
            with st.txn():
                st.put("customers:C-03", {**orig, "name": "evil"}, author=env["agent_id"], seq=rec["seq"],
                       action_id=env["action_id"])
            with st.txn():  # honest-looking overwrite restoring the value hides it from a final-state diff
                st.put("customers:C-03", orig, author="honest", seq=st.last_seq() + 1, action_id="later")
        finally:
            st.close()
        real = real_ledger(run)
        star = run_s_star(spec, tmp_path_factory.mktemp("star") / "s").effects
        byp = [e for e in real if e["key"] == "customers:C-03.name" and e["value_hash"] != _name_hash(orig)]
        assert byp and byp[0]["seq"] is None
        assert "customers:C-03.name" in b_set(real, star)
    finally:
        shutil.rmtree(base, ignore_errors=True)


def _name_hash(row):
    from ks.contracts import value_hash
    return value_hash(row["name"])


def test_real_run_bypass_then_honest_overwrite_still_in_B(spec, tmp_path_factory):
    """Real store accepts a bypass at seq L then an honest write at L+1 (it refuses only seq < last_seq)."""
    import shutil

    from ks.oracle import real_ledger
    from ks.world.scenario import open_world_store
    base = _real_run_dir(spec)
    try:
        run = base / "run"
        st = open_world_store(run / "workspace" / "state.db")
        try:
            orig = st.value_at("customers:C-01", st.heads()["customers:C-01"].ver)
            with st.txn():
                st.put("customers:C-01", {**orig, "name": "evil"}, author="rogue", seq=st.last_seq(), action_id="bypass")
            with st.txn():
                st.put("customers:C-01", orig, author="honest", seq=st.last_seq() + 1, action_id="later")
        finally:
            st.close()
        real = real_ledger(run)
        star = run_s_star(spec, tmp_path_factory.mktemp("star") / "s").effects
        assert any(e["agent"] == "rogue" and e["seq"] is None for e in real)
        assert "customers:C-01.name" in b_set(real, star)
    finally:
        shutil.rmtree(base, ignore_errors=True)
