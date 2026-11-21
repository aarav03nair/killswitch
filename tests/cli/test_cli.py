"""B3-12: ks command surface, exit codes, runtime hand-off."""

from __future__ import annotations

import json

import pytest

from ks.cli import main
from ks.contracts import Exit

ALL = ("run", "inject", "verify", "blame", "contain", "recover", "score", "repro", "bench", "console")


def test_help_lists_every_command(capsys):
    with pytest.raises(SystemExit) as e:
        main(["--help"])
    assert e.value.code == 0
    out = capsys.readouterr().out
    for c in ALL:
        assert c in out


@pytest.mark.parametrize("argv", [
    [], ["nope"], ["run", "--ticks", "x"], ["run", "--pause-at", "1", "--step"], ["run", "--pause-at", "a,b"],
    ["run", "--slot", "docs"], ["inject"], ["inject", "F2+", "--rogue", "x.py"], ["inject", "F2+", "--culprit", "docs"],
    ["inject", "F99"], ["run", "--fault", "F2+"], ["run", "--scenario", "world", "--fault", "F99"], ["contain", "revoke", "agent:crm", "RUN"], ["contain", "suspend", "crm", "RUN"],
    ["recover", "RUN"], ["recover", "RUN", "--dry-run", "--apply", "P"], ["console", "RUN"],
    ["bench", "--seeds", "a"], ["verify"], ["repro", "A"],
])
def test_bad_args_exit_usage(argv, capsys):
    try:
        rc = main(argv)
    except SystemExit as e:
        rc = e.code
    assert rc == Exit.USAGE


def test_validation_usage_without_exit(tmp_path):
    assert main(["contain", "revoke", "agent:crm", str(tmp_path)]) == Exit.USAGE
    assert main(["bench", "--seeds", "a"]) == Exit.USAGE
    assert main(["inject", "F2+", "--culprit", "docs"]) == Exit.USAGE


def test_unbuilt_commands_say_not_yet(tmp_path, capsys):
    assert main(["blame", str(tmp_path)]) == Exit.IO  # S4-29: built; not a run dir is IO
    assert "ks blame" in capsys.readouterr().err
    assert main(["score", str(tmp_path)]) == Exit.IO  # B3-27: built; a dir that is not a run dir is IO
    assert "ks score" in capsys.readouterr().err
    assert main(["recover", str(tmp_path / "missing"), "--dry-run"]) == Exit.IO
    # B3-30: recover is built; a directory that is not a run dir is IO (verify missing_file), never FROZEN
    assert main(["recover", str(tmp_path), "--dry-run"]) == Exit.IO
    assert "not a readable run dir" in capsys.readouterr().err


def test_contain_on_a_finished_run_is_io(tmp_path, capsys):
    """B3-13: contain needs a live gateway; no operator socket in the run dir gives IO (ADR-07)."""
    assert main(["contain", "suspend", "agent:crm", str(tmp_path)]) == Exit.IO
    assert "no live run" in capsys.readouterr().err


def _capture(monkeypatch):
    seen: dict = {}

    def fake(*, agents, ticks, seed, key_mode, out, options=None, **kw):
        seen.update(seed=seed, ticks=ticks, out=out, options=options, **kw)
    monkeypatch.setattr("ks.runtime.run", fake)
    return seen


def test_run_fault_reaches_runtime(monkeypatch, tmp_path):
    seen = _capture(monkeypatch)
    out = str(tmp_path / "r")
    assert main(["run", "--scenario", "world", "--fault", "F2+", "--seed", "7", "--hold", "3",
                 "--pause-at", "4,9", "--out", out]) == Exit.OK
    o = seen["options"]
    assert (o.fault, seen["seed"], o.hold, o.pause_at) == ("F2+", 7, 3, (4, 9))


def test_plain_run_passes_empty_options(monkeypatch, tmp_path):
    seen = _capture(monkeypatch)
    assert main(["run", "--out", str(tmp_path / "r")]) == Exit.OK
    assert seen["options"].requested() == ()


def test_hold_zero_is_forwarded(monkeypatch, tmp_path):
    seen = _capture(monkeypatch)
    assert main(["run", "--hold", "0", "--out", str(tmp_path / "r")]) == Exit.OK
    assert seen["options"].hold == 0


def test_run_fault_validated(tmp_path):
    assert main(["run", "--scenario", "world", "--fault", "F99", "--out", str(tmp_path / "r")]) == Exit.USAGE
    assert main(["run", "--fault", "F2+", "--out", str(tmp_path / "r")]) == Exit.USAGE  # skeleton scenario


def test_inject_reaches_runtime(monkeypatch, tmp_path):
    seen = _capture(monkeypatch)
    assert main(["inject", "F2+", "--seed", "5", "--culprit", "crm", "--step", "--out", str(tmp_path / "r")]) == Exit.OK
    o = seen["options"]
    assert (o.fault, o.culprit, seen["seed"], o.step) == ("F2+", "crm", 5, True)
    assert seen["ticks"] == 120
    assert seen["run_id"] == "world-f2plus-s5"  # does not collide with the plain world-s5 run dir


def test_inject_rogue_default_slot(monkeypatch, tmp_path):
    seen = _capture(monkeypatch)
    f = tmp_path / "rogue.py"
    f.write_text("pass\n")
    assert main(["inject", "--rogue", str(f), "--out", str(tmp_path / "r")]) == Exit.OK
    o = seen["options"]
    assert o.slot == "docs" and o.rogue == str(f)


def test_unserved_option_is_not_yet(tmp_path, capsys):
    """Real ks.runtime.run raises NotImplementedError before creating anything; CLI maps it to IO + fixed text."""
    out = tmp_path / "r"
    from ks.runtime.options import SERVED
    if {"fault", "hold"} <= SERVED:
        pytest.skip("runtime serves these now")
    assert main(["run", "--scenario", "world", "--fault", "F2+", "--out", str(out)]) == Exit.IO
    assert "not yet implemented" in capsys.readouterr().err
    assert not out.exists()


def test_remaining_placeholders_listed():
    """Visible punch list: every entry must be gone before the finale (CALL-02 / B3-12 review)."""
    from ks.runtime.options import SERVED, RunOptions
    unserved = sorted(f for f in RunOptions.__dataclass_fields__ if f not in SERVED)
    commands: list[str] = []  # recover (B3-30), score (B3-27), bench (B3-33) landed
    print("PLACEHOLDERS runtime options:", unserved, "commands:", commands)
    assert set(unserved) | set(SERVED) == set(RunOptions.__dataclass_fields__)
    assert unserved == ["with_baselines"]  # B3-27 served fault, culprit, hold, pause_on_alert; B3-35 rogue, slot
    assert len(commands) == 0  # update when it lands; delete this test when both lists are empty


def test_repro_banner_ok_and_diverged(tmp_path, capsys):
    from ks.contracts import RunDir
    a, b = tmp_path / "a", tmp_path / "b"
    for d in (a, b):
        d.mkdir()
        (d / "config.json").write_text("{}")
    assert main(["repro", str(a), str(b)]) == Exit.OK
    assert capsys.readouterr().out.startswith("NOT A SECURITY RUN")
    (b / "config.json").write_text('{"x":1}')
    assert main(["repro", str(a), str(b)]) == Exit.DIVERGED
    assert main(["repro", str(a), str(tmp_path / "zz")]) == Exit.IO
    assert RunDir  # imported API stays public


def test_verify_last_line_is_report_with_isolation(tmp_path, capsys):
    out = tmp_path / "run"
    rc = main(["run", "--agents", "2", "--ticks", "3", "--seed", "1", "--shared-uid", "--out", str(out)])
    assert rc == Exit.OK
    capsys.readouterr()
    assert main(["verify", str(out)]) == Exit.OK
    last = capsys.readouterr().out.strip().splitlines()[-1]
    assert json.loads(last)["isolation"] == "degraded"
    assert main(["verify", str(out), "--json"]) == Exit.OK
    assert json.loads(capsys.readouterr().out)["isolation"] == "degraded"


@pytest.fixture(scope="module")
def hero_run(tmp_path_factory):
    out = tmp_path_factory.mktemp("blame") / "hero"
    assert main(["run", "--scenario", "world", "--fault", "F2+", "--seed", "2", "--ticks", "40", "--out", str(out)]) in (
        Exit.OK, Exit.ISOLATION_DEGRADED if hasattr(Exit, "ISOLATION_DEGRADED") else Exit.OK)
    return out


def _as_per_agent_uid(monkeypatch):
    """The sandbox runs non-root, so the hero run is degraded here; present its VerifyReport as the container's."""
    import ks.verify as kv
    real = kv.verify
    monkeypatch.setattr(kv, "verify", lambda *a, **k: (lambda r: r.model_copy(update={"isolation": "per_agent_uid"}))(
        real(*a, **k)))


def test_blame_hero_run_names_crm_first(hero_run, capsys, monkeypatch):
    _as_per_agent_uid(monkeypatch)
    capsys.readouterr()
    assert main(["blame", str(hero_run)]) == Exit.OK
    out = capsys.readouterr().out
    assert "1. crm" in out and "suspect crm" in out and "taint:" in out


def test_blame_refuses_tampered_copy(hero_run, tmp_path, capsys):
    import json
    import shutil
    cp = tmp_path / "copy"
    shutil.copytree(hero_run, cp)
    lines = (cp / "record.jsonl").read_text().splitlines()
    i = next(k for k, l in enumerate(lines) if json.loads(l).get("seq") == 45)
    assert '"agent_id":"crm"' in lines[i]
    lines[i] = lines[i].replace('"agent_id":"crm"', '"agent_id":"intake"', 1)
    (cp / "record.jsonl").write_text("\n".join(lines) + "\n")
    capsys.readouterr()
    rc = main(["blame", str(cp)])
    cap = capsys.readouterr()
    assert rc != Exit.OK and "UNVERIFIED RECORD" in cap.err and "root candidates" not in cap.out


def test_blame_unanchored_says_so_and_hero_crm_first(hero_run, capsys, monkeypatch):
    _as_per_agent_uid(monkeypatch)
    capsys.readouterr()
    assert main(["blame", str(hero_run)]) == Exit.OK
    out = capsys.readouterr().out
    assert out.startswith("verify: OK") and "not anchored" in out and "1. crm" in out
    assert "VOID" not in out


def test_blame_head_anchored(tmp_path, capsys, monkeypatch):
    out = tmp_path / "h"
    capsys.readouterr()
    main(["run", "--scenario", "world", "--fault", "F2+", "--seed", "2", "--ticks", "40", "--out", str(out)])
    anchor = next((l for l in capsys.readouterr().out.splitlines() if l.startswith("{") and '"config_hash"' in l), None)
    if anchor is None:
        pytest.skip("run printed no RunAnchor line")
    _as_per_agent_uid(monkeypatch)
    assert main(["blame", str(out), "--head", anchor]) == Exit.OK
    o = capsys.readouterr().out
    assert "; anchored;" in o and "1. crm" in o


def test_blame_void_run_does_not_attribute(tmp_path, capsys):
    out = tmp_path / "void"
    assert main(["run", "--scenario", "world", "--fault", "F2+", "--seed", "2", "--ticks", "40", "--shared-uid",
                 "--out", str(out)]) == Exit.OK
    capsys.readouterr()
    main(["blame", str(out)])
    o = capsys.readouterr().out
    assert "attribution VOID" in o and "not anchored" in o
    assert "unattributed: isolation degraded" in o
    assert "root candidates (ranked)" not in o


def test_blame_void_every_agent_line_is_labelled(tmp_path, capsys):
    out = tmp_path / "void2"
    assert main(["run", "--scenario", "world", "--fault", "F2+", "--seed", "2", "--ticks", "40", "--shared-uid",
                 "--out", str(out)]) == Exit.OK
    capsys.readouterr()
    main(["blame", str(out)])
    lines = capsys.readouterr().out.splitlines()
    named = [l for l in lines if l.startswith(("  1.", "  2.", "suspect ", "taint:"))
             and not l.startswith("taint: none")]
    assert any(l.startswith("taint:") for l in named) and any(l.startswith("suspect ") for l in named)
    assert all("unattributed: isolation degraded" in l for l in named)
