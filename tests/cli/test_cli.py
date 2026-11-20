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
    for argv in (["blame", str(tmp_path)],):
        assert main(argv) == Exit.IO
        assert "not yet implemented" in capsys.readouterr().err
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
    commands = ["blame (B3-14)"]  # recover (B3-30), score (B3-27), bench (B3-33) landed
    print("PLACEHOLDERS runtime options:", unserved, "commands:", commands)
    assert set(unserved) | set(SERVED) == set(RunOptions.__dataclass_fields__)
    assert unserved == ["with_baselines"]  # B3-27 served fault, culprit, hold, pause_on_alert; B3-35 rogue, slot
    assert len(commands) == 1  # update when it lands; delete this test when both lists are empty


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
