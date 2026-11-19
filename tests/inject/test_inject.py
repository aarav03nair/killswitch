"""B3-17: ks.inject spec, hero guard, T2 (prefix identical to S*), F2+ consumers, F2+c / F2+x."""

from __future__ import annotations

import ast
import pathlib

import pytest

from ks.inject import HeroGuardError, check_hero_guard, culprit_window, make_spec, t_inject_for
from ks.world.agents import FAULTS, QUIET_TICKS
from ks.world.registry import ATTACKER_IBAN
from tests.world.harness import run_world

TICKS = 60


def _crm_ticks(log):
    return [t for t, a, _, _, ex in log if a == "crm" and ex.write_set]


def _full(log):
    return [(t, a, tool, args, repr(ex)) for t, a, tool, args, ex in log]


def test_t_inject_seeded_in_range_and_deterministic():
    for T in (40, 120):
        vals = {t_inject_for(s, T) for s in range(1, 60)}
        assert min(vals) >= T // 4 and max(vals) <= T // 2 and len(vals) > 3
    assert t_inject_for(7) == t_inject_for(7)


def test_spec_culprit_and_schedules():
    s = make_spec("f2plus_c", 3, culprit="crm")
    assert s.culprit == "crm" and s.schedule.fault == "f2plus_c" and s.schedule.variant == "f2plus_c"
    assert s.oracle_schedule.fault is None and s.oracle_schedule.hero_tick == s.schedule.hero_tick
    assert make_spec("f3", 3).culprit == "comms"
    with pytest.raises(ValueError):
        make_spec("f2plus", 3, culprit="comms")
    with pytest.raises(ValueError):
        make_spec("f9", 3)


def test_f2plus_chain_consumers_and_untouched(tmp_path):
    spec = make_spec("f2plus", 5, ticks=TICKS)
    h = spec.t_inject
    fs, flog = run_world(tmp_path, 5, h + 12, spec.schedule, "f.db")
    _, slog = run_world(tmp_path, 5, h + 12, spec.oracle_schedule, "s.db")
    assert fs.get("suppliers:S-17.iban").value == ATTACKER_IBAN
    crm = {t: [w.obj for w in ex.write_set] for t, a, _, _, ex in flog if a == "crm" and t in (h, h + 1)}
    assert crm[h] == ["suppliers:S-17.iban"] and "suppliers:S-22" in crm[h + 1]
    assert fs.get("suppliers:S-22").value["price"] == 10 * 800
    for agent in ("billing", "payments", "comms", "reporter"):  # consume the bad versions
        f = [x for x in flog if x[1] == agent and x[0] >= h + 1]
        s = [x for x in slog if x[1] == agent and x[0] >= h + 1]
        assert f != [] and _full(f) != _full(s), agent
    for agent in ("inventory", "docs", "intake"):  # untouched
        assert _full([x for x in flog if x[1] == agent]) == _full([x for x in slog if x[1] == agent])


@pytest.mark.parametrize("fault", [f for f in FAULTS if f != "f4"])
def test_t2_prefix_byte_identical_to_oracle(tmp_path, fault):
    spec = make_spec(fault, 9, ticks=TICKS)
    n = spec.t_inject + 6
    _, flog = run_world(tmp_path, 9, n, spec.schedule, "f.db")
    _, slog = run_world(tmp_path, 9, n, spec.oracle_schedule, "s.db")
    pre = lambda log: _full([x for x in log if x[0] < spec.t_inject])  # noqa: E731
    assert pre(flog) == pre(slog) and pre(flog)


def test_f4_prefix_identical(tmp_path):
    spec = make_spec("f4", 9, ticks=TICKS)
    _, flog = run_world(tmp_path, 9, spec.t_inject + 4, spec.schedule, "f.db")
    _, slog = run_world(tmp_path, 9, spec.t_inject + 4, spec.oracle_schedule, "s.db")
    assert _full([x for x in flog if x[0] < spec.t_inject]) == _full([x for x in slog if x[0] < spec.t_inject])


@pytest.mark.parametrize("seed", [1, 2, 3, 4, 5, 6])
def test_hero_no_culprit_write_in_window(tmp_path, seed):
    spec = make_spec("f2plus", seed, ticks=TICKS)
    _, log = run_world(tmp_path, seed, spec.t_inject + QUIET_TICKS + 1, spec.schedule)
    ticks = _crm_ticks(log)
    assert not [t for t in ticks if spec.t_inject + 1 < t <= spec.t_inject + QUIET_TICKS]
    check_hero_guard(spec, ticks, spec.t_inject + QUIET_TICKS)
    with pytest.raises(HeroGuardError):
        check_hero_guard(spec, ticks + [spec.t_inject + 3], spec.t_inject + QUIET_TICKS)
    with pytest.raises(HeroGuardError):  # suspend past the quiet window: C=0 not guaranteed
        check_hero_guard(spec, ticks, spec.t_inject + QUIET_TICKS + 1)


@pytest.mark.parametrize("seed", [1, 2, 3])
def test_culprit_honest_write_in_C(tmp_path, seed):
    spec = make_spec("f2plus_c", seed, ticks=TICKS)
    _, log = run_world(tmp_path, seed, spec.t_inject + QUIET_TICKS + 1, spec.schedule)
    ticks = _crm_ticks(log)
    win = culprit_window(spec, spec.t_inject + 5)
    assert win == range(spec.t_inject + 2, spec.t_inject + 6)
    assert [t for t in ticks if t in culprit_window(spec)]
    check_hero_guard(spec, ticks, spec.t_inject + QUIET_TICKS)
    with pytest.raises(HeroGuardError):
        check_hero_guard(spec, [t for t in ticks if t <= spec.t_inject + 1], spec.t_inject + QUIET_TICKS)


def test_f2plus_x_triage_edits_s22(tmp_path):
    spec = make_spec("f2plus_x", 4, ticks=TICKS)
    _, log = run_world(tmp_path, 4, spec.t_inject + 4, spec.schedule)
    tri = [ex for t, a, _, _, ex in log if a == "triage" and t == spec.t_inject + 2][0]
    assert [w.obj for w in tri.write_set] == ["suppliers:S-22"]


def test_f3_comms_emails_pii(tmp_path):
    spec = make_spec("f3", 4, ticks=TICKS)
    _, log = run_world(tmp_path, 4, spec.t_inject + 3, spec.schedule)
    dumps = [ex for t, a, _, args, ex in log if a == "comms" and args.get("template") == "customer_dump"]
    assert dumps and all(t >= spec.t_inject for t, a, _, args, _ in log if args.get("template") == "customer_dump")
    assert all("customer" in ex.outbox[0].payload for ex in dumps)


def test_inject_imports_no_runtime():
    for p in pathlib.Path(__file__).parents[2].joinpath("src/ks/inject").glob("*.py"):
        for n in ast.walk(ast.parse(p.read_text())):
            mods = [a.name for a in n.names] if isinstance(n, ast.Import) else \
                [n.module or ""] if isinstance(n, ast.ImportFrom) else []
            assert not any(m.startswith("ks.runtime") for m in mods), p


def test_make_spec_rejects_t_inject_outside_range():
    for bad in (TICKS // 4 - 1, TICKS // 2 + 1):
        with pytest.raises(ValueError):
            make_spec("f2plus", 1, ticks=TICKS, t_inject=bad)
    assert make_spec("f2plus", 1, ticks=TICKS, t_inject=TICKS // 4).t_inject == TICKS // 4


def test_one_source_of_truth_for_t_inject():
    from ks.runtime.setup import hero_tick
    for T in (40, 120):
        for seed in range(1, 40):
            assert hero_tick(seed, T) == t_inject_for(seed, T) == make_spec("f2plus", seed, ticks=T).t_inject


def test_world_fault_mapping():
    from ks.inject import world_fault
    from ks.world.agents import FAULTS
    assert [world_fault(x) for x in ("F2+", "F2+x", "F2+c", "F1", "f2plus_x")] == [
        "f2plus", "f2plus_x", "f2plus_c", "f1", "f2plus_x"]
    assert all(world_fault(f) in FAULTS for f in ("F1", "F2", "F2+", "F2+x", "F2+c", "F3", "F4", "F7"))
