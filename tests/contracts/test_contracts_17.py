"""Contracts 1.7.0 (S4-13, D-18, ADR-05a; CALL-02 B5-a): additive only.

``StepOp`` gains ``resolve`` / ``unresolve`` (``ResolveStep``, ``UnresolveStep``, ``RevertEntry``), ``RunConfig.resolver``
(``off`` | ``ww_rebase/1``, omitted from the canonical bytes at ``off``), verify reason ``resolution_invalid`` (TAMPER).
Plans without the new steps parse and hash as before; 1.3-1.6 runs still verify. ``fixtures/run-1.6-world-s0`` was
built from the 1.6.0 tree (S4-13 work, before this bump) with ``ks run --scenario world --ticks 8 --seed 0
--run-id world-s0``.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from ks import contracts as C
from ks.contracts import (VERIFY_REASONS, ActionRef, Exit, NonCanonicalError, RecoverArgs, ResolveStep, RevertEntry,
                          RunConfig, StepOp, UnresolveStep, VersionRef, recover_tool, resolver_label,
                          system_tool_signers)
from ks.verify import verify

from samples import samples

SRC = Path(C.__file__).resolve().parent
FIX = Path(__file__).with_name("fixtures")
H = "a" * 64


def test_version_readme_reason():
    assert tuple(map(int, C.CONTRACTS_VERSION.split("."))) >= (1, 7, 0)
    readme = (SRC / "README.md").read_text(encoding="utf-8")
    assert "### 1.7.0" in readme and "`resolution_invalid`" in readme and "`ResolveStep`" in readme
    assert VERIFY_REASONS["resolution_invalid"] == Exit.TAMPER


def _cfg(**kw) -> RunConfig:
    return RunConfig.model_validate({**samples()["run_config"].to_obj(), **kw})


def test_resolver_default_omitted_and_hash_unchanged():
    c = _cfg()
    assert c.resolver == "off" and b"resolver" not in c.to_canonical()
    raw = json.loads(c.to_canonical())
    raw["resolver"] = "off"
    with pytest.raises(NonCanonicalError):
        RunConfig.from_canonical(C.canonical.dumps(raw))


def test_resolver_on_is_serialized_moves_hash_and_tcb_sees_it():
    c, x = _cfg(), _cfg(resolver="ww_rebase/1")
    assert x.to_obj()["resolver"] == "ww_rebase/1" and RunConfig.from_canonical(x.to_canonical()) == x
    assert x.content_hash() != c.content_hash()
    assert x.tcb_view().resolver == "ww_rebase/1"
    assert (resolver_label("off"), x.resolver_label) == ("resolver: off", "resolver: ww_rebase/1 (on)")
    with pytest.raises(ValueError):
        _cfg(resolver="merge_anything/9")


def _resolve(**kw) -> ResolveStep:
    base = dict(n=1, reason="write_write_conflict", rule="ww_rebase", rule_version=1, obj="suppliers:S-22",
                culprit_ver=VersionRef(ver=2, hash=H), expect=VersionRef(ver=3, hash=H), to=VersionRef(ver=1, hash=H),
                rebased=ActionRef(seq=9, agent_id="triage", action_id="triage-t9"), rebased_hash=H,
                unblocked=("ob-000031", "ob-000032"), rationale=("row_object", "sim_clean"))
    base.update(kw)
    return ResolveStep(**base)


def test_new_steps_roundtrip_and_validate():
    r = _resolve()
    a = RecoverArgs(plan_id="p-000100", plan_hash=H, n=1, step=r)
    assert RecoverArgs.from_canonical(a.to_canonical()) == a and recover_tool(StepOp.RESOLVE) == "ks.recover.resolve"
    assert _resolve(unblocked=("ob-000032", "ob-000031")).unblocked == ("ob-000031", "ob-000032")  # sorted
    with pytest.raises(ValueError):
        _resolve(unblocked=("ob-000031", "ob-000031"))  # unique
    with pytest.raises(ValueError):
        _resolve(rule_version=0)
    u = UnresolveStep(n=0, reason="resolution_reverted", resolution=ActionRef(seq=50, agent_id="ks.recovery",
                                                                              action_id="p-000100.1"),
                      resolution_plan_hash=H, reverts=(RevertEntry(obj="suppliers:S-22", expect=VersionRef(ver=4, hash=H),
                                                                   to=VersionRef(ver=3, hash=H)),),
                      reheld=(), rationale=("resolution_executed",))
    ua = RecoverArgs(plan_id="p-000120", plan_hash=H, n=0, step=u)
    assert RecoverArgs.from_canonical(ua.to_canonical()) == ua
    with pytest.raises(ValueError):
        UnresolveStep(**{**u.model_dump(), "reverts": ()})
    assert system_tool_signers("ks.recover.resolve") == system_tool_signers("ks.recover.unresolve") == {"ks.recovery"}


def _copy(src: Path, tmp_path: Path) -> Path:
    run = tmp_path / src.name
    shutil.copytree(src, run)
    for d in ("baselines", "oracle", "plans"):
        (run / d).mkdir(exist_ok=True)
    for p in run.rglob("*"):
        p.chmod(0o700 if p.is_dir() else 0o600)
    return run


@pytest.mark.parametrize("name,ver", [("run-1.3-world-s0", "1.3.0"), ("run-1.4-world-s0", "1.4.0"),
                                      ("run-1.5-world-s0", "1.5.0"), ("run-1.6-world-s0", "1.6.0")])
def test_old_runs_verify_under_17(name, ver, tmp_path):
    cfg = json.loads((FIX / name / "config.json").read_bytes())
    assert cfg["contracts_version"] == ver and "resolver" not in cfg
    rep = verify(_copy(FIX / name, tmp_path), log=lambda s: None)
    assert rep.ok and rep.exit == 0, rep
