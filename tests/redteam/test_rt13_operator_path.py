"""RT13 operator-path guards (X6, X7, R3): replayed decisions and repro mode.

THREAT-MODEL claims defended: operator decisions are replayed only from a verified, anchored source and never with
a rogue; a replay that differs is ``replay_mismatch`` -> exit 6 DIVERGED (not TAMPER, contracts 1.5); repro keys
are never a security run (never anchored, refused with --rogue).
"""

from __future__ import annotations

import os
import shutil

import pytest

from ks.contracts import Exit, RunDir

from .conftest import ks, verify, world_run

NOOP = "def on_tick(ctx, t):\n    pass\n"


@pytest.fixture(scope="module")
def source(base):
    return world_run(base, "rt13_src", ticks=14, extra=("--key-mode", "fresh"),
                     actions={6: [{"op": "suspend", "target": "agent:docs"}],
                              8: [{"op": "release", "target": "agent:docs"}]})


@pytest.fixture(scope="module")
def secret(base):
    p = base / "rt13.secret"
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(fd, b"rt13 repro secret: not for security runs, 32+ bytes")
    os.close(fd)
    return p


def test_rt13a_decisions_with_rogue_refused(base, source):
    r = base / "rt13a.py"
    r.write_text(NOOP)
    out = base / "rt13a"
    p = ks("run", "--scenario", "world", "--ticks", 14, "--decisions", source.dir, "--decisions-head", source.anchor,
           "--rogue", r, "--slot", "docs", "--out", out)
    assert p.returncode == Exit.USAGE, p.stderr
    assert not out.exists()


def test_rt13b_tampered_source_refused(base, source):
    bad = base / "rt13b_src"
    shutil.copytree(source.dir, bad)
    rec = bad / "record.jsonl"
    lines = rec.read_bytes().splitlines(keepends=True)
    lines[4] = lines[4].replace(b'"tick":', b'"tick": ', 1) if b'"tick":' in lines[4] else lines[4][:-2] + b"x\n"
    rec.write_bytes(b"".join(lines))
    out = base / "rt13b"
    p = ks("run", "--scenario", "world", "--ticks", 14, "--decisions", bad, "--decisions-head", source.anchor,
           "--out", out)
    assert p.returncode != Exit.OK
    assert not out.exists() or not [c for c in RunDir(out).records() if c.control is not None
                                    and c.control.issued_by == "ks.operator"]


def test_rt13c_replay_matches_and_a_changed_plan_is_stale(base, source):
    out = base / "rt13c"
    p = ks("run", "--scenario", "world", "--ticks", 14, "--decisions", source.dir, "--decisions-head", source.anchor,
           "--out", out)
    assert p.returncode == Exit.OK, p.stderr
    code, rep = verify(out)
    assert code == Exit.OK, rep
    ops = [(c.control.op.value, c.control.target, c.tick) for c in RunDir(out).records()
           if c.control is not None and c.control.issued_by == "ks.operator"]
    src = [(c.control.op.value, c.control.target, c.tick) for c in RunDir(source.dir).records()
           if c.control is not None and c.control.issued_by == "ks.operator"]
    assert ops == src and len(ops) == 2
    from tests.verify.test_decisions import test_stale_plan_hold
    test_stale_plan_hold()  # an approval whose plan_hash differs from the recomputed plan is hold/stale_plan


def test_rt13_replay_mismatch_is_exit_6_diverged(tmp_path):
    """kabir's B3-47 review: replay_mismatch is DIVERGED (6), documented in ADR-02 §6 and the THREAT-MODEL RT13 row."""
    from ks.contracts import VERIFY_REASONS
    assert VERIFY_REASONS["replay_mismatch"] is Exit.DIVERGED and int(Exit.DIVERGED) == 6
    from tests.verify.test_decisions import test_replay_differs_is_failure
    test_replay_differs_is_failure(tmp_path)


def test_rt13d_repro_with_rogue_refused(base, secret):
    r = base / "rt13d.py"
    r.write_text(NOOP)
    out = base / "rt13d"
    p = ks("run", "--scenario", "world", "--ticks", 6, "--key-mode", "repro", "--repro-secret", secret,
           "--rogue", r, "--slot", "docs", "--out", out)
    assert p.returncode == Exit.USAGE and not out.exists()


def test_rt13e_repro_is_never_anchored(base, secret):
    out = base / "rt13e"
    p = ks("run", "--scenario", "world", "--ticks", 6, "--key-mode", "repro", "--repro-secret", secret, "--out", out)
    assert p.returncode == Exit.OK, p.stderr
    assert "NOT A SECURITY RUN" in p.stdout
    anchor = p.stdout.split("RunAnchor (copy into ks verify --head):")[1].strip().splitlines()[0]
    code, rep = verify(out, anchor)
    assert rep["anchored"] is False and rep["unanchored_reason"] == "repro_keys", rep
    assert RunDir(out).config().key_mode == "repro"
