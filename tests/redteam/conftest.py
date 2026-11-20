"""Red-team harness (SPEC §1.2, B3-35): real ``ks run`` subprocesses over the real runtime, gateway, signer, witness,
monitor and ``ks verify``. In the container (Linux root) agents run under per-agent uids; natively (macOS) the run is
degraded, and tests whose claim *is* the uid boundary are skipped with that reason (they run in the container
command, never silently).

    run = world_run(base, "rt3", rogue=SRC, slot="docs", ticks=24, actions={10: [{"op": "suspend", ...}]})
    run.records() / run.rogue_log(kind=, leg=) / run.controls() / run.alerts() / run.status("agent:billing")
    code, rep = verify(run.dir, run.anchor)
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

from ks.contracts import ControlOp, Decision, EpochFold, RunDir

REPO = Path(__file__).resolve().parents[2]
ENV = {**os.environ, "PYTHONPATH": str(REPO / "src")}
ENV.pop("KS_DEBUG", None)
LINUX_ROOT = sys.platform == "linux" and os.geteuid() == 0
NEEDS_UIDS = pytest.mark.skipif(not LINUX_ROOT, reason="claim is the per-agent uid boundary: runs in the container "
                                                       "(Linux root); native macOS is degraded (attribution VOID)")
AGENTS = ("billing", "comms", "compliance", "crm", "docs", "intake", "inventory", "payments", "reporter", "triage")


def conn_of(agent: str) -> str:
    return f"c-{AGENTS.index(agent) + 1}"


def ks(*args, timeout: float = 300) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "ks", *map(str, args)], cwd=REPO, env=ENV, capture_output=True,
                          text=True, timeout=timeout)


def verify(run: Path, head: str | None = None) -> tuple[int, dict]:
    p = ks("verify", "--json", *(["--head", head] if head else []), run)
    return p.returncode, json.loads(p.stdout.strip().splitlines()[-1])


@dataclass
class Run:
    dir: Path
    stdout: str
    anchor: str | None

    def records(self):
        return list(RunDir(self.dir).records())

    def rogue_log(self, kind: str | None = None, leg: str | None = None) -> list[dict]:
        p = self.dir / "rogue.jsonl"
        out = [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []
        return [e for e in out if (kind is None or e.get("kind") == kind) and (leg is None or e.get("leg") == leg)]

    def controls(self):
        return [(r, r.control) for r in self.records() if r.control is not None and r.decision == Decision.EXEC]

    def alerts(self) -> list[dict]:
        p = self.dir / "alerts.jsonl"
        return [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []

    def status(self, target: str) -> str:
        """Fold of executed Controls: ``active`` | ``suspended`` | ``revoked`` (agents via EpochFold, D1)."""
        kind, _, ident = target.partition(":")
        if kind == "agent":
            f = EpochFold(AGENTS)
            for _, c in self.controls():
                if c.target.startswith("agent:"):
                    f.apply(c)
            return f.status(ident)
        st = "active"
        for _, c in self.controls():
            if c.target == target:
                st = {ControlOp.SUSPEND: "suspended", ControlOp.REVOKE: "revoked",
                      ControlOp.RELEASE: "active"}.get(c.op, st) if st != "revoked" else st
        return st

    def score(self) -> dict:
        p = ks("score", self.dir)
        assert p.returncode == 0, p.stdout + p.stderr
        return json.loads((self.dir / "score.json").read_text())


@pytest.fixture(scope="session")
def base():
    """A 0711 dir in /tmp: agent uids must traverse the parents of the run dir (container)."""
    d = Path(tempfile.mkdtemp(prefix="ks-rt-", dir="/tmp"))
    os.chmod(d, 0o711)
    yield d
    shutil.rmtree(d, ignore_errors=True)


def world_run(base: Path, name: str, *, rogue: str | None = None, slot: str = "docs", seed: int = 0, ticks: int = 24,
              fault: str | None = None, hold: int | None = None, actions: dict[int, list] | None = None,
              extra: tuple[str, ...] = ()) -> Run:
    """``ks run --scenario world``; ``actions[t]`` are operator requests (``operator_request`` dicts or callables
    ``f(run_dir)``) issued while the run is paused before tick ``t``: they land in tick ``t``'s control phase."""
    from ks.runtime.operator import operator_request
    out = base / name
    argv = [sys.executable, "-m", "ks", "run", "--scenario", "world", "--seed", str(seed), "--ticks", str(ticks),
            "--out", str(out), *extra]
    if rogue is not None:
        src = base / f"{name}.rogue.py"
        src.write_text(textwrap.dedent(rogue))
        argv += ["--rogue", str(src), "--slot", slot]
    if fault is not None:
        argv += ["--fault", fault]
    if hold is not None:
        argv += ["--hold", str(hold)]
    if actions:
        argv += ["--pause-at", ",".join(map(str, sorted(actions)))]
    p = subprocess.Popen(argv, cwd=REPO, env=ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         stdin=subprocess.DEVNULL, text=True)
    lines: list[str] = []
    try:
        end = time.monotonic() + 600
        for line in p.stdout:
            lines.append(line)
            m = re.search(r"paused before tick (\d+)", line)
            if m:
                reqs = list((actions or {}).get(int(m.group(1)), []))
                for req in reqs or [{"op": "resume"}]:
                    rep = req(out) if callable(req) else operator_request(out, req)
                    assert rep.get("ok", True) is not False, (req, rep)
            if time.monotonic() > end:
                raise AssertionError("run timed out")
        err = p.stderr.read()
        p.wait(60)
    finally:
        if p.poll() is None:
            p.kill()
            p.wait()
    text = "".join(lines)
    assert p.returncode == 0, err[-3000:] + text[-2000:]
    anchor = None
    if "RunAnchor (copy into ks verify --head):" in text:
        anchor = text.split("RunAnchor (copy into ks verify --head):")[1].strip().splitlines()[0]
    return Run(out, text, anchor)


def assert_global(run: Run, *, rogue_conn: str | None = None, sent_exact: bool = True) -> None:
    """SPEC §1.2 global invariant: verify OK and anchored, seq 1..n, every rogue frame recorded once (rule 11),
    no honest agent attributed on a bad_sig record (Q9)."""
    code, rep = verify(run.dir, run.anchor)
    assert code == 0 and rep["anchored"] is True, rep
    recs = run.records()
    assert [r.seq for r in recs] == list(range(1, len(recs) + 1))
    assert not [r for r in recs if r.reason is not None and r.reason.value == "bad_sig" and r.attributed_agent]
    if rogue_conn is not None:
        sent = len(run.rogue_log(kind="sent"))
        mine = len([r for r in recs if r.conn_id == rogue_conn])
        assert (sent == mine) if sent_exact else (mine <= sent), (sent, mine)


def inproc_run(out: Path, *, ticks: int = 30, seed: int = 2, fault: str | None = None, rogue: str | None = None,
               slot: str = "docs", skip_checkpoint=None):
    """``ks.runtime.run`` in the test process so the harness can see what an attacker is *given* (SPEC RT2/RT8): the
    run's KeyStore (test-only capture; production never exposes it) and the ``GatewayHooks.skip_checkpoint`` seam.
    Returns ``(RunResult, KeyStore)``. The witness key is made in the witness process and is never captured (E4)."""
    import importlib
    from ks.recorder.hooks import GatewayHooks
    from ks.runtime import RunOptions
    runmod = importlib.import_module("ks.runtime.run")
    box: list = []
    orig = runmod.KeyStore.create

    def cap(*a, **k):
        box.append(orig(*a, **k))
        return box[-1]

    kw: dict = {}
    if rogue is not None:
        src = out.parent / f"{out.name}.rogue.py"
        src.write_text(textwrap.dedent(rogue))
        kw.update(rogue=str(src), slot=slot, monitor=True)
    if fault is not None:
        kw.update(fault=fault, monitor=True)
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(runmod.KeyStore, "create", staticmethod(cap))
        if skip_checkpoint is not None:
            mp.setattr(GatewayHooks, "skip_checkpoint", lambda self, tick: skip_checkpoint(tick))
        res = runmod.run(agents=None, ticks=ticks, seed=seed, key_mode="fresh", out=out, scenario="world",
                         say=lambda s: None, options=RunOptions(**kw))
    return res, box[0]
