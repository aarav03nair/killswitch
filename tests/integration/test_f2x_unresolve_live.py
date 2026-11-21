"""S4-34 (Panel jury #2 M8; ADR-05a §5 as amended): the resolver undo works **live** on F2+x seed 2.

    ks run --scenario world --fault F2+x --seed 2 --pause-on-alert --resolver ww_rebase/1
      -> alert, suspend, paused -> ks recover --dry-run -> --apply PLAN (the resolve on suppliers:S-22 lands)
      -> billing drafts an invoice from the rebased S-22 in the apply tick (an honest read of the resolved value)
      -> paused again -> ks recover --unresolve PLAN.N  (was: unresolve_blocked) -> --apply UNDO -> resume
    ks verify --head ANCHOR RUN: OK, anchored.

The undo puts S-22 back to triage's version, deletes the invoice billing created from the rebased row (a tombstone,
contracts 1.8.0) and re-holds any item that depended on it. In the container the run also has per-agent uids.
"""

from __future__ import annotations

import re
import sys

import pytest

from ks.contracts import TOMBSTONE_HASH, RunDir

from tests.integration.test_hero_f2plus import ENV, REPO, LINUX_ROOT, Live, ks  # noqa: F401


class LiveX(Live):
    def __init__(self, out, *extra):
        import subprocess
        self.out = out
        self.lines = []
        self.p = subprocess.Popen([sys.executable, "-m", "ks", "run", "--scenario", "world", "--fault", "F2+x",
                                   "--seed", "2", "--ticks", "40", "--out", str(out), "--pause-on-alert",
                                   "--resolver", "ww_rebase/1", *extra],
                                  cwd=REPO, env=ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  stdin=subprocess.DEVNULL, text=True)


def test_f2x_unresolve_live_after_honest_read(tmp_path):
    run = tmp_path / "f2x-s2"
    live = LiveX(run)
    try:
        live.wait_for("paused before tick")
        dry = ks("recover", run, "--dry-run")
        assert dry.returncode == 0, dry.stderr
        plan = re.search(r"--apply (p-\d+)", dry.stdout).group(1)
        ref = re.search(r"--unresolve (p-\d+\.\d+)", dry.stdout).group(1)
        ap = ks("recover", run, "--apply", plan)
        assert ap.returncode == 0, ap.stderr
        live.wait_for("paused before tick")
        recs = list(RunDir(run).records())
        rr = next(r for r in recs if r.envelope and r.envelope.tool == "ks.recover.resolve")
        later = [r for r in recs if r.seq > rr.seq and r.envelope and r.envelope.agent_id == "billing"
                 and any((e.obj, e.ver) == (rr.write_set[0].obj, rr.write_set[0].after.ver) for e in r.read_set)]
        assert later, "the live shape: an honest agent read the resolved value before the operator's next moment"
        un = ks("recover", run, "--unresolve", ref)
        assert un.returncode == 0, un.stdout + un.stderr
        assert "unresolve    " + ref in un.stdout and "deleted (created by a dependent)" in un.stdout
        undo = re.search(r"--apply (p-\d+)", un.stdout).group(1)
        ua = ks("recover", run, "--apply", undo)
        assert ua.returncode == 0 and "1 steps recorded" in ua.stdout, ua.stdout + ua.stderr
        live.wait_for("paused before tick")
        from ks.runtime.operator import operator_request
        operator_request(run, {"op": "resume"})
        anchor = live.finish()
    finally:
        live.kill()
    recs = list(RunDir(run).records())
    ur = [r for r in recs if r.envelope and r.envelope.tool == "ks.recover.unresolve"]
    assert len(ur) == 1 and ur[0].decision.value == "exec"
    w = {x.obj: x for x in ur[0].write_set}
    assert w[rr.write_set[0].obj].after.hash == rr.write_set[0].before.hash  # S-22 back to triage's value
    created = [x for x in later if x.write_set and x.write_set[0].before is None]
    for c in created:
        assert w[c.write_set[0].obj].after.hash == TOMBSTONE_HASH
    v = ks("verify", "--json", "--head", anchor, run)
    assert v.returncode == 0, v.stdout + v.stderr
    if LINUX_ROOT:
        assert '"isolation":"per_agent_uid"' in v.stdout and '"anchored":true' in v.stdout
