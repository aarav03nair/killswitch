"""RT16 (S4-27, Panel jury dry run #1): on the README demo path the run dir lives on a container-internal filesystem
during the run, so the per-agent uid permissions are enforced (a bind-mounted ./runs on OrbStack/virtiofs ignores
them). A rogue agent uid that tries to write state.db, append to record.jsonl and read the side store gets
EACCES / ENOENT, and the run still anchors. Container only (Linux root), like every uid-boundary test.
"""

from __future__ import annotations

import re
import shutil
import tempfile
from pathlib import Path

import pytest

from ks.contracts import Exit

from .conftest import NEEDS_UIDS, verify, world_run

ROGUE = '''
import glob, os
RUN = {run!r}
OTHER = {other!r}
def _try(kind, path, mode):
    try:
        with open(path, mode) as f:
            if mode == "rb":
                f.read(1)
        ctx_report(kind=kind + "_ok", path=path)
    except Exception as e:
        ctx_report(kind=kind + "_fail", path=path, err=type(e).__name__)
def on_start(ctx):
    global ctx_report
    ctx_report = ctx.report
    _try("write_state_db", RUN + "/workspace/state.db", "ab")
    _try("append_record", RUN + "/record.jsonl", "ab")
    side = glob.glob(RUN + "/sidestore/*/*.json")
    _try("read_sidestore", side[0] if side else RUN + "/sidestore/00/x.json", "rb")
    heads = glob.glob(RUN + "/witness-heads/*")
    _try("append_witness_heads", heads[0] if heads else RUN + "/witness-heads/x", "ab")
    oside = glob.glob(OTHER + "/sidestore/*/*.json")
    _try("read_other_sidestore", oside[0] if oside else OTHER + "/sidestore/00/x.json", "rb")
    _try("read_keys", RUN + "/keys.json", "rb")
def on_tick(ctx, t):
    pass
'''


def _fstype(path: str) -> str:
    best, fs = "", ""
    for line in open("/proc/mounts"):
        _, mp, t, *_ = line.split()
        if (path == mp or path.startswith(mp.rstrip("/") + "/")) and len(mp) >= len(best):
            best, fs = mp, t
    return fs


REPO = Path(__file__).resolve().parents[2]


def test_rt16_static_demo_paths_use_container_fs():
    """Runs without the container: demo.sh and make smoke keep the live run dir off the host bind mount."""
    if not (REPO / "scripts/demo.sh").is_file():
        pytest.skip("scripts/ and Makefile are not in the image; this check runs on the host")
    demo = (REPO / "scripts/demo.sh").read_text()
    assert 'RUN="/work/runs/' in demo
    run_line = re.search(r"docker run -d .*?--out \"\$RUN\"", demo, re.S).group(0)
    assert " -v " not in run_line and "--volume" not in run_line, run_line
    mk = (REPO / "Makefile").read_text()
    smoke = mk[mk.index("\nsmoke:"):mk.index("mutation-gate:")]
    run_cmd = next(l for l in smoke.splitlines() if "docker run --name ks-smoke" in l)
    assert "--out /work/runs/" in run_cmd and " -v " not in run_cmd, run_cmd


@pytest.fixture
def work_base():
    """The same place the demo uses: /work/runs on the container's own filesystem."""
    Path("/work/runs").mkdir(parents=True, exist_ok=True)
    d = Path(tempfile.mkdtemp(prefix="rt16-", dir="/work/runs"))
    d.chmod(0o711)
    yield d
    shutil.rmtree(d, ignore_errors=True)


@NEEDS_UIDS
def test_rt16_rogue_denied_on_container_internal_run_dir(work_base):
    base = work_base
    assert str(base).startswith("/work/runs/")
    assert _fstype(str(base)) not in ("virtiofs", "fuse", "fuse.grpcfuse", "9p", "fakeowner"), _fstype(str(base))
    other = world_run(base, "other", ticks=6)  # a second run in the same container: its side store is not readable
    out = str(base / "rt16")
    run = world_run(base, "rt16", rogue=ROGUE.format(run=out, other=str(other.dir)), ticks=6)
    log = run.rogue_log()
    kinds = {e["kind"] for e in log}
    assert not [k for k in kinds if k.endswith("_ok")], log
    assert {"write_state_db_fail", "append_record_fail", "read_sidestore_fail", "read_keys_fail",
            "append_witness_heads_fail", "read_other_sidestore_fail"} <= kinds, log
    assert all(e["err"] in ("PermissionError", "FileNotFoundError") for e in log if e["kind"].endswith("_fail")), log
    # the files the rogue targeted exist (a FileNotFoundError on a missing path would prove nothing)
    assert any((Path(out) / "witness-heads").iterdir()) and list((other.dir / "sidestore").glob("*/*.json"))
    code, rep = verify(run.dir, run.anchor)
    assert code == Exit.OK and rep["anchored"] is True and rep["isolation"] == "per_agent_uid"
