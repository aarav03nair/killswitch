"""B3-10: 10-agent world spawn, isolation pinning (abort on contradicting /proc readback), run_id default.

Tests marked ``linux_root`` need per-agent uids (Linux, euid 0, e.g. the Docker image); on native macOS they skip
and the run is degraded with attribution VOID (asserted by test_world_run_spawns_adr06_agents).
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

from ks.contracts import (Exit, NoopFrame, RunDir, TickFrame, WitnessInit, WitnessPub, canonical, decode_frame,
                          decode_witness_frame, encode_frame)
from ks.runtime.setup import (WORLD_TICKS_UNTIL_STATE, IsolationError, default_out, default_run_id, hero_tick,
                              isolation_problems, scenario)
from ks.runtime.spawn import WITNESS_UID, agent_uid, pids_with_uids, proc_uid, spawn_child
from ks.world.agents import AGENT_IDS
from ks.world.registry import SENSITIVE_FIELDS
from tests.skeleton.conftest import ks, ks_verify
from tests.skeleton.test_determinism import _raw_deterministic_files

LINUX_ROOT = sys.platform == "linux" and os.geteuid() == 0
linux_root = pytest.mark.skipif(not LINUX_ROOT, reason="per-agent uids need Linux root (run in Docker)")
WORLD_UIDS = [WITNESS_UID] + [agent_uid(i) for i in range(len(AGENT_IDS))]


@pytest.fixture(scope="module")
def base():
    d = Path(tempfile.mkdtemp(prefix="ks-b310-", dir="/tmp"))
    os.chmod(d, 0o711)
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture(scope="module")
def secret(base) -> Path:
    p = base / "repro.secret"
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(fd, b"b3-10 repro secret: not for security runs, 32+ bytes")
    os.close(fd)
    return p


def world_run(out: Path, *extra: str, seed: int = 7):
    return ks("run", "--scenario", "world", "--ticks", WORLD_TICKS_UNTIL_STATE, "--seed", seed, "--out", out,
              *extra)


# --- acceptance 1: the ADR-06 agents are what gets spawned ------------------------------------------------------
def test_world_run_spawns_adr06_agents(base):
    out = base / "world"
    p = world_run(out)
    assert p.returncode == 0, p.stderr + p.stdout
    cfg = RunDir(out).config()
    assert cfg.agents == AGENT_IDS and cfg.scenario == "world" and cfg.sensitive_fields == SENSITIVE_FIELDS
    assert cfg.run_id == "world-s7"
    for a in AGENT_IDS:
        assert f"{a}=" in p.stdout  # the isolation banner read every agent back
    if LINUX_ROOT:
        assert cfg.isolation == "per_agent_uid" and "per-agent uids" in p.stdout and "VOID" not in p.stdout
        assert pids_with_uids(WORLD_UIDS) == []  # teardown by uid
    else:  # native macOS / non-root: degraded, attribution void, still runs
        assert cfg.isolation == "degraded" and "per-agent attribution is VOID" in p.stdout
    # all 10 agent processes ran ks.world.agents.step on their view and answered before the deadline
    assert [canonical.loads_line(l)["missed"] for l in (out / "timing.jsonl").read_bytes().splitlines(True)] == [[]]
    # every ADR-06 agent is idle at tick 0, so nothing is recorded or witnessed yet (WORLD_TICKS_UNTIL_STATE)
    assert "no witnessed head" in p.stdout and (out / "record.jsonl").read_bytes() == b""
    code, rep = ks_verify(out)
    assert code == Exit.OK and rep.isolation == cfg.isolation


def test_world_scenario_arguments():
    assert scenario("world", agents=None, seed=1, ticks=1).agent_ids == AGENT_IDS
    with pytest.raises(ValueError, match="exactly 10"):
        scenario("world", agents=3, seed=1, ticks=1)
    with pytest.raises(ValueError, match="state txn"):  # TODO(B3-11/B3-41): lift with the gateway's state txn
        scenario("world", agents=None, seed=1, ticks=WORLD_TICKS_UNTIL_STATE + 1)
    with pytest.raises(ValueError, match="unknown scenario"):
        scenario("acme", agents=None, seed=1, ticks=1)
    assert scenario("skeleton", agents=None, seed=1, ticks=5).agent_ids == ("agent_00", "agent_01")
    for s in range(1, 21):
        assert 30 <= hero_tick(s, 120) <= 60 and hero_tick(s, 120) == hero_tick(s, 120)


def _probe(uid: int, targets: list[int]) -> dict:
    a, b = socket.socketpair()
    p = spawn_child("ks.runtime.isoprobe", [str(b.fileno()), *map(str, targets)], uid=uid, pass_socks=[b],
                    agent=True)
    b.close()
    line = a.makefile("rb").readline()
    p.wait(10)
    a.close()
    return canonical.loads_line(line)


def _uids(pid: int) -> tuple[str, list[int]]:
    """(State letter, [real, effective, saved, fs] uids) from /proc/<pid>/status."""
    st = dict(l.split(":", 1) for l in Path(f"/proc/{pid}/status").read_text().splitlines() if ":" in l)
    return st["State"].split()[0], [int(x) for x in st["Uid"].split()]


def _ready(sock: socket.socket, send: bytes, want: type) -> None:
    """Handshake: the child answers from its own main(), i.e. after exec and after BOOT's prctl."""
    sock.settimeout(10.0)
    sock.sendall(send)
    line = sock.makefile("rb").readline()
    frame = decode_witness_frame(line) if want is WitnessPub else decode_frame(line)
    assert isinstance(frame, want), frame


@linux_root
def test_cross_uid_ptrace_eperm_and_nondumpable_after_exec():
    """Agents i, j and the witness spawned exactly as ks run does; agent i's ptrace on j and on the witness is
    EPERM, and every child is non-dumpable after exec.

    Dumpable readback: with dumpable != 1 the kernel reports the per-process files under /proc/<pid> (status,
    fd, environ, mem) as owned by root instead of the task's euid. The /proc/<pid> directory itself is exempt
    (fs/proc/base.c task_dump_owner skips mode S_IFDIR|0555) and always shows the euid, so it cannot be used.
    A dumpable control under an agent uid proves the readback tells the two cases apart."""
    socks, procs = [], []
    try:
        for i in (0, 1):
            g, gc = socket.socketpair()
            s, sc = socket.socketpair()
            procs.append(spawn_child("ks.runtime.agent_template",
                                     ["--agent", AGENT_IDS[i], "--seed", "1", "--gw-fd", str(gc.fileno()),
                                      "--signer-fd", str(sc.fileno()), "--behaviour", "ks.world.agents",
                                      "--hero-tick", "30"], uid=agent_uid(i), pass_socks=[gc, sc], agent=True))
            gc.close(), sc.close()
            socks += [g, s]
            _ready(g, encode_frame(TickFrame(tick=0, epoch=None, view=())), NoopFrame)
        w, wc = socket.socketpair()
        procs.append(spawn_child("ks.witness.server", [str(wc.fileno())], uid=WITNESS_UID, pass_socks=[wc],
                                 agent=False))
        wc.close()
        socks.append(w)
        _ready(w, encode_frame(WitnessInit(key_seed=None)), WitnessPub)
        expect = {procs[0].pid: agent_uid(0), procs[1].pid: agent_uid(1), procs[2].pid: WITNESS_UID}
        for p in procs:  # alive, not a zombie, and on its uid in all four slots
            assert p.poll() is None
            state, uids = _uids(p.pid)
            assert state != "Z" and uids == [expect[p.pid]] * 4, (p.pid, state, uids)
        for p in procs:  # dumpable = 0 after exec
            for f in ("status", "fd"):
                assert os.stat(f"/proc/{p.pid}/{f}").st_uid == 0, (p.pid, f)
        control = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"], user=agent_uid(2),
                                   group=agent_uid(2), extra_groups=[], env={}, cwd="/")
        procs.append(control)
        deadline = time.monotonic() + 10
        while proc_uid(control.pid) != agent_uid(2) and time.monotonic() < deadline:
            time.sleep(0.01)
        assert os.stat(f"/proc/{control.pid}/status").st_uid == agent_uid(2)  # dumpable control
        a_j, wit = procs[1].pid, procs[2].pid
        got = _probe(agent_uid(0), [a_j, wit])
        assert got["uid"] == agent_uid(0)
        assert got["results"] == {str(a_j): "EPERM", str(wit): "EPERM"}
    finally:
        for s in socks:
            s.close()
        for p in procs:
            p.kill()
            p.wait()


# --- acceptance 2: /proc readback contradicting RunConfig.isolation aborts before tick 0 ----------------------
def test_isolation_problems_unit():
    planned = [agent_uid(0), agent_uid(1)]
    ok = isolation_problems("per_agent_uid", planned, {"a": agent_uid(0), "b": agent_uid(1)}, WITNESS_UID,
                            WITNESS_UID, our_uid=0)
    assert ok == []
    shared = isolation_problems("per_agent_uid", planned, {"a": agent_uid(0), "b": agent_uid(0)}, WITNESS_UID,
                                WITNESS_UID, our_uid=0)
    assert any("share" in p for p in shared) and any("b: uid" in p for p in shared)
    assert isolation_problems("per_agent_uid", planned, {"a": agent_uid(0), "b": None}, WITNESS_UID, WITNESS_UID,
                              our_uid=0)
    assert isolation_problems("per_agent_uid", planned, {"a": 0, "b": agent_uid(1)}, WITNESS_UID, WITNESS_UID,
                              our_uid=0)
    assert isolation_problems("per_agent_uid", planned, {"a": agent_uid(0), "b": agent_uid(1)}, agent_uid(1),
                              WITNESS_UID, our_uid=0)
    # degraded promises nothing beyond the uids it asked for: macOS (no /proc, nothing planned) never aborts
    assert isolation_problems("degraded", [None, None], {"a": None, "b": None}, None, None, our_uid=501) == []
    # degraded as root (S2 shared unprivileged uid) still aborts if an agent is not on the uid it was given
    assert isolation_problems("degraded", [agent_uid(0)] * 2, {"a": agent_uid(0), "b": 0}, None, None, our_uid=0)


@linux_root
def test_forced_shared_uid_aborts_before_tick0(base):
    from ks.runtime.run import run
    out = base / "forced-shared"
    lines = []
    with pytest.raises(IsolationError, match="per_agent_uid"):
        run(scenario="world", agents=None, ticks=1, seed=3, key_mode="fresh", out=out, say=lines.append,
            _force_agent_uids=[agent_uid(0)] * len(AGENT_IDS))
    assert (out / "record.jsonl").read_bytes() == b""  # no tick ran, nothing recorded
    assert not (out / "timing.jsonl").exists()
    assert pids_with_uids(WORLD_UIDS) == []


# --- acceptance 3: run_id default, byte-identical repro, existing run dir refuses ------------------------------
def test_default_run_id_and_out():
    assert default_run_id("world", 7) == "world-s7" and default_run_id("skeleton", 0) == "skeleton-s0"
    want = Path("/run/ks/world-s7") if LINUX_ROOT else Path("runs/world-s7")
    assert default_out("world-s7") == want


def test_world_repro_same_seed_byte_identical(base, secret):
    runs = [base / f"repro-{i}" for i in (1, 2)]
    anchors = []
    for r in runs:
        p = world_run(r, "--key-mode", "repro", "--repro-secret", str(secret), seed=11)
        assert p.returncode == 0, p.stderr + p.stdout
        anchors.append(p.stdout.strip().splitlines()[-1])
    a, b = (_raw_deterministic_files(r) for r in runs)
    assert a == b and {"config.json", "record.jsonl", "witness.jsonl"} <= a.keys()
    assert anchors[0] == anchors[1]  # both "no witnessed head" until the world writes (B3-11)
    assert RunDir(runs[0]).config().run_id == "world-s11"


def test_existing_run_dir_refuses_before_spawn(base):
    out = base / "exists"
    out.mkdir()
    marker = out / "keep"
    marker.write_bytes(b"x")
    p = world_run(out)
    assert p.returncode == Exit.IO and "already exists" in p.stderr
    assert sorted(os.listdir(out)) == ["keep"]  # nothing written into it
    if LINUX_ROOT:
        assert pids_with_uids(WORLD_UIDS) == []
