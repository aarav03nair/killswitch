"""Process spawning, uids and teardown (ADR-00 "Processes", THREAT-MODEL v4 Live setup).

Every child (agent or witness) is started through :data:`BOOT`, which sets ``PR_SET_DUMPABLE=0`` as its very
first statement. It cannot be done in ``preexec_fn``: ``execve`` resets the dumpable flag to 1 when real and
effective ids match (checked 19 Nov), so the template must do it after exec, before any agent code.
Children get a numeric uid with no passwd entry, ``close_fds``, only the passed socketpair ends, env
``{PYTHONHASHSEED=0}`` and cwd ``/``.
"""

from __future__ import annotations

import ctypes
import os
import resource
import signal
import socket
import subprocess
import sys
import time
from collections.abc import Iterable
from pathlib import Path

__all__ = ["WITNESS_UID", "AGENT_UID_BASE", "agent_uid", "BOOT", "spawn_child", "proc_uid", "pids_with_uids",
           "kill_uids", "set_nondumpable", "set_oom_score_adj", "plan_agent_uids", "SHARED_AGENT_UID"]

WITNESS_UID = 60000
AGENT_UID_BASE = 60001
AGENT_NPROC = 64
"""RLIMIT_NPROC per agent uid (threads count too)."""
PR_SET_DUMPABLE = 4
SRC = str(Path(__file__).resolve().parents[2])
"""Directory that contains the ``ks`` package; children put it on sys.path themselves (clean env)."""

LINUX = sys.platform == "linux"
"""prctl, oom_score_adj and /proc uid readback exist only on Linux; elsewhere the run is shared-uid (degraded)."""

BOOT = ("import ctypes,sys\n"
        "if sys.platform=='linux' and ctypes.CDLL(None).prctl(4,0,0,0,0)!=0: sys.exit(70)\n"
        "sys.path.insert(0,sys.argv[1])\n"
        "import importlib\n"
        "sys.exit(importlib.import_module(sys.argv[2]).main(sys.argv[3:]))\n")
"""Child bootstrap: non-dumpable first, then ``<module>.main(argv)``."""


def agent_uid(index: int) -> int:
    return AGENT_UID_BASE + index


SHARED_AGENT_UID = AGENT_UID_BASE
"""The one unprivileged uid every agent shares under ``--shared-uid`` as root (SKEL-01 S2): never 0."""


def plan_agent_uids(root: bool, separate: bool, agents: int) -> list[int | None]:
    """uid for each agent index. ``None`` = our own uid (not root: nothing to drop to). As root, agents are
    **never** uid 0: per-agent uids when ``separate``, else one shared unprivileged uid (S2)."""
    if not root:
        return [None] * agents
    return [agent_uid(i) if separate else SHARED_AGENT_UID for i in range(agents)]


def set_nondumpable() -> bool:
    if not LINUX:
        return False
    return ctypes.CDLL(None, use_errno=True).prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0


def set_oom_score_adj(pid: int | str, value: int) -> bool:
    if not LINUX:
        return False
    try:
        Path(f"/proc/{pid}/oom_score_adj").write_text(str(value))
        return True
    except OSError:
        return False


def _agent_limits() -> None:  # runs in the child after setuid, before exec: may only tighten
    resource.setrlimit(resource.RLIMIT_NPROC, (AGENT_NPROC, AGENT_NPROC))
    set_oom_score_adj("self", 1000)


def spawn_child(module: str, args: Iterable[str], *, uid: int | None, pass_socks: Iterable[socket.socket],
                agent: bool, env: dict[str, str] | None = None) -> subprocess.Popen:
    """Start ``module.main(args)`` via BOOT under ``uid`` (``None`` = same uid as us: degraded mode). ``env`` adds
    variables to the clean env (B3-27: ``KS_FAULT`` for the culprit only; ``/proc/<pid>/environ`` of a non-dumpable
    child is readable by root only, unlike its cmdline)."""
    fds = tuple(s.fileno() for s in pass_socks)
    debug = os.environ.get("KS_DEBUG") == "1"
    kw: dict = {}
    if uid is not None:
        kw.update(user=uid, group=uid, extra_groups=[])
        if agent:
            kw["preexec_fn"] = _agent_limits
    return subprocess.Popen(
        [sys.executable, "-s", "-P", "-c", BOOT, SRC, module, *args],
        env={"PYTHONHASHSEED": "0", **(env or {})}, cwd="/", close_fds=True, pass_fds=fds, stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=None if debug else subprocess.DEVNULL, **kw)


def proc_uid(pid: int) -> int | None:
    """uid of a live process, read from /proc: the real uid if real, effective, saved and fs uid all agree
    (kabir, B3-10), else ``None`` (gone, or ids that disagree: not the uid we asked for, so never trusted)."""
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("Uid:"):
                ids = [int(x) for x in line.split()[1:5]]
                return ids[0] if len(ids) == 4 and len(set(ids)) == 1 else None
    except (OSError, ValueError, IndexError):
        pass
    return None


def pids_with_uids(uids: Iterable[int]) -> list[int]:
    """Every live (non-zombie) process whose real, effective, saved or fs uid is in ``uids``."""
    want = set(uids)
    out = []
    if not LINUX:
        return out
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        try:
            status = dict(l.split(":", 1) for l in Path(f"/proc/{d}/status").read_text().splitlines() if ":" in l)
            if status["State"].split()[0] != "Z" and want & {int(x) for x in status["Uid"].split()}:
                out.append(int(d))
        except (OSError, ValueError, KeyError, IndexError):
            continue
    return sorted(out)


def kill_uids(uids: Iterable[int], timeout_s: float = 5.0) -> list[int]:
    """SIGKILL every process running under ``uids`` until none is left (forks included, K2).
    Returns the pids that survived the timeout (empty on success). Only meaningful when the uids are
    not ours: in degraded (shared-uid) mode the caller kills its children by pid instead."""
    uids = tuple(uids)
    end = time.monotonic() + timeout_s
    while True:
        pids = pids_with_uids(uids)
        if not pids or time.monotonic() > end:
            return pids
        for pid in pids:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        time.sleep(0.01)
