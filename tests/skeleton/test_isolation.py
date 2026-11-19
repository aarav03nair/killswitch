"""SKEL-01 / THREAT-MODEL v4 Live setup: per-agent uids, EACCES on the run dir, kill by uid, degraded mode."""

import re
import subprocess
import sys

from ks.contracts import Exit
from ks.runtime.spawn import WITNESS_UID, agent_uid, pids_with_uids

from .conftest import ks_run, ks_verify, needs_root

PROBE = r"""
import errno, os, sys
run = sys.argv[1]
os.stat(run)  # parents and the 0711 run dir are traversable, so any EACCES below is the file's own mode
out = []
for name in ("record.jsonl", "witness.jsonl", "config.json", "keys.json", "timing.jsonl"):
    try:
        open(os.path.join(run, name), "rb").read(1); out.append(name + ":read")
    except OSError as e:
        out.append(name + ":" + errno.errorcode[e.errno])
for d in ("", "sidestore", "witness-heads", "workspace"):
    try:
        os.listdir(os.path.join(run, d)); out.append((d or ".") + ":list")
    except OSError as e:
        out.append((d or ".") + ":" + errno.errorcode[e.errno])
print(" ".join(out))
"""


def _banner_uids(stdout: str) -> dict[str, int]:
    line = next(l for l in stdout.splitlines() if l.startswith("isolation:"))
    return {a: int(u) for a, u in re.findall(r"(agent_\d+)=(\d+)", line)}


@needs_root
def test_agent_uid_gets_eacces_on_run_dir(clean_run):
    p = subprocess.run([sys.executable, "-c", PROBE, str(clean_run[0])], user=agent_uid(0), group=agent_uid(0),
                       extra_groups=[], capture_output=True, text=True, timeout=30)
    assert p.returncode == 0, p.stderr
    got = dict(item.split(":") for item in p.stdout.split())
    assert set(got.values()) == {"EACCES"}, got
    assert got["record.jsonl"] == "EACCES"


@needs_root
def test_each_agent_has_its_own_uid(clean_run):
    uids = _banner_uids(clean_run[2])
    assert uids == {"agent_00": agent_uid(0), "agent_01": agent_uid(1)}
    assert len(set(uids.values())) == 2 and WITNESS_UID not in uids.values() and 0 not in uids.values()
    assert "per-agent uids" in clean_run[2] and "VOID" not in clean_run[2]


@needs_root
def test_teardown_leaves_nothing_under_run_uids(clean_run):
    assert pids_with_uids([WITNESS_UID, agent_uid(0), agent_uid(1)]) == []


def test_shared_uid_fallback_voids_attribution(base_dir):
    out = base_dir / "shared"
    stdout, anchor = ks_run(out, extra=("--shared-uid",))
    assert "DEGRADED" in stdout and "per-agent attribution is VOID" in stdout
    code, rep = ks_verify(out, anchor)
    assert code == Exit.OK and rep.anchored
