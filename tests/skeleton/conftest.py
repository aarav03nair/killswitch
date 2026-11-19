"""SKEL-01 fixtures: real `python3 -m ks run` subprocesses into run dirs whose parents agent uids can traverse
(so an EACCES comes from the run dir's own modes, not from pytest's 0700 tmp root)."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from ks.contracts import RunAnchor, VerifyReport

REPO = Path(__file__).resolve().parents[2]
ENV = {**os.environ, "PYTHONPATH": str(REPO / "src")}
ENV.pop("KS_DEBUG", None)
IS_ROOT = os.geteuid() == 0
needs_root = pytest.mark.skipif(not IS_ROOT, reason="uid separation needs root")


def ks(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "ks", *map(str, args)], cwd=REPO, env=ENV, capture_output=True,
                          text=True, timeout=180)


def ks_run(out: Path, *, seed: int = 7, key_mode: str = "fresh", extra: tuple[str, ...] = ()) -> tuple[str, str]:
    """Run the skeleton; returns (stdout, RunAnchor line)."""
    p = ks("run", "--agents", 2, "--ticks", 10, "--seed", seed, "--key-mode", key_mode, "--out", out, *extra)
    assert p.returncode == 0, p.stderr + p.stdout
    anchor = p.stdout.strip().splitlines()[-1]
    RunAnchor.from_canonical(anchor.encode())  # it is a canonical RunAnchor line
    return p.stdout, anchor


def ks_verify(run: Path, head: str | None = None) -> tuple[int, VerifyReport]:
    p = ks("verify", run, *(("--head", head) if head else ()), "--json")
    rep = VerifyReport.from_canonical(p.stdout.strip().splitlines()[-1].encode())
    assert rep.exit == p.returncode
    return p.returncode, rep


@pytest.fixture(scope="session")
def base_dir():
    d = Path(tempfile.mkdtemp(prefix="ks-skel-", dir="/tmp"))
    os.chmod(d, 0o711)
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture(scope="session")
def clean_run(base_dir) -> tuple[Path, str, str]:
    """(run dir, RunAnchor line, stdout) of one fresh-key run, seed 7. Never modify it: use ``run_copy``."""
    out = base_dir / "clean"
    stdout, anchor = ks_run(out)
    return out, anchor, stdout


@pytest.fixture
def run_copy(clean_run, tmp_path) -> Path:
    dst = tmp_path / "run"
    shutil.copytree(clean_run[0], dst)
    return dst


@pytest.fixture(scope="session")
def repro_secret(base_dir) -> Path:
    p = base_dir / "repro.secret"
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(fd, b"skel-01 repro secret: not for security runs, 32+ bytes")
    os.close(fd)
    return p
