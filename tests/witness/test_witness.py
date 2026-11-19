"""B3-08: witness-owned witness.jsonl, fd handover, per-tick idempotency. Linux-root tests are skipped elsewhere
(never faked); they run in the container."""

from __future__ import annotations

import os
import socket
import stat
import sys
import threading

import pytest

from ks.contracts import RunDir, WitnessCheckpoint
from ks.identity import verify_hex
from ks.witness import WitnessLink, open_witness_fds, server

LINUX_ROOT = sys.platform == "linux" and os.geteuid() == 0
linux_root = pytest.mark.skipif(not LINUX_ROOT, reason="needs Linux and root (uid ownership, /proc/self/fd)")
H1, H2, H3 = "11" * 32, "22" * 32, "33" * 32


class _Thread:
    def __init__(self, t):
        self.t = t

    def wait(self, timeout=None):
        self.t.join(timeout)

    def kill(self):
        pass


@pytest.fixture
def link(tmp_path):
    gw, wit = socket.socketpair()
    t = threading.Thread(target=lambda: server.main([str(wit.detach())]), daemon=True)
    t.start()
    lk = WitnessLink(gw, _Thread(t))
    lk.init(None, timeout_s=10)
    (tmp_path / "heads").mkdir()
    (tmp_path / "witness.jsonl").touch()
    lk.attach(*open_witness_fds(tmp_path / "witness.jsonl", tmp_path / "heads"), timeout_s=10)
    yield lk
    lk.close(timeout_s=10)


def _lines(tmp_path):
    return [WitnessCheckpoint.from_canonical(x) for x in (tmp_path / "witness.jsonl").read_bytes().splitlines()]


def test_repeated_push_returns_existing_checkpoint_without_new_line(link, tmp_path):
    cp = link.push(1, H1, 0, timeout_s=10)
    again = link.push(1, H1, 0, timeout_s=10)
    assert cp is not None and again == cp
    assert _lines(tmp_path) == [cp]
    assert len((tmp_path / "heads" / "heads.jsonl").read_bytes().splitlines()) == 1


def test_ticks_strictly_increase_and_regressions_get_no_ack(link, tmp_path):
    a = link.push(1, H1, 3, timeout_s=10)
    assert link.push(2, H2, 3, timeout_s=0.3) is None   # second head for the same tick
    assert link.push(1, H1, 2, timeout_s=0.3) is None   # earlier tick
    b = link.push(2, H2, 4, timeout_s=10)
    assert link.push(1, H1, 5, timeout_s=0.3) is None   # seq regresses
    c = link.push(2, H2, 6, timeout_s=10)               # no-op tick repeats (seq, head)
    got = _lines(tmp_path)
    assert got == [a, b, c] and [x.count for x in got] == [1, 2, 3]
    assert [x.tick for x in got] == [3, 4, 6]
    assert all(verify_hex(link.pub, x.sig, x.signing_bytes()) for x in got)


@linux_root
def test_witness_file_owned_by_witness_uid_mode_0600_and_gateway_holds_no_fd(tmp_path):
    """Real witness process under uid 60000 gets the fds over SCM_RIGHTS and never opens a run-dir path; after
    attach the gateway (root) has no descriptor on witness.jsonl. UNEXECUTED on macOS: container only."""
    import sys as _sys
    _sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "contracts"))
    import samples as S
    from ks.runtime.spawn import WITNESS_UID, spawn_child

    base = tmp_path / "base"
    base.mkdir()
    os.chmod(base, 0o755)  # the witness uid may traverse nothing: it must not need a path at all
    rd = RunDir.create(base / "run", S.run_config(), S.keyring(), witness_uid=WITNESS_UID, witness_gid=WITNESS_UID)
    st = os.stat(rd.path / "witness.jsonl")
    assert st.st_uid == WITNESS_UID and stat.S_IMODE(st.st_mode) == 0o600
    hs = os.stat(rd.path / "witness-heads")
    assert hs.st_uid == WITNESS_UID and stat.S_IMODE(hs.st_mode) == 0o700

    w_parent, w_child = socket.socketpair()
    proc = spawn_child("ks.witness.server", [str(w_child.fileno())], uid=WITNESS_UID, pass_socks=[w_child], agent=False)
    w_child.close()
    lk = WitnessLink(w_parent, proc)
    lk.init(None, timeout_s=30)
    lk.attach(*open_witness_fds(rd.path / "witness.jsonl", rd.path / "witness-heads"), timeout_s=10)
    target = os.path.realpath(rd.path / "witness.jsonl")
    held = [os.readlink(f"/proc/self/fd/{n}") for n in os.listdir("/proc/self/fd")]
    assert target not in held and not any(h.startswith(str(rd.path / "witness-heads")) for h in held)
    cp = lk.push(1, H1, 0, timeout_s=10)
    assert cp is not None and lk.push(1, H1, 0, timeout_s=10) == cp
    lk.close(timeout_s=10)
    assert [WitnessCheckpoint.from_canonical(x) for x in rd.path.joinpath("witness.jsonl").read_bytes().splitlines()] == [cp]
    assert stat.S_IMODE(os.stat(rd.path / "witness.jsonl").st_mode) == 0o600
